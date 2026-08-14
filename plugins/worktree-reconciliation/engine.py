"""Session-owned Git worktree leases and automatic local WIP checkpoints.

Safety boundary:
- isolated non-canonical task branches only
- exact preclaimed paths only
- local commits only; no push/merge/tag/deploy/promotion code exists here
- fail closed on peer collisions, identity drift, unknown paths, sensitive file
  classes, secret-scan findings, hook failures, or non-clean final readback
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

PLUGIN_DIR = Path(__file__).resolve().parent
PROFILE_HOME = PLUGIN_DIR.parent.parent
GATE_SCRIPT = PROFILE_HOME / "skills" / "devops" / "worktree-reconciliation-gate" / "scripts" / "worktree_reconciliation_gate.py"
DEFAULT_STATE_ROOT = PROFILE_HOME / "worktree-reconciliation"
LEASE_SCHEMA = "loaw.worktree_reconciliation_lease.v1"
EXTENSION_SCHEMA = "loaw.worktree_scope_extension.v1"
CHECKPOINT_SCHEMA = "loaw.worktree_checkpoint.v1"
AUTHORITY_POLICY = "standing_local_wip_checkpoint_authority_2026-08-13"
LEASE_HOURS = 4
MAX_AUTOMATIC_FILE_BYTES = 10 * 1024 * 1024

BLOCKED_EXACT_NAMES = {
    ".env", ".netrc", "auth.json", "credentials.json", "secrets.json",
    "id_rsa", "id_ed25519", "known_hosts", "cookies.sqlite",
}
BLOCKED_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".kdbx", ".sqlite", ".sqlite3", ".db",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".dmg", ".iso",
    ".mp3", ".mp4", ".mov", ".wav", ".m4a",
}
_GATE_MODULE = None


class ReconciliationError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ReconciliationError("session_id and run_id must be non-empty")
    visible = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-._")[:48] or "id"
    return f"{visible}-{hashlib.sha256(raw.encode()).hexdigest()[:10]}"


def _display_token(value: str, limit: int = 48) -> str:
    return (re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-._") or "checkpoint")[:limit]


def _state_root(value: str | Path | None = None) -> Path:
    root = Path(value).expanduser().resolve() if value else DEFAULT_STATE_ROOT
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def _run_dir(state_root: Path, session_id: str, run_id: str) -> Path:
    path = state_root / "runs" / _slug(session_id) / _slug(run_id)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _lease_path(state_root: Path, session_id: str, run_id: str) -> Path:
    directory = state_root / "leases" / _slug(session_id)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory / f"{_slug(run_id)}.json"


def _gate():
    global _GATE_MODULE
    if _GATE_MODULE is not None:
        return _GATE_MODULE
    if not GATE_SCRIPT.is_file():
        raise ReconciliationError(f"missing worktree gate: {GATE_SCRIPT}")
    spec = importlib.util.spec_from_file_location("loaw_worktree_reconciliation_gate", GATE_SCRIPT)
    if spec is None or spec.loader is None:
        raise ReconciliationError(f"cannot load worktree gate: {GATE_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _GATE_MODULE = module
    return module


def _atomic_json(path: Path, payload: dict[str, Any], *, immutable: bool) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    if immutable:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise ReconciliationError(f"refusing to overwrite immutable record: {path}") from exc
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    else:
        temp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                temp.unlink()
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReconciliationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReconciliationError(f"expected JSON object: {path}")
    return payload


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_git(repo: Path, *args: str, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if check and proc.returncode:
        raise ReconciliationError(f"git {' '.join(args)} failed with exit {proc.returncode}")
    return proc


def _lease_deadline() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=LEASE_HOURS)).isoformat()


def _is_expired(lease: dict[str, Any]) -> bool:
    try:
        return datetime.fromisoformat(str(lease["lease_deadline"])) < datetime.now(timezone.utc)
    except Exception:
        return True


def _event_path(run_dir: Path, label: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return run_dir / "events" / f"{stamp}-{label}-{uuid.uuid4().hex[:8]}.json"


@contextlib.contextmanager
def _lease_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        except ImportError:  # pragma: no cover - Windows fallback is process-local best effort
            pass
        yield
    finally:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
        except ImportError:  # pragma: no cover
            pass
        os.close(fd)


def open_lease(
    *,
    repo: str,
    session_id: str,
    run_id: str,
    owned_paths: Iterable[str],
    owner: str | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    gate = _gate()
    root = _state_root(state_root)
    lease_path = _lease_path(root, session_id, run_id)
    run_dir = _run_dir(root, session_id, run_id)
    open_receipt = run_dir / "open.json"
    if lease_path.exists() or open_receipt.exists():
        raise ReconciliationError("run_id is immutable and already exists for this session")

    args = argparse.Namespace(
        repo=repo,
        run_id=run_id,
        owner=owner or session_id,
        owned_path=list(owned_paths),
        adoption_manifest=None,
        output=str(open_receipt),
    )
    receipt, exit_code = gate.open_gate(args)
    repo_root = gate.repo_root(repo)
    gate.immutable_write_json(str(open_receipt), receipt, repo_root)
    if exit_code or not receipt.get("ok"):
        return {
            "ok": False,
            "gate": "Blocked",
            "state": "OPEN_REJECTED",
            "open_receipt": str(open_receipt),
            "violations": receipt.get("violations", []),
        }

    now = utc_now()
    lease = {
        "schema": LEASE_SCHEMA,
        "lease_id": hashlib.sha256(f"{session_id}\0{run_id}\0{receipt['identity']['worktree']}".encode()).hexdigest(),
        "session_id": session_id,
        "run_id": run_id,
        "owner": owner or session_id,
        "authority_policy": AUTHORITY_POLICY,
        "state": "ACTIVE",
        "complete": False,
        "created_at": now,
        "updated_at": now,
        "lease_deadline": _lease_deadline(),
        "worktree": receipt["identity"]["worktree"],
        "branch": receipt["identity"]["branch"],
        "starting_head": receipt["identity"]["head"],
        "starting_status_sha256": receipt["starting_status"]["sha256"],
        "owned_paths": receipt["owned_paths"],
        "open_receipt": str(open_receipt),
        "run_directory": str(run_dir),
        "last_event": str(open_receipt),
        "checkpoint_commit": None,
        "blocker": None,
    }
    _atomic_json(lease_path, lease, immutable=True)
    return {"ok": True, "gate": "Pass", "state": "ACTIVE", "lease": str(lease_path), "open_receipt": str(open_receipt)}


def load_lease(
    session_id: str,
    run_id: str,
    *,
    state_root: str | Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    root = _state_root(state_root)
    path = _lease_path(root, session_id, run_id)
    if not path.is_file():
        raise ReconciliationError(f"lease not found for session/run: {session_id}/{run_id}")
    lease = _load_json(path)
    if lease.get("schema") != LEASE_SCHEMA:
        raise ReconciliationError(f"invalid lease schema: {path}")
    if lease.get("session_id") != session_id or lease.get("run_id") != run_id:
        raise ReconciliationError("lease identity mismatch")
    return path, lease


def list_leases(
    session_id: str | None = None,
    *,
    states: set[str] | None = None,
    state_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    root = _state_root(state_root)
    base = root / "leases"
    if not base.is_dir():
        return []
    paths = list((base / _slug(session_id)).glob("*.json")) if session_id else list(base.glob("*/*.json"))
    result: list[dict[str, Any]] = []
    for path in sorted(paths):
        try:
            lease = _load_json(path)
        except ReconciliationError:
            continue
        if lease.get("schema") != LEASE_SCHEMA:
            continue
        if states and lease.get("state") not in states:
            continue
        lease = dict(lease)
        lease["lease_path"] = str(path)
        result.append(lease)
    return result


def touch_lease(path: Path, lease: dict[str, Any]) -> dict[str, Any]:
    updated = dict(lease)
    updated["updated_at"] = utc_now()
    updated["lease_deadline"] = _lease_deadline()
    _atomic_json(path, updated, immutable=False)
    return updated


def git_root_for_target(path_arg: str, *, base: str | Path | None = None) -> tuple[Path, str] | None:
    raw = Path(path_arg).expanduser()
    if not raw.is_absolute():
        if base is None:
            return None
        raw = Path(base).expanduser() / raw
    target = raw.resolve(strict=False)
    probe = target if target.is_dir() else target.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    proc = subprocess.run(
        ["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        return None
    repo = Path(proc.stdout.strip()).resolve()
    try:
        relative = target.relative_to(repo).as_posix()
    except ValueError:
        return None
    return repo, relative


def lease_for_target(
    session_id: str,
    path_arg: str,
    *,
    base: str | Path | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    located = git_root_for_target(path_arg, base=base)
    if not located:
        return {"kind": "not_git"}
    repo, relative = located
    gate = _gate()
    matching_repo: list[dict[str, Any]] = []
    for lease in list_leases(session_id, states={"ACTIVE"}, state_root=state_root):
        if Path(str(lease.get("worktree"))).resolve() != repo:
            continue
        matching_repo.append(lease)
        if _is_expired(lease):
            continue
        if gate.path_claimed(relative, lease.get("owned_paths") or []):
            return {"kind": "claimed", "repo": str(repo), "relative": relative, "lease": lease}
    if matching_repo:
        return {"kind": "outside_scope", "repo": str(repo), "relative": relative, "lease": matching_repo[0]}
    return {"kind": "no_lease", "repo": str(repo), "relative": relative}


def extend_lease(
    *,
    session_id: str,
    run_id: str,
    owned_paths: Iterable[str],
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    gate = _gate()
    path, _ = load_lease(session_id, run_id, state_root=state_root)
    with _lease_lock(path):
        lease = _load_json(path)
        if lease.get("state") != "ACTIVE":
            raise ReconciliationError(f"only ACTIVE leases can be extended; state={lease.get('state')}")
        repo = gate.repo_root(lease["worktree"])
        opened = _load_json(Path(lease["open_receipt"]))
        scopes = gate.normalize_scopes([*(lease.get("owned_paths") or []), *list(owned_paths)])
        live_identity = gate.identity(repo)
        snapshot = gate.status_snapshot(repo)
        effective_open = dict(opened)
        effective_open["owned_paths"] = scopes
        classifications = gate.classify_paths(effective_open, snapshot)
        violations = gate.verify_identity(opened, live_identity)
        if classifications["foreign_unknown"]:
            violations.append("existing dirt remains outside the proposed extended scope")
        peer_scan = gate.scan_peer_worktrees(repo, scopes)
        if not peer_scan["ok"]:
            violations.append("proposed scope overlaps a dirty peer worktree")
        event = {
            "schema": EXTENSION_SCHEMA,
            "generated_at": utc_now(),
            "session_id": session_id,
            "run_id": run_id,
            "ok": not violations,
            "gate": "Pass" if not violations else "Blocked",
            "worktree": str(repo),
            "previous_owned_paths": lease.get("owned_paths") or [],
            "proposed_owned_paths": scopes,
            "current_status_sha256": snapshot["sha256"],
            "classifications": classifications,
            "collision_check": peer_scan,
            "violations": violations,
        }
        event_path = _event_path(Path(lease["run_directory"]), "scope-extension")
        _atomic_json(event_path, event, immutable=True)
        if violations:
            return {"ok": False, "gate": "Blocked", "state": "ACTIVE", "event": str(event_path), "violations": violations}
        lease["owned_paths"] = scopes
        lease["last_event"] = str(event_path)
        lease = touch_lease(path, lease)
        return {"ok": True, "gate": "Pass", "state": "ACTIVE", "owned_paths": scopes, "event": str(event_path)}


def _sensitive_path_violations(repo: Path, paths: Iterable[str]) -> list[str]:
    violations: list[str] = []
    for relative in paths:
        candidate = (repo / relative).resolve(strict=False)
        try:
            candidate.relative_to(repo)
        except ValueError:
            violations.append(f"path escapes worktree: {relative}")
            continue
        name = Path(relative).name.lower()
        suffix = Path(relative).suffix.lower()
        if name in BLOCKED_EXACT_NAMES or name.startswith(".env.") or name.startswith("credentials.") or name.startswith("secrets."):
            violations.append(f"automatic checkpoint blocks sensitive filename: {relative}")
            continue
        if suffix in BLOCKED_SUFFIXES:
            violations.append(f"automatic checkpoint blocks sensitive/binary file class: {relative}")
            continue
        if not candidate.exists() and not candidate.is_symlink():
            continue  # deletion
        try:
            info = candidate.lstat()
        except OSError:
            violations.append(f"cannot inspect checkpoint path: {relative}")
            continue
        if info.st_size > MAX_AUTOMATIC_FILE_BYTES:
            violations.append(f"automatic checkpoint file exceeds 10 MiB: {relative}")
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.readlink(candidate))
            if target.is_absolute() or ".." in target.parts:
                violations.append(f"automatic checkpoint blocks escaping symlink: {relative}")
        elif not stat.S_ISREG(info.st_mode):
            violations.append(f"automatic checkpoint blocks non-regular file: {relative}")
    return violations


def _staged_paths(repo: Path) -> list[str]:
    raw = _run_git(repo, "diff", "--cached", "--name-only", "-z").stdout
    return sorted(part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part)


def _write_checkpoint_event(lease: dict[str, Any], event: dict[str, Any], label: str) -> Path:
    path = _event_path(Path(lease["run_directory"]), label)
    _atomic_json(path, event, immutable=True)
    return path


def _finish_failed_checkpoint(
    lease_path: Path,
    lease: dict[str, Any],
    event: dict[str, Any],
    *,
    finalize: bool,
) -> dict[str, Any]:
    event["ok"] = False
    event["gate"] = "Blocked"
    event["complete"] = False
    event["state"] = "BLOCKED_DIRTY" if finalize else "CHECKPOINT_RETRY_REQUIRED"
    event_path = _write_checkpoint_event(lease, event, "checkpoint-blocked")
    lease["last_event"] = str(event_path)
    lease["blocker"] = "; ".join(event.get("violations") or ["checkpoint blocked"])
    lease["updated_at"] = utc_now()
    if finalize:
        lease["state"] = "BLOCKED_DIRTY"
        lease["closed_at"] = utc_now()
    else:
        lease["state"] = "ACTIVE"
        lease["lease_deadline"] = _lease_deadline()
    _atomic_json(lease_path, lease, immutable=False)
    return {
        "ok": False,
        "gate": "Blocked",
        "state": event["state"],
        "complete": False,
        "receipt": str(event_path),
        "violations": event.get("violations") or [],
    }


def checkpoint_lease(
    *,
    session_id: str,
    run_id: str,
    reason: str,
    finalize: bool,
    state_root: str | Path | None = None,
    gitleaks_path: str | None = None,
) -> dict[str, Any]:
    gate = _gate()
    lease_path, _ = load_lease(session_id, run_id, state_root=state_root)
    with _lease_lock(lease_path):
        lease = _load_json(lease_path)
        if lease.get("state") != "ACTIVE":
            return {
                "ok": lease.get("state") in {"CHECKPOINTED_WIP", "NO_CHANGE", "ALREADY_CLEAN"},
                "gate": "Pass" if lease.get("state") in {"CHECKPOINTED_WIP", "NO_CHANGE", "ALREADY_CLEAN"} else "Blocked",
                "state": lease.get("state"),
                "complete": bool(lease.get("complete")),
                "receipt": lease.get("last_event"),
            }
        if lease.get("session_id") != session_id:
            raise ReconciliationError("session does not own this lease")

        repo = gate.repo_root(lease["worktree"])
        opened = _load_json(Path(lease["open_receipt"]))
        effective_open = dict(opened)
        effective_open["owned_paths"] = lease.get("owned_paths") or []
        live_identity = gate.identity(repo)
        snapshot = gate.status_snapshot(repo)
        classifications = gate.classify_paths(effective_open, snapshot)
        peer_scan = gate.scan_peer_worktrees(repo, effective_open["owned_paths"])
        violations = gate.verify_identity(opened, live_identity)
        if live_identity.get("branch") in gate.CANONICAL_BRANCHES or not live_identity.get("branch"):
            violations.append("automatic checkpoint requires a non-canonical attached task branch")
        if classifications["foreign_unknown"]:
            violations.append("dirty paths escape the lease ownership scope")
        if not peer_scan["ok"]:
            violations.append("dirty peer worktree overlaps the lease ownership scope")

        event: dict[str, Any] = {
            "schema": CHECKPOINT_SCHEMA,
            "generated_at": utc_now(),
            "authority_policy": AUTHORITY_POLICY,
            "session_id": session_id,
            "run_id": run_id,
            "reason": reason,
            "worktree": str(repo),
            "branch": live_identity.get("branch"),
            "starting_head": opened["identity"]["head"],
            "pre_checkpoint_head": live_identity.get("head"),
            "pre_checkpoint_status_sha256": snapshot["sha256"],
            "owned_paths": effective_open["owned_paths"],
            "classifications": classifications,
            "collision_check": peer_scan,
            "dirty_paths": [row["path"] for row in snapshot["rows"]],
            "untracked_paths": classifications["untracked"],
            "secret_scan": {"tool": "gitleaks", "status": "not_run"},
            "diff_check": "not_run",
            "tests": "not_attested_by_checkpoint_hook",
            "commit": None,
            "final_status_sha256": None,
            "violations": violations,
            "complete": False,
        }
        if violations:
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)

        if not snapshot["dirty_path_count"]:
            same_head = live_identity["head"] == opened["identity"]["head"]
            event.update({
                "ok": True,
                "gate": "Pass",
                "state": "NO_CHANGE" if same_head else "ALREADY_CLEAN",
                "complete": same_head,
                "final_status_sha256": snapshot["sha256"],
            })
            event_path = _write_checkpoint_event(lease, event, "clean-close")
            lease.update({
                "state": event["state"],
                "complete": event["complete"],
                "updated_at": utc_now(),
                "closed_at": utc_now(),
                "ending_head": live_identity["head"],
                "last_event": str(event_path),
                "blocker": None,
            })
            _atomic_json(lease_path, lease, immutable=False)
            return {"ok": True, "gate": "Pass", "state": event["state"], "complete": event["complete"], "receipt": str(event_path)}

        dirty_paths = [row["path"] for row in snapshot["rows"]]
        event["violations"].extend(_sensitive_path_violations(repo, dirty_paths))
        if event["violations"]:
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)

        # Exact-path staging only. No broad add, stash, reset, clean, checkout, or deletion.
        stage = _run_git(repo, "add", "-A", "--", *dirty_paths, check=False)
        if stage.returncode:
            event["violations"].append(f"exact-path staging failed with exit {stage.returncode}")
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)

        staged = _staged_paths(repo)
        post_stage = gate.status_snapshot(repo)
        expected = sorted(set(dirty_paths))
        if staged != expected:
            event["violations"].append("staged path set does not exactly equal the leased dirty path set")
        if any(row["worktree_status"] not in {" ", "?"} for row in post_stage["rows"]):
            event["violations"].append("working files changed concurrently after staging")
        if event["violations"]:
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)

        diff_check = _run_git(repo, "diff", "--cached", "--check", check=False)
        event["diff_check"] = "pass" if diff_check.returncode == 0 else "fail"
        if diff_check.returncode:
            event["violations"].append("git diff --cached --check failed")
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)

        scanner = gitleaks_path or shutil.which("gitleaks")
        if not scanner:
            event["violations"].append("gitleaks is unavailable; automatic checkpoint fails closed")
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)
        report_path = _event_path(Path(lease["run_directory"]), "gitleaks")
        report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        scan = subprocess.run(
            [
                scanner, "git", "--staged", "--no-banner", "--no-color", "--redact",
                "--report-format", "json", "--report-path", str(report_path),
                "--timeout", "30", str(repo),
            ],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if not report_path.exists():
            _atomic_json(report_path, {"findings": [], "scanner_exit": scan.returncode}, immutable=True)
        event["secret_scan"] = {
            "tool": "gitleaks",
            "status": "pass" if scan.returncode == 0 else "blocked",
            "exit_code": scan.returncode,
            "report": str(report_path),
            "report_sha256": _sha256_file(report_path),
        }
        if scan.returncode:
            event["violations"].append("gitleaks blocked the staged checkpoint")
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)

        safe_run = _display_token(run_id)
        safe_session = _display_token(session_id)
        message = (
            f"wip({safe_run}): automatic local checkpoint\n\n"
            f"Run-ID: {safe_run}\n"
            f"Session-ID: {safe_session}\n"
            f"Checkpoint-Reason: {_display_token(reason)}\n"
            "Complete: false"
        )
        commit_env = os.environ.copy()
        commit_env.update({
            "GIT_AUTHOR_NAME": "Hermes Worktree Gate",
            "GIT_AUTHOR_EMAIL": "checkpoint@local.invalid",
            "GIT_COMMITTER_NAME": "Hermes Worktree Gate",
            "GIT_COMMITTER_EMAIL": "checkpoint@local.invalid",
        })
        commit = _run_git(repo, "commit", "-m", message, check=False, env=commit_env)
        if commit.returncode:
            event["violations"].append(f"local WIP commit failed with exit {commit.returncode}")
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=finalize)

        ending_identity = gate.identity(repo)
        ending_status = gate.status_snapshot(repo)
        event["commit"] = ending_identity["head"]
        event["final_status_sha256"] = ending_status["sha256"]
        event["remaining_dirty_paths"] = [row["path"] for row in ending_status["rows"]]
        if ending_status["dirty_path_count"]:
            event["violations"].append("worktree remained dirty after checkpoint commit")
            return _finish_failed_checkpoint(lease_path, lease, event, finalize=True)

        event.update({"ok": True, "gate": "Pass", "state": "CHECKPOINTED_WIP", "complete": False})
        event_path = _write_checkpoint_event(lease, event, "checkpoint")
        lease.update({
            "state": "CHECKPOINTED_WIP",
            "complete": False,
            "updated_at": utc_now(),
            "closed_at": utc_now(),
            "ending_head": ending_identity["head"],
            "checkpoint_commit": ending_identity["head"],
            "last_event": str(event_path),
            "blocker": None,
        })
        _atomic_json(lease_path, lease, immutable=False)
        return {
            "ok": True,
            "gate": "Pass",
            "state": "CHECKPOINTED_WIP",
            "complete": False,
            "commit": ending_identity["head"],
            "receipt": str(event_path),
        }


def checkpoint_session(
    session_id: str,
    *,
    reason: str,
    finalize: bool,
    state_root: str | Path | None = None,
    gitleaks_path: str | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for lease in list_leases(session_id, states={"ACTIVE"}, state_root=state_root):
        results.append(checkpoint_lease(
            session_id=session_id,
            run_id=lease["run_id"],
            reason=reason,
            finalize=finalize,
            state_root=state_root,
            gitleaks_path=gitleaks_path,
        ))
    return results


def status_summary(session_id: str | None = None, *, state_root: str | Path | None = None) -> dict[str, Any]:
    leases = list_leases(session_id, state_root=state_root)
    return {
        "schema": "loaw.worktree_reconciliation_status.v1",
        "ok": True,
        "gate": "Pass",
        "session_id": session_id,
        "lease_count": len(leases),
        "leases": [
            {key: lease.get(key) for key in (
                "session_id", "run_id", "state", "complete", "worktree", "branch",
                "starting_head", "ending_head", "owned_paths", "lease_deadline",
                "checkpoint_commit", "blocker", "last_event",
            )}
            for lease in leases
        ],
    }


def shell_open_command(repo: str, session_id: str, run_id: str, owned_path: str) -> str:
    return " ".join([
        "hermes", "worktree-gate", "open",
        "--repo", shlex.quote(repo),
        "--session-id", shlex.quote(session_id),
        "--run-id", shlex.quote(run_id),
        "--owned-path", shlex.quote(owned_path),
    ])


def shell_extend_command(session_id: str, run_id: str, owned_path: str) -> str:
    return " ".join([
        "hermes", "worktree-gate", "extend",
        "--session-id", shlex.quote(session_id),
        "--run-id", shlex.quote(run_id),
        "--owned-path", shlex.quote(owned_path),
    ])
