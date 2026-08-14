#!/usr/bin/env python3
"""Non-destructive lifecycle gate for task-owned Git worktrees.

This tool records and validates worktree state. It never stages, commits, stashes,
resets, cleans, deletes, pushes, merges, or checks out files.

Operations:
  open   Register a clean or explicitly adopted baseline and path ownership.
  audit  Classify live dirt against the registered baseline and ownership scope.
  close  Validate one declared closeout disposition and emit an immutable receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

OPEN_SCHEMA = "loaw.worktree_reconciliation_open.v1"
AUDIT_SCHEMA = "loaw.worktree_reconciliation_audit.v1"
CLOSE_SCHEMA = "loaw.worktree_reconciliation_closeout.v1"
ADOPTION_SCHEMA = "loaw.dirty_baseline_adoption.v1"
HANDOFF_SCHEMA = "loaw.worktree_patch_handoff.v1"
CANONICAL_BRANCHES = {"main", "master", "trunk", "production", "release"}


class GateError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and proc.returncode:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git {' '.join(args)} failed: {detail}")
    return proc


def git_text(repo: Path, *args: str, required: bool = True) -> str | None:
    proc = run_git(repo, *args, check=False)
    if proc.returncode:
        if required:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise GateError(f"git {' '.join(args)} failed: {detail}")
        return None
    return proc.stdout.decode("utf-8", "surrogateescape").strip()


def repo_root(repo_arg: str) -> Path:
    supplied = Path(repo_arg).expanduser().resolve()
    root = git_text(supplied, "rev-parse", "--show-toplevel")
    if not root:
        raise GateError(f"not a Git worktree: {supplied}")
    return Path(root).resolve()


def resolve_git_path(repo: Path, value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = repo / path
    return str(path.resolve())


def identity(repo: Path) -> dict[str, Any]:
    branch = git_text(repo, "symbolic-ref", "--quiet", "--short", "HEAD", required=False)
    head = git_text(repo, "rev-parse", "HEAD")
    upstream = git_text(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", required=False)
    git_dir = git_text(repo, "rev-parse", "--git-dir")
    common_dir = git_text(repo, "rev-parse", "--git-common-dir")
    return {
        "worktree": str(repo),
        "git_dir": resolve_git_path(repo, git_dir or ".git"),
        "common_git_dir": resolve_git_path(repo, common_dir or ".git"),
        "branch": branch,
        "head": head,
        "upstream": upstream,
    }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def working_path_fingerprint(repo: Path, relative: str) -> dict[str, Any]:
    target = repo / relative
    try:
        info = target.lstat()
    except FileNotFoundError:
        return {"kind": "absent", "sha256": None, "size": None, "mode": None}
    mode = stat.S_IMODE(info.st_mode)
    if target.is_symlink():
        value = os.readlink(target).encode("utf-8", "surrogateescape")
        return {"kind": "symlink", "sha256": sha256_bytes(value), "size": len(value), "mode": mode}
    if target.is_file():
        return {"kind": "file", "sha256": sha256_file(target), "size": info.st_size, "mode": mode}
    return {"kind": "other", "sha256": None, "size": info.st_size, "mode": mode}


def status_snapshot(repo: Path) -> dict[str, Any]:
    raw = run_git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    tokens = raw.split(b"\0")
    rows: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        record = tokens[index]
        index += 1
        if not record:
            continue
        text = record.decode("utf-8", "surrogateescape")
        if len(text) < 4:
            raise GateError(f"unexpected porcelain record: {text!r}")
        xy = text[:2]
        path = text[3:]
        original_path = None
        if xy[0] in {"R", "C"}:
            if index >= len(tokens) or not tokens[index]:
                raise GateError(f"rename/copy record missing source path: {text!r}")
            original_path = tokens[index].decode("utf-8", "surrogateescape")
            index += 1
        row = {
            "path": path,
            "original_path": original_path,
            "index_status": xy[0],
            "worktree_status": xy[1],
            "untracked": xy == "??",
            "ignored": xy == "!!",
            "fingerprint": working_path_fingerprint(repo, path),
        }
        rows.append(row)
    rows.sort(key=lambda item: (item["path"], item.get("original_path") or ""))
    return {
        "sha256": sha256_bytes(raw),
        "raw_bytes": len(raw),
        "dirty_path_count": len(rows),
        "rows": rows,
    }


def normalize_scope(value: str) -> str:
    raw = value.replace("\\", "/").strip()
    path = PurePosixPath(raw)
    if not raw or raw.startswith("/") or ".." in path.parts:
        raise GateError(f"owned path must be a safe repository-relative path: {value!r}")
    normalized = str(path).rstrip("/")
    if normalized in {"", "."}:
        raise GateError("repository-wide ownership is not allowed; claim bounded paths")
    return normalized


def normalize_scopes(values: Iterable[str]) -> list[str]:
    scopes = sorted(set(normalize_scope(value) for value in values))
    if not scopes:
        raise GateError("at least one --owned-path is required")
    return scopes


def path_within_scope(path: str, scope: str) -> bool:
    return path == scope or path.startswith(scope + "/")


def path_claimed(path: str, scopes: Iterable[str]) -> bool:
    return any(path_within_scope(path, scope) for scope in scopes)


def scopes_overlap_path(scope: str, path: str) -> bool:
    return path_within_scope(path, scope) or path_within_scope(scope, path)


def worktree_paths(repo: Path) -> list[str]:
    text = git_text(repo, "worktree", "list", "--porcelain") or ""
    result: list[str] = []
    for line in text.splitlines():
        if line.startswith("worktree "):
            result.append(line[len("worktree ") :])
    return result


def scan_peer_worktrees(repo: Path, scopes: list[str]) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []
    overlaps: list[dict[str, Any]] = []
    current = str(repo.resolve())
    for raw_peer in worktree_paths(repo):
        peer = Path(raw_peer).expanduser().resolve()
        if str(peer) == current:
            continue
        if not peer.is_dir():
            checked.append({"worktree": str(peer), "status": "missing_or_prunable"})
            continue
        proc = run_git(peer, "status", "--porcelain=v1", "-z", "--untracked-files=all", check=False)
        if proc.returncode:
            checked.append({"worktree": str(peer), "status": "unreadable"})
            continue
        try:
            peer_snapshot = status_snapshot(peer)
        except GateError:
            checked.append({"worktree": str(peer), "status": "unreadable"})
            continue
        peer_dirty = [row["path"] for row in peer_snapshot["rows"]]
        checked.append({
            "worktree": str(peer),
            "status": "checked",
            "dirty_path_count": len(peer_dirty),
            "status_sha256": peer_snapshot["sha256"],
        })
        for dirty_path in peer_dirty:
            matching = [scope for scope in scopes if scopes_overlap_path(scope, dirty_path)]
            if matching:
                overlaps.append({
                    "worktree": str(peer),
                    "dirty_path": dirty_path,
                    "owned_scopes": matching,
                })
    return {"ok": not overlaps, "peer_worktrees_checked": checked, "overlaps": overlaps}


def load_json(path_arg: str) -> dict[str, Any]:
    path = Path(path_arg).expanduser().resolve()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise GateError(f"expected a JSON object: {path}")
    return data


def ensure_output_outside_repo(repo: Path, output: Path) -> None:
    try:
        output.relative_to(repo)
    except ValueError:
        return
    raise GateError("receipt output must be outside the audited repository")


def immutable_write_json(path_arg: str, payload: dict[str, Any], repo: Path) -> Path:
    destination = Path(path_arg).expanduser().resolve()
    ensure_output_outside_repo(repo, destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise GateError(f"refusing to overwrite immutable receipt: {destination}") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return destination


def validate_adoption_manifest(
    manifest: dict[str, Any], ident: dict[str, Any], snapshot: dict[str, Any]
) -> list[dict[str, Any]]:
    errors: list[str] = []
    if manifest.get("schema") != ADOPTION_SCHEMA:
        errors.append(f"schema must be {ADOPTION_SCHEMA}")
    if manifest.get("starting_head") != ident["head"]:
        errors.append("starting_head does not match live HEAD")
    if manifest.get("starting_status_sha256") != snapshot["sha256"]:
        errors.append("starting_status_sha256 does not match live status")
    if not manifest.get("approved_by"):
        errors.append("approved_by is required")
    entries = manifest.get("paths")
    if not isinstance(entries, list):
        errors.append("paths must be a list")
        entries = []
    current_paths = {row["path"] for row in snapshot["rows"]}
    manifest_paths: set[str] = set()
    required = {"path", "classification", "provenance", "owner", "intended_disposition"}
    for entry in entries:
        if not isinstance(entry, dict) or not required.issubset(entry):
            errors.append("every adoption path needs path, classification, provenance, owner, intended_disposition")
            continue
        manifest_paths.add(str(entry["path"]))
    if manifest_paths != current_paths:
        errors.append("adoption manifest path set does not exactly match live dirty paths")
    if errors:
        raise GateError("invalid adoption manifest: " + "; ".join(errors))
    return entries


def open_gate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    repo = repo_root(args.repo)
    ident = identity(repo)
    snapshot = status_snapshot(repo)
    scopes = normalize_scopes(args.owned_path)
    violations: list[str] = []
    adoption_entries: list[dict[str, Any]] = []

    if not ident["branch"]:
        violations.append("detached HEAD is not a task-owned branch")
    elif ident["branch"] in CANONICAL_BRANCHES:
        violations.append(f"canonical branch is observation-only: {ident['branch']}")
    if snapshot["dirty_path_count"]:
        if not args.adoption_manifest:
            violations.append("dirty baseline lacks an explicit adoption manifest")
        else:
            try:
                adoption_entries = validate_adoption_manifest(
                    load_json(args.adoption_manifest), ident, snapshot
                )
            except GateError as exc:
                violations.append(str(exc))

    peer_scan = scan_peer_worktrees(repo, scopes)
    if not peer_scan["ok"]:
        violations.append("owned path scope overlaps dirty paths in peer worktrees")

    ok = not violations
    receipt = {
        "schema": OPEN_SCHEMA,
        "operation": "open",
        "generated_at": utc_now(),
        "run_id": args.run_id,
        "owner": args.owner,
        "ok": ok,
        "gate": "Pass" if ok else "Blocked",
        "state": "OPEN_ADOPTED_DIRTY" if ok and snapshot["dirty_path_count"] else (
            "OPEN_CLEAN" if ok else "OPEN_REJECTED"
        ),
        "complete": False,
        "identity": ident,
        "starting_status": snapshot,
        "owned_paths": scopes,
        "adoption_manifest": str(Path(args.adoption_manifest).expanduser().resolve()) if args.adoption_manifest else None,
        "adopted_paths": adoption_entries,
        "collision_check": peer_scan,
        "violations": violations,
        "non_destructive": True,
    }
    return receipt, 0 if ok else 2


def load_open_receipt(path_arg: str) -> dict[str, Any]:
    receipt = load_json(path_arg)
    if receipt.get("schema") != OPEN_SCHEMA or receipt.get("operation") != "open":
        raise GateError("not a worktree reconciliation open receipt")
    if not receipt.get("ok"):
        raise GateError("the open receipt was blocked and cannot authorize work")
    return receipt


def verify_identity(open_receipt: dict[str, Any], live: dict[str, Any]) -> list[str]:
    start = open_receipt["identity"]
    violations: list[str] = []
    for key in ("worktree", "common_git_dir", "branch"):
        if start.get(key) != live.get(key):
            violations.append(f"identity drift: {key} changed from {start.get(key)!r} to {live.get(key)!r}")
    return violations


def classify_paths(open_receipt: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, list[str]]:
    scopes = open_receipt["owned_paths"]
    baseline = {row["path"] for row in open_receipt["starting_status"]["rows"]}
    result: dict[str, list[str]] = {
        "authored_owned": [],
        "adopted_owned": [],
        "adopted_baseline": [],
        "foreign_unknown": [],
        "untracked": [],
    }
    for row in snapshot["rows"]:
        path = row["path"]
        claimed = path_claimed(path, scopes)
        if path in baseline and claimed:
            result["adopted_owned"].append(path)
        elif path in baseline:
            result["adopted_baseline"].append(path)
        elif claimed:
            result["authored_owned"].append(path)
        else:
            result["foreign_unknown"].append(path)
        if row["untracked"]:
            result["untracked"].append(path)
    for values in result.values():
        values.sort()
    return result


def audit_gate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    opened = load_open_receipt(args.open_receipt)
    repo = repo_root(opened["identity"]["worktree"])
    live_identity = identity(repo)
    snapshot = status_snapshot(repo)
    classifications = classify_paths(opened, snapshot)
    violations = verify_identity(opened, live_identity)
    if classifications["foreign_unknown"]:
        violations.append("live dirty paths escape the registered ownership/adoption scope")
    peer_scan = scan_peer_worktrees(repo, opened["owned_paths"])
    if not peer_scan["ok"]:
        violations.append("a peer worktree now overlaps the registered ownership scope")
    ok = not violations
    state = "ACTIVE_OWNED" if snapshot["dirty_path_count"] and ok else (
        "OPEN_CLEAN" if ok else "COLLISION_BLOCKED"
    )
    receipt = {
        "schema": AUDIT_SCHEMA,
        "operation": "audit",
        "generated_at": utc_now(),
        "run_id": opened["run_id"],
        "owner": opened["owner"],
        "open_receipt": str(Path(args.open_receipt).expanduser().resolve()),
        "ok": ok,
        "gate": "Pass" if ok else "Blocked",
        "state": state,
        "complete": False,
        "identity": live_identity,
        "current_status": snapshot,
        "classifications": classifications,
        "collision_check": peer_scan,
        "violations": violations,
        "non_destructive": True,
    }
    return receipt, 0 if ok else 2


def committed_paths(repo: Path, starting_head: str, ending_head: str) -> list[str]:
    raw = run_git(repo, "diff", "--name-only", "-z", f"{starting_head}..{ending_head}").stdout
    paths = [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]
    return sorted(set(paths))


def artifact_record(path_arg: str | None) -> dict[str, Any] | None:
    if not path_arg:
        return None
    path = Path(path_arg).expanduser().resolve()
    if not path.is_file():
        raise GateError(f"artifact is not a regular file: {path}")
    return {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}


def validate_handoff(
    manifest_arg: str | None,
    artifact: dict[str, Any] | None,
    opened: dict[str, Any],
    snapshot: dict[str, Any],
) -> list[str]:
    violations: list[str] = []
    if not manifest_arg:
        return ["patch_handoff requires --handoff-manifest"]
    if not artifact:
        return ["patch_handoff requires --artifact"]
    manifest = load_json(manifest_arg)
    if manifest.get("schema") != HANDOFF_SCHEMA:
        violations.append(f"handoff schema must be {HANDOFF_SCHEMA}")
    if manifest.get("base_head") != opened["identity"]["head"]:
        violations.append("handoff base_head does not match starting HEAD")
    if manifest.get("artifact_sha256") != artifact["sha256"]:
        violations.append("handoff artifact_sha256 does not match artifact bytes")
    live_paths = {row["path"] for row in snapshot["rows"]}
    declared_paths = set(manifest.get("paths") or [])
    if declared_paths != live_paths:
        violations.append("handoff path set does not exactly cover every live dirty path")
    live_untracked = {row["path"] for row in snapshot["rows"] if row["untracked"]}
    declared_untracked = set(manifest.get("untracked_paths") or [])
    if declared_untracked != live_untracked:
        violations.append("handoff untracked_paths does not exactly cover live untracked files")
    return violations


def close_gate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    opened = load_open_receipt(args.open_receipt)
    repo = repo_root(opened["identity"]["worktree"])
    live_identity = identity(repo)
    snapshot = status_snapshot(repo)
    classifications = classify_paths(opened, snapshot)
    violations = verify_identity(opened, live_identity)
    peer_scan = scan_peer_worktrees(repo, opened["owned_paths"])
    if not peer_scan["ok"]:
        violations.append("peer-worktree overlap exists at closeout")

    disposition = args.disposition
    artifact = artifact_record(args.artifact)
    authority = artifact_record(args.authority_receipt)
    start_head = opened["identity"]["head"]
    end_head = live_identity["head"]
    commit_paths: list[str] = []

    if disposition == "committed_clean":
        if snapshot["dirty_path_count"]:
            violations.append("committed_clean requires an empty final Git status")
        if end_head == start_head:
            violations.append("committed_clean requires ending HEAD to differ from starting HEAD")
        if not authority:
            violations.append("committed_clean requires --authority-receipt")
        if classifications["foreign_unknown"]:
            violations.append("committed_clean cannot include unexplained paths")
        if end_head != start_head:
            commit_paths = committed_paths(repo, start_head, end_head)
            allowed_scopes = opened["owned_paths"]
            adopted = {row["path"] for row in opened["starting_status"]["rows"]}
            escaped = [
                path for path in commit_paths
                if path not in adopted and not path_claimed(path, allowed_scopes)
            ]
            if escaped:
                violations.append("commit range contains paths outside ownership/adoption scope: " + ", ".join(escaped))
    elif disposition == "no_change":
        if snapshot["dirty_path_count"]:
            violations.append("no_change requires an empty final Git status")
        if end_head != start_head:
            violations.append("no_change requires ending HEAD to equal starting HEAD")
    elif disposition == "patch_handoff":
        violations.extend(validate_handoff(args.handoff_manifest, artifact, opened, snapshot))
        if classifications["foreign_unknown"]:
            violations.append("patch_handoff cannot claim unexplained paths")
    elif disposition == "blocked_dirty":
        if not args.blocker:
            violations.append("blocked_dirty requires --blocker")
        if not args.next_action:
            violations.append("blocked_dirty requires --next-action")
    else:
        violations.append(f"unsupported disposition: {disposition}")

    valid = not violations
    complete = valid and disposition in {"committed_clean", "no_change"}
    if not valid:
        gate = "Blocked"
        state = "CLOSE_REJECTED"
    elif complete:
        gate = "Pass"
        state = "COMMITTED_CLEAN" if disposition == "committed_clean" else "NO_CHANGE"
    else:
        gate = "Warnings"
        state = "PATCH_HANDOFF" if disposition == "patch_handoff" else "BLOCKED_DIRTY"

    receipt = {
        "schema": CLOSE_SCHEMA,
        "operation": "close",
        "generated_at": utc_now(),
        "run_id": opened["run_id"],
        "owner": opened["owner"],
        "open_receipt": str(Path(args.open_receipt).expanduser().resolve()),
        "ok": valid,
        "gate": gate,
        "state": state,
        "disposition": disposition,
        "complete": complete,
        "starting_head": start_head,
        "ending_head": end_head,
        "branch": live_identity["branch"],
        "upstream": live_identity["upstream"],
        "worktree": live_identity["worktree"],
        "common_git_dir": live_identity["common_git_dir"],
        "starting_status_sha256": opened["starting_status"]["sha256"],
        "ending_status_sha256": snapshot["sha256"],
        "current_status": snapshot,
        "owned_paths": opened["owned_paths"],
        "classifications": classifications,
        "untracked_paths": classifications["untracked"],
        "remaining_dirty_paths": [row["path"] for row in snapshot["rows"]],
        "collision_check": peer_scan,
        "commit_paths": commit_paths,
        "authority_receipt": authority,
        "patch_artifact": artifact,
        "handoff_manifest": str(Path(args.handoff_manifest).expanduser().resolve()) if args.handoff_manifest else None,
        "test_receipts": [str(Path(path).expanduser().resolve()) for path in args.test_receipt],
        "diff_check": args.diff_check,
        "blocker": args.blocker,
        "next_action": args.next_action,
        "violations": violations,
        "non_destructive": True,
    }
    return receipt, 0 if valid else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)

    open_parser = commands.add_parser("open", help="register baseline, ownership, and peer collision state")
    open_parser.add_argument("--repo", required=True)
    open_parser.add_argument("--run-id", required=True)
    open_parser.add_argument("--owner", required=True)
    open_parser.add_argument("--owned-path", action="append", default=[], required=True)
    open_parser.add_argument("--adoption-manifest")
    open_parser.add_argument("--output", required=True)

    audit_parser = commands.add_parser("audit", help="classify live dirt against an open receipt")
    audit_parser.add_argument("--open-receipt", required=True)
    audit_parser.add_argument("--output", required=True)

    close_parser = commands.add_parser("close", help="validate and record one closeout disposition")
    close_parser.add_argument("--open-receipt", required=True)
    close_parser.add_argument(
        "--disposition",
        required=True,
        choices=["committed_clean", "no_change", "patch_handoff", "blocked_dirty"],
    )
    close_parser.add_argument("--authority-receipt")
    close_parser.add_argument("--artifact")
    close_parser.add_argument("--handoff-manifest")
    close_parser.add_argument("--test-receipt", action="append", default=[])
    close_parser.add_argument("--diff-check", choices=["pass", "fail", "not_run"], default="not_run")
    close_parser.add_argument("--blocker")
    close_parser.add_argument("--next-action")
    close_parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.operation == "open":
            receipt, exit_code = open_gate(args)
            repo = repo_root(args.repo)
            output = args.output
        elif args.operation == "audit":
            receipt, exit_code = audit_gate(args)
            repo = repo_root(receipt["identity"]["worktree"])
            output = args.output
        else:
            receipt, exit_code = close_gate(args)
            repo = repo_root(receipt["worktree"])
            output = args.output
        destination = immutable_write_json(output, receipt, repo)
        print(json.dumps({
            "ok": receipt["ok"],
            "gate": receipt["gate"],
            "state": receipt["state"],
            "complete": receipt["complete"],
            "output": str(destination),
        }, sort_keys=True))
        return exit_code
    except (GateError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "gate": "Blocked", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
