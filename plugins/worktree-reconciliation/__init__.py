"""Hermes hooks for fail-closed worktree reconciliation and local WIP checkpoints."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from . import engine
from .cli import register_cli, worktree_gate_command

logger = logging.getLogger("worktree-reconciliation")

_FILE_WRITE_TOOLS = {"write_file", "patch", "apply_patch"}
_PATCH_PATH = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", re.MULTILINE)
_PATCH_MOVE = re.compile(r"^\*\*\* Move to: (.+)$", re.MULTILINE)
_EXPLICIT_TERMINAL_MUTATOR = re.compile(
    r"(?i)(?:\bgit\s+(?:-C\s+\S+\s+)?(?:add|apply|commit|mv|rm|restore|reset|clean|checkout|switch|merge|cherry-pick|rebase|stash)\b"
    r"|(?:^|[;&|]\s*)(?:cp|mv|rm|touch|mkdir|install)\s+)"
)
_BROAD_GIT_MUTATION = re.compile(
    r"(?i)(?:\bgit\s+add\s+(?:-A|--all|\.)\b|\bgit\s+commit\s+-a\b|\bgit\s+(?:stash|reset|clean)\b)"
)


def _session_id(kwargs: dict[str, Any]) -> str:
    return str(kwargs.get("session_id") or kwargs.get("task_id") or "").strip()


def _tool_paths(tool_name: str, args: dict[str, Any]) -> list[str]:
    if tool_name == "write_file":
        path = args.get("path")
        return [str(path)] if path else []
    if tool_name in {"patch", "apply_patch"}:
        mode = args.get("mode")
        if mode == "replace" and args.get("path"):
            return [str(args["path"])]
        payload = str(args.get("patch") or "")
        return sorted(set(_PATCH_PATH.findall(payload) + _PATCH_MOVE.findall(payload)))
    return []


def _suggested_scope(relative: str) -> str:
    parent = Path(relative).parent.as_posix()
    return relative if parent in {"", "."} else parent


def _suggested_run_id(session_id: str, task_id: str | None) -> str:
    source = task_id or session_id
    return f"{engine._display_token(source, 32)}-work"


def _repo_active_lease(session_id: str, repo: Path) -> dict[str, Any] | None:
    for lease in engine.list_leases(session_id, states={"ACTIVE"}):
        try:
            if Path(str(lease.get("worktree"))).resolve() == repo.resolve() and not engine._is_expired(lease):
                return lease
        except Exception:
            continue
    return None


def on_pre_tool_call(tool_name: str, args: dict[str, Any], **kwargs):
    session_id = _session_id(kwargs)
    base = args.get("workdir") or Path.cwd()

    paths = _tool_paths(tool_name, args)
    for path in paths:
        located = engine.git_root_for_target(path, base=base)
        if not located:
            continue
        repo, relative = located
        if not session_id:
            return {
                "action": "block",
                "message": "Worktree reconciliation blocked this Git write because the Hermes session ID is unavailable.",
            }
        claim = engine.lease_for_target(session_id, str(repo / relative), state_root=None)
        if claim["kind"] == "claimed":
            continue
        if claim["kind"] == "outside_scope":
            lease = claim["lease"]
            command = engine.shell_extend_command(session_id, lease["run_id"], _suggested_scope(relative))
            return {
                "action": "block",
                "message": (
                    f"Worktree lease does not own {relative}. Run a fresh peer-collision scope extension, then retry:\n{command}"
                ),
            }
        run_id = _suggested_run_id(session_id, str(kwargs.get("task_id") or ""))
        command = engine.shell_open_command(str(repo), session_id, run_id, _suggested_scope(relative))
        return {
            "action": "block",
            "message": (
                "Repository writes require a clean session-owned worktree lease before the first mutation. "
                f"Open the bounded scope, then retry:\n{command}"
            ),
        }

    if tool_name == "terminal":
        command = str(args.get("command") or "")
        if not command or "hermes worktree-gate" in command:
            return None
        if not _EXPLICIT_TERMINAL_MUTATOR.search(command):
            return None
        workdir = Path(str(args.get("workdir") or Path.cwd())).expanduser().resolve()
        located = engine.git_root_for_target(str(workdir), base=Path.cwd())
        if not located:
            return None
        repo, _ = located
        if _BROAD_GIT_MUTATION.search(command):
            return {
                "action": "block",
                "message": (
                    "Worktree gate blocks broad staging/stash/reset/clean operations. "
                    "Use exact claimed paths or the authorized automatic checkpoint."
                ),
            }
        if not session_id or _repo_active_lease(session_id, repo) is None:
            return {
                "action": "block",
                "message": (
                    "This terminal command can mutate a Git worktree, but no active session-owned lease exists. "
                    "Run `hermes worktree-gate open` with bounded --owned-path values first."
                ),
            }
    return None


def on_pre_llm_call(**kwargs):
    session_id = _session_id(kwargs)
    if not session_id:
        return None
    leases = engine.list_leases(session_id)
    relevant = [
        {key: lease.get(key) for key in ("run_id", "state", "worktree", "branch", "owned_paths", "checkpoint_commit", "blocker")}
        for lease in leases
        if lease.get("state") in {"ACTIVE", "BLOCKED_DIRTY"}
    ]
    if not relevant:
        return None
    return {
        "context": (
            "WORKTREE RECONCILIATION (session-owned; metadata only):\n"
            + json.dumps(relevant, separators=(",", ":"))
            + "\nDo not claim completion while ACTIVE/BLOCKED_DIRTY state remains."
        )
    }


def on_pre_verify(coding: bool, attempt: int, changed_paths: list[str], **kwargs):
    if not coding or not changed_paths:
        return None
    session_id = _session_id(kwargs)
    if not session_id:
        return {
            "action": "continue",
            "message": "A coding turn cannot close because worktree reconciliation lacks a session identity.",
        } if attempt < 2 else None

    active = engine.list_leases(session_id, states={"ACTIVE"})
    if not active:
        git_paths = [path for path in changed_paths if engine.git_root_for_target(path, base=Path.cwd())]
        if git_paths and attempt < 2:
            return {
                "action": "continue",
                "message": (
                    "Git files changed without a session-owned worktree lease. Open/reconcile the lease and "
                    "produce a valid closeout before finishing."
                ),
            }
        return None

    results = engine.checkpoint_session(session_id, reason="pre_verify", finalize=False)
    blocked = [result for result in results if not result.get("ok")]
    if blocked and attempt < 3:
        reasons = blocked[0].get("violations") or ["automatic checkpoint blocked"]
        return {
            "action": "continue",
            "message": (
                "Automatic local WIP checkpoint did not pass. Resolve this fail-closed blocker before finishing: "
                + "; ".join(str(item) for item in reasons[:4])
            ),
        }
    return None


def _finalize_session(session_id: str, reason: str) -> None:
    if not session_id:
        return
    try:
        results = engine.checkpoint_session(session_id, reason=reason, finalize=True)
        for result in results:
            if not result.get("ok"):
                logger.error("worktree checkpoint blocked session=%s receipt=%s", session_id, result.get("receipt"))
            else:
                logger.info("worktree checkpoint session=%s state=%s commit=%s", session_id, result.get("state"), result.get("commit"))
    except Exception:
        logger.exception("worktree reconciliation finalizer failed for session=%s", session_id)


def on_session_end(**kwargs):
    session_id = _session_id(kwargs)
    reason = str(kwargs.get("turn_exit_reason") or kwargs.get("reason") or "session_end")
    if kwargs.get("interrupted"):
        reason = f"interrupted-{reason}"
    elif kwargs.get("failed"):
        reason = f"failed-{reason}"
    _finalize_session(session_id, reason)


def on_subagent_stop(**kwargs):
    child_session_id = str(kwargs.get("child_session_id") or "").strip()
    child_status = str(kwargs.get("child_status") or "subagent_stop")
    _finalize_session(child_session_id, f"subagent-{child_status}")


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("pre_verify", on_pre_verify)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("subagent_stop", on_subagent_stop)
    ctx.register_cli_command(
        name="worktree-gate",
        help="Open, inspect, extend, and checkpoint session-owned Git worktrees",
        setup_fn=register_cli,
        handler_fn=worktree_gate_command,
        description="Fail-closed worktree lease and automatic local WIP checkpoint control",
    )
