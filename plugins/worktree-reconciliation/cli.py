"""CLI surface for the worktree reconciliation plugin."""
from __future__ import annotations

import argparse
import json

from . import engine


def register_cli(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="worktree_gate_action")

    open_parser = commands.add_parser("open", help="Open a clean session-owned worktree lease")
    open_parser.add_argument("--repo", required=True)
    open_parser.add_argument("--session-id", required=True)
    open_parser.add_argument("--run-id", required=True)
    open_parser.add_argument("--owner", default="")
    open_parser.add_argument("--owned-path", action="append", required=True)
    open_parser.add_argument("--state-root", default="")

    extend_parser = commands.add_parser("extend", help="Extend an active lease after a fresh collision check")
    extend_parser.add_argument("--session-id", required=True)
    extend_parser.add_argument("--run-id", required=True)
    extend_parser.add_argument("--owned-path", action="append", required=True)
    extend_parser.add_argument("--state-root", default="")

    checkpoint_parser = commands.add_parser("checkpoint", help="Create an exact-path local WIP checkpoint")
    checkpoint_parser.add_argument("--session-id", required=True)
    checkpoint_parser.add_argument("--run-id", required=True)
    checkpoint_parser.add_argument("--reason", default="manual")
    checkpoint_parser.add_argument("--finalize", action="store_true")
    checkpoint_parser.add_argument("--state-root", default="")

    status_parser = commands.add_parser("status", help="Read lease/checkpoint state")
    status_parser.add_argument("--session-id", default="")
    status_parser.add_argument("--state-root", default="")

    parser.set_defaults(func=worktree_gate_command)


def worktree_gate_command(args: argparse.Namespace) -> int:
    action = getattr(args, "worktree_gate_action", None)
    state_root = getattr(args, "state_root", "") or None
    try:
        if action == "open":
            result = engine.open_lease(
                repo=args.repo,
                session_id=args.session_id,
                run_id=args.run_id,
                owner=args.owner or args.session_id,
                owned_paths=args.owned_path,
                state_root=state_root,
            )
        elif action == "extend":
            result = engine.extend_lease(
                session_id=args.session_id,
                run_id=args.run_id,
                owned_paths=args.owned_path,
                state_root=state_root,
            )
        elif action == "checkpoint":
            result = engine.checkpoint_lease(
                session_id=args.session_id,
                run_id=args.run_id,
                reason=args.reason,
                finalize=bool(args.finalize),
                state_root=state_root,
            )
        elif action == "status":
            result = engine.status_summary(args.session_id or None, state_root=state_root)
        else:
            print("Usage: hermes worktree-gate {open|extend|checkpoint|status}")
            return 2
    except Exception as exc:
        result = {"ok": False, "gate": "Blocked", "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 2
