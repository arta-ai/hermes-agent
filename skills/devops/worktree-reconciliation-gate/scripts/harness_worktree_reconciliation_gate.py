#!/usr/bin/env python3
"""End-to-end harness for worktree_reconciliation_gate.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).with_name("worktree_reconciliation_gate.py")


class HarnessFailure(AssertionError):
    pass


def run(command: list[str], cwd: Path | None = None, expected: int = 0) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != expected:
        raise HarnessFailure(
            f"expected exit {expected}, got {proc.returncode}: {' '.join(command)}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc


def git(repo: Path, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    return run(["git", "-C", str(repo), *args], expected=expected)


def invoke(args: list[str], expected: int) -> dict[str, Any]:
    proc = run([sys.executable, str(SCRIPT), *args], expected=expected)
    stream = proc.stdout if proc.stdout.strip() else proc.stderr
    return json.loads(stream.strip().splitlines()[-1])


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def main() -> int:
    assertions = 0
    scenarios: list[str] = []

    def check(condition: bool, message: str) -> None:
        nonlocal assertions
        assertions += 1
        if not condition:
            raise HarnessFailure(message)

    with tempfile.TemporaryDirectory(prefix="worktree-reconciliation-harness-") as temp_value:
        temp = Path(temp_value)
        canonical = temp / "repo"
        receipts = temp / "receipts"
        receipts.mkdir()
        canonical.mkdir()
        git(canonical, "init", "-b", "main")
        git(canonical, "config", "user.name", "Reconciliation Harness")
        git(canonical, "config", "user.email", "harness@example.invalid")
        write(canonical / "README.md", "fixture\n")
        write(canonical / "src" / "app.py", "VALUE = 1\n")
        git(canonical, "add", "--", "README.md", "src/app.py")
        git(canonical, "commit", "-m", "fixture baseline")

        # Scenario 1: clean open -> owned dirt -> dirty completion rejected -> exact commit closes clean.
        task_one = temp / "task-one"
        git(canonical, "worktree", "add", "-b", "task/one", str(task_one), "HEAD")
        open_one = receipts / "task-one-open.json"
        summary = invoke([
            "open", "--repo", str(task_one), "--run-id", "task-one", "--owner", "harness",
            "--owned-path", "src", "--output", str(open_one),
        ], expected=0)
        check(summary["state"] == "OPEN_CLEAN", "clean task worktree did not open")
        check(load(open_one)["starting_status"]["dirty_path_count"] == 0, "open status was not clean")

        write(task_one / "src" / "app.py", "VALUE = 2\n")
        write(task_one / "src" / "test_app.py", "def test_value():\n    assert True\n")
        audit_one = receipts / "task-one-audit.json"
        summary = invoke(["audit", "--open-receipt", str(open_one), "--output", str(audit_one)], expected=0)
        check(summary["state"] == "ACTIVE_OWNED", "owned dirt did not classify ACTIVE_OWNED")
        audit_payload = load(audit_one)
        check(audit_payload["classifications"]["foreign_unknown"] == [], "owned dirt was misclassified foreign")
        check(audit_payload["classifications"]["untracked"] == ["src/test_app.py"], "untracked source was omitted")

        rejected_close = receipts / "task-one-rejected-close.json"
        summary = invoke([
            "close", "--open-receipt", str(open_one), "--disposition", "committed_clean",
            "--output", str(rejected_close),
        ], expected=2)
        check(summary["complete"] is False and summary["state"] == "CLOSE_REJECTED", "dirty completion was not rejected")

        git(task_one, "add", "--", "src/app.py", "src/test_app.py")
        git(task_one, "commit", "-m", "test: checkpoint owned fixture changes")
        authority = receipts / "task-one-authority.json"
        write(authority, '{"authority":"harness-only"}\n')
        clean_close = receipts / "task-one-clean-close.json"
        summary = invoke([
            "close", "--open-receipt", str(open_one), "--disposition", "committed_clean",
            "--authority-receipt", str(authority), "--diff-check", "pass",
            "--output", str(clean_close),
        ], expected=0)
        clean_payload = load(clean_close)
        check(summary["complete"] is True and summary["state"] == "COMMITTED_CLEAN", "committed clean close failed")
        check(clean_payload["remaining_dirty_paths"] == [], "clean close retained dirty paths")
        check(clean_payload["commit_paths"] == ["src/app.py", "src/test_app.py"], "commit path scope was not recorded")
        scenarios.append("clean_open_owned_audit_committed_clean")

        # Scenario 2: interruption can close only as explicitly blocked, never complete.
        task_two = temp / "task-two"
        git(canonical, "worktree", "add", "-b", "task/two", str(task_two), "HEAD")
        open_two = receipts / "task-two-open.json"
        invoke([
            "open", "--repo", str(task_two), "--run-id", "task-two", "--owner", "harness",
            "--owned-path", "docs", "--output", str(open_two),
        ], expected=0)
        write(task_two / "docs" / "draft.md", "unfinished\n")
        blocked_close = receipts / "task-two-blocked-close.json"
        summary = invoke([
            "close", "--open-receipt", str(open_two), "--disposition", "blocked_dirty",
            "--blocker", "simulated iteration limit", "--next-action", "resume task-two and checkpoint",
            "--output", str(blocked_close),
        ], expected=0)
        check(summary["state"] == "BLOCKED_DIRTY" and summary["complete"] is False, "blocked dirty was misreported complete")
        check(load(blocked_close)["remaining_dirty_paths"] == ["docs/draft.md"], "blocked close omitted dirty path")
        scenarios.append("interrupted_blocked_dirty")

        # Scenario 3: a dirty peer lane blocks an overlapping ownership claim before writing.
        write(task_two / "src" / "collision.py", "PEER = True\n")
        task_three = temp / "task-three"
        git(canonical, "worktree", "add", "-b", "task/three", str(task_three), "HEAD")
        open_three = receipts / "task-three-open.json"
        summary = invoke([
            "open", "--repo", str(task_three), "--run-id", "task-three", "--owner", "harness",
            "--owned-path", "src", "--output", str(open_three),
        ], expected=2)
        collision_payload = load(open_three)
        check(summary["state"] == "OPEN_REJECTED", "peer collision did not reject open")
        check(collision_payload["collision_check"]["overlaps"], "peer collision receipt omitted overlap")
        scenarios.append("peer_collision_prewrite_block")

        # Scenario 4: pre-existing dirt cannot be silently adopted.
        task_four = temp / "task-four"
        git(canonical, "worktree", "add", "-b", "task/four", str(task_four), "HEAD")
        write(task_four / "misc" / "preexisting.txt", "unknown\n")
        open_four = receipts / "task-four-open.json"
        summary = invoke([
            "open", "--repo", str(task_four), "--run-id", "task-four", "--owner", "harness",
            "--owned-path", "misc", "--output", str(open_four),
        ], expected=2)
        check(summary["state"] == "OPEN_REJECTED", "dirty baseline opened without adoption manifest")
        check(
            any("adoption manifest" in item for item in load(open_four)["violations"]),
            "dirty baseline rejection omitted reason",
        )
        scenarios.append("dirty_baseline_requires_adoption")

        # Scenario 5: exact patch handoff must cover tracked and untracked paths; it remains incomplete.
        task_five = temp / "task-five"
        git(canonical, "worktree", "add", "-b", "task/five", str(task_five), "HEAD")
        open_five = receipts / "task-five-open.json"
        invoke([
            "open", "--repo", str(task_five), "--run-id", "task-five", "--owner", "harness",
            "--owned-path", "assets", "--output", str(open_five),
        ], expected=0)
        write(task_five / "assets" / "tracked.txt", "handoff\n")
        write(task_five / "assets" / "untracked.txt", "also handoff\n")
        artifact = receipts / "task-five.patch.bin"
        write(artifact, "synthetic content-addressed fixture\n")
        artifact_hash = __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()
        bad_manifest = receipts / "task-five-bad-manifest.json"
        write(bad_manifest, json.dumps({
            "schema": "loaw.worktree_patch_handoff.v1",
            "base_head": load(open_five)["identity"]["head"],
            "artifact_sha256": artifact_hash,
            "paths": ["assets/tracked.txt"],
            "untracked_paths": ["assets/tracked.txt"],
        }) + "\n")
        rejected_handoff = receipts / "task-five-rejected-handoff.json"
        invoke([
            "close", "--open-receipt", str(open_five), "--disposition", "patch_handoff",
            "--artifact", str(artifact), "--handoff-manifest", str(bad_manifest),
            "--output", str(rejected_handoff),
        ], expected=2)
        check(load(rejected_handoff)["complete"] is False, "incomplete handoff was accepted as complete")

        live_paths = [row["path"] for row in load(rejected_handoff)["current_status"]["rows"]]
        live_untracked = [row["path"] for row in load(rejected_handoff)["current_status"]["rows"] if row["untracked"]]
        good_manifest = receipts / "task-five-good-manifest.json"
        write(good_manifest, json.dumps({
            "schema": "loaw.worktree_patch_handoff.v1",
            "base_head": load(open_five)["identity"]["head"],
            "artifact_sha256": artifact_hash,
            "paths": live_paths,
            "untracked_paths": live_untracked,
        }) + "\n")
        accepted_handoff = receipts / "task-five-accepted-handoff.json"
        summary = invoke([
            "close", "--open-receipt", str(open_five), "--disposition", "patch_handoff",
            "--artifact", str(artifact), "--handoff-manifest", str(good_manifest),
            "--output", str(accepted_handoff),
        ], expected=0)
        check(summary["state"] == "PATCH_HANDOFF" and summary["complete"] is False, "patch handoff semantics are wrong")
        scenarios.append("exact_patch_handoff_incomplete_by_design")

        # Scenario 6: a genuine no-change task can close complete and clean.
        task_six = temp / "task-six"
        git(canonical, "worktree", "add", "-b", "task/six", str(task_six), "HEAD")
        open_six = receipts / "task-six-open.json"
        invoke([
            "open", "--repo", str(task_six), "--run-id", "task-six", "--owner", "harness",
            "--owned-path", "noop", "--output", str(open_six),
        ], expected=0)
        close_six = receipts / "task-six-close.json"
        summary = invoke([
            "close", "--open-receipt", str(open_six), "--disposition", "no_change",
            "--output", str(close_six),
        ], expected=0)
        check(summary["state"] == "NO_CHANGE" and summary["complete"] is True, "no-change close failed")
        scenarios.append("no_change_clean_close")

    result = {
        "schema": "loaw.worktree_reconciliation_harness.v1",
        "ok": True,
        "gate": "Pass",
        "scenario_count": len(scenarios),
        "assertion_count": assertions,
        "scenarios": scenarios,
        "script": str(SCRIPT),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({
            "schema": "loaw.worktree_reconciliation_harness.v1",
            "ok": False,
            "gate": "Blocked",
            "error": f"{type(exc).__name__}: {exc}",
        }, indent=2, sort_keys=True))
        raise
