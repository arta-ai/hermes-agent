from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "worktree_reconciliation_plugin",
    PLUGIN_DIR / "__init__.py",
    submodule_search_locations=[str(PLUGIN_DIR)],
)
assert SPEC and SPEC.loader
plugin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plugin
SPEC.loader.exec_module(plugin)
engine = plugin.engine


def run(command: list[str], *, expected: int = 0) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != expected:
        raise AssertionError(
            f"expected {expected}, got {proc.returncode}: {' '.join(command)}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc


def git(repo: Path, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    return run(["git", "-C", str(repo), *args], expected=expected)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_ctx = tempfile.TemporaryDirectory(prefix="worktree-plugin-test-")
        self.temp = Path(self.temp_ctx.name)
        self.repo = self.temp / "repo"
        self.state = self.temp / "state"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.name", "Fixture User")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        write(self.repo / "src" / "app.py", "VALUE = 1\n")
        write(self.repo / "docs" / "readme.md", "baseline\n")
        git(self.repo, "add", "--", "src/app.py", "docs/readme.md")
        git(self.repo, "commit", "-m", "fixture baseline")
        self.base_head = git(self.repo, "rev-parse", "HEAD").stdout.strip()
        engine.DEFAULT_STATE_ROOT = self.state

    def tearDown(self) -> None:
        self.temp_ctx.cleanup()

    def worktree(self, name: str) -> Path:
        path = self.temp / name
        git(self.repo, "worktree", "add", "-b", f"task/{name}", str(path), self.base_head)
        return path


class EngineTests(Fixture):
    def test_exact_path_checkpoint_commits_and_cleans(self) -> None:
        wt = self.worktree("exact")
        opened = engine.open_lease(
            repo=str(wt), session_id="session-exact", run_id="run-exact",
            owned_paths=["src"], state_root=self.state,
        )
        self.assertTrue(opened["ok"])
        write(wt / "src" / "app.py", "VALUE = 2\n")
        write(wt / "src" / "test_app.py", "def test_value():\n    assert True\n")

        result = engine.checkpoint_lease(
            session_id="session-exact", run_id="run-exact", reason="iteration_limit",
            finalize=True, state_root=self.state,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "CHECKPOINTED_WIP")
        self.assertFalse(result["complete"])
        self.assertEqual(git(wt, "status", "--porcelain").stdout, "")
        self.assertNotEqual(git(wt, "rev-parse", "HEAD").stdout.strip(), self.base_head)
        committed = git(wt, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").stdout.splitlines()
        self.assertEqual(committed, ["src/app.py", "src/test_app.py"])
        self.assertEqual(git(wt, "show", "-s", "--format=%ae", "HEAD").stdout.strip(), "checkpoint@local.invalid")
        git(wt, "rev-parse", "@{u}", expected=128)

        _, lease = engine.load_lease("session-exact", "run-exact", state_root=self.state)
        self.assertEqual(lease["state"], "CHECKPOINTED_WIP")
        self.assertEqual(lease["checkpoint_commit"], result["commit"])
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual(receipt["secret_scan"]["status"], "pass")
        self.assertEqual(receipt["diff_check"], "pass")
        self.assertEqual(receipt["remaining_dirty_paths"], [])

    def test_gitleaks_blocks_secret_and_never_commits_it(self) -> None:
        wt = self.worktree("secret")
        engine.open_lease(
            repo=str(wt), session_id="session-secret", run_id="run-secret",
            owned_paths=["src"], state_root=self.state,
        )
        # Runtime-assembled synthetic generic API key. The test source itself
        # does not contain a complete scanner-triggering token.
        fake_secret = "".join(["mJ8kQ2vR7xP4", "nL9cT6wZ3sH5", "bD1fG0yU"])
        write(wt / "src" / "leak.py", f'api_key = "{fake_secret}"\n')

        result = engine.checkpoint_lease(
            session_id="session-secret", run_id="run-secret", reason="session_end",
            finalize=True, state_root=self.state,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "BLOCKED_DIRTY")
        self.assertEqual(git(wt, "rev-parse", "HEAD").stdout.strip(), self.base_head)
        self.assertNotEqual(git(wt, "status", "--porcelain").stdout, "")
        _, lease = engine.load_lease("session-secret", "run-secret", state_root=self.state)
        self.assertEqual(lease["state"], "BLOCKED_DIRTY")
        records = "\n".join(path.read_text(errors="replace") for path in self.state.rglob("*.json"))
        self.assertNotIn(fake_secret, records)
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual(receipt["secret_scan"]["status"], "blocked")

    def test_sensitive_file_class_fails_before_commit(self) -> None:
        wt = self.worktree("sensitive")
        engine.open_lease(
            repo=str(wt), session_id="session-sensitive", run_id="run-sensitive",
            owned_paths=["config"], state_root=self.state,
        )
        write(wt / "config" / ".env", "NOT_A_REAL_SECRET=value\n")
        result = engine.checkpoint_lease(
            session_id="session-sensitive", run_id="run-sensitive", reason="session_end",
            finalize=True, state_root=self.state,
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("sensitive filename" in item for item in result["violations"]))
        self.assertEqual(git(wt, "rev-parse", "HEAD").stdout.strip(), self.base_head)

    def test_peer_collision_blocks_open(self) -> None:
        peer = self.worktree("peer")
        write(peer / "src" / "peer.py", "PEER = True\n")
        target = self.worktree("target")
        result = engine.open_lease(
            repo=str(target), session_id="session-target", run_id="run-target",
            owned_paths=["src"], state_root=self.state,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "OPEN_REJECTED")
        self.assertTrue(any("peer" in item for item in result["violations"]))

    def test_scope_extension_rechecks_and_allows_new_exact_path(self) -> None:
        wt = self.worktree("extend")
        engine.open_lease(
            repo=str(wt), session_id="session-extend", run_id="run-extend",
            owned_paths=["src"], state_root=self.state,
        )
        result = engine.extend_lease(
            session_id="session-extend", run_id="run-extend", owned_paths=["docs"],
            state_root=self.state,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["owned_paths"], ["docs", "src"])
        write(wt / "docs" / "readme.md", "updated\n")
        checkpoint = engine.checkpoint_lease(
            session_id="session-extend", run_id="run-extend", reason="pre_verify",
            finalize=False, state_root=self.state,
        )
        self.assertTrue(checkpoint["ok"])
        self.assertEqual(git(wt, "status", "--porcelain").stdout, "")


class HookTests(Fixture):
    def test_pre_write_blocks_then_allows_claimed_path_and_blocks_escape(self) -> None:
        wt = self.worktree("hooks")
        target = str(wt / "src" / "new.py")
        blocked = plugin.on_pre_tool_call(
            "write_file", {"path": target}, session_id="session-hooks", task_id="task-hooks"
        )
        self.assertEqual(blocked["action"], "block")
        self.assertIn("worktree-gate open", blocked["message"])

        engine.open_lease(
            repo=str(wt), session_id="session-hooks", run_id="task-hooks-work",
            owned_paths=["src"], state_root=self.state,
        )
        allowed = plugin.on_pre_tool_call(
            "write_file", {"path": target}, session_id="session-hooks", task_id="task-hooks"
        )
        self.assertIsNone(allowed)
        outside = plugin.on_pre_tool_call(
            "write_file", {"path": str(wt / "docs" / "new.md")},
            session_id="session-hooks", task_id="task-hooks",
        )
        self.assertEqual(outside["action"], "block")
        self.assertIn("worktree-gate extend", outside["message"])

    def test_pre_verify_creates_real_checkpoint(self) -> None:
        wt = self.worktree("preverify")
        engine.open_lease(
            repo=str(wt), session_id="session-preverify", run_id="run-preverify",
            owned_paths=["src"], state_root=self.state,
        )
        write(wt / "src" / "app.py", "VALUE = 3\n")
        directive = plugin.on_pre_verify(
            coding=True, attempt=0, changed_paths=[str(wt / "src" / "app.py")],
            session_id="session-preverify",
        )
        self.assertIsNone(directive)
        self.assertEqual(git(wt, "status", "--porcelain").stdout, "")
        _, lease = engine.load_lease("session-preverify", "run-preverify", state_root=self.state)
        self.assertEqual(lease["state"], "CHECKPOINTED_WIP")

    def test_session_end_catches_iteration_limit(self) -> None:
        wt = self.worktree("iteration")
        engine.open_lease(
            repo=str(wt), session_id="session-iteration", run_id="run-iteration",
            owned_paths=["src"], state_root=self.state,
        )
        write(wt / "src" / "app.py", "VALUE = 4\n")
        plugin.on_session_end(
            session_id="session-iteration", completed=False, failed=True,
            interrupted=False, turn_exit_reason="iteration_limit",
        )
        self.assertEqual(git(wt, "status", "--porcelain").stdout, "")
        _, lease = engine.load_lease("session-iteration", "run-iteration", state_root=self.state)
        self.assertEqual(lease["state"], "CHECKPOINTED_WIP")
        receipt = json.loads(Path(lease["last_event"]).read_text())
        self.assertIn("iteration_limit", receipt["reason"])

    def test_register_wires_all_enforcement_hooks_and_cli(self) -> None:
        class Context:
            def __init__(self):
                self.hooks = []
                self.cli = []
            def register_hook(self, name, callback):
                self.hooks.append((name, callback))
            def register_cli_command(self, **kwargs):
                self.cli.append(kwargs)

        context = Context()
        plugin.register(context)
        self.assertEqual(
            {name for name, _ in context.hooks},
            {"pre_tool_call", "pre_llm_call", "pre_verify", "on_session_end", "subagent_stop"},
        )
        self.assertEqual(context.cli[0]["name"], "worktree-gate")


if __name__ == "__main__":
    unittest.main()
