# Worktree reconciliation closeout receipt v1

A receipt is append-only, stored outside the source repository, and hash-bound to its source artifacts. It must not contain secrets, client facts, matter payloads, or raw credentials.

## Required fields

```json
{
  "schema": "loaw.worktree_reconciliation_closeout.v1",
  "run_id": "string",
  "owner": "agent/session/worker identity",
  "opened_at": "RFC3339",
  "closed_at": "RFC3339",
  "worktree": "/absolute/path",
  "common_git_dir": "/absolute/path",
  "branch": "refs/heads/task-branch",
  "upstream": null,
  "starting_head": "40-hex",
  "ending_head": "40-hex",
  "starting_status_sha256": "64-hex",
  "ending_status_sha256": "64-hex",
  "owned_paths": [],
  "adopted_paths": [],
  "generated_paths": [],
  "foreign_paths": [],
  "unknown_paths": [],
  "untracked_paths": [],
  "collision_check": {
    "ok": true,
    "peer_worktrees_checked": [],
    "overlaps": []
  },
  "test_receipts": [],
  "diff_check": "pass | fail | not_run",
  "disposition": "committed_clean | no_change | checkpointed_wip | patch_handoff | blocked_dirty",
  "complete": false,
  "commit_or_patch_sha256": null,
  "secret_scan": {
    "tool": "gitleaks",
    "status": "pass | blocked | not_run",
    "report_sha256": null
  },
  "remaining_dirty_paths": [],
  "blocker": null,
  "next_action": null
}
```

## Validation rules

1. `complete=true` is valid only for `committed_clean` or `no_change`.
2. `committed_clean` and `no_change` require `remaining_dirty_paths=[]` and an empty Git status readback.
3. `committed_clean` requires an ending commit identity and authority receipt.
4. `checkpointed_wip` requires a local commit, exact leased path match, successful secret/diff scans, empty final status, and `complete=false`.
5. `patch_handoff` requires an artifact hash and a manifest covering every current dirty path, including untracked files.
6. `blocked_dirty` requires non-empty `blocker`, `owner`, and `next_action`.
7. Any peer overlap, unknown path, missing untracked content, scan failure, or status/hash mismatch forces `complete=false`.
8. Tests and product/runtime acceptance remain separate proof dimensions; a clean Git tree is not by itself GREEN.
9. Receipt creation never grants reset, clean, stash, delete, push, merge, tag, release, promotion, or deployment authority.
