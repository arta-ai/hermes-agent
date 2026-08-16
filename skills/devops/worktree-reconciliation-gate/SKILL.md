---
name: worktree-reconciliation-gate
description: "Prevent ambiguous or abandoned Git dirt during agent coding. Use before any repository write, patch import, delegation, handoff, context boundary, interruption recovery, or completion claim. Opens a clean task-owned worktree, records ownership and peer-path collisions, checkpoints task-owned changes, and permits only clean commit, exact patch handoff, or explicitly blocked dirty closeout."
version: 1.0.0
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [git, worktree, reconciliation, checkpoint, provenance, handoff, closeout, multi-agent]
---

# Worktree Reconciliation Gate

## Core invariant

> No run may report **complete**, **reconciled**, or **ready** while its target worktree contains unexplained dirty paths.

Coding may temporarily dirty an isolated worktree. The prohibited state is **unowned, uncheckpointed, or ambiguously abandoned dirt**.

This skill extends the non-destructive canonical hygiene rule. The automatic interruption/checkpoint mechanism has standing authority to create a local WIP commit when all of these conditions hold:

- isolated, attached, non-canonical task branch;
- exactly one active lease for the worktree across all Hermes sessions;
- exact paths claimed by a session-owned lease before mutation;
- fresh peer-worktree collision check;
- no unknown, peer-owned, client, matter, credential, secret, or blocked binary/document material;
- real `gitleaks --staged` and `git diff --cached --check` pass;
- local checkpoint explicitly marked `Complete: false`.

Automatic checkpoints preserve modifications and additions only. A tracked
deletion fails closed and must be reviewed and committed intentionally under
the current task authority. Every successful automatic checkpoint also gets
an immutable `refs/hermes/checkpoints/.../<commit>` ref. The WIP commit and ref
are preservation evidence, not semantic adoption or package authority.

That automatic checkpoint scope does not limit current-request authority. When the current scoped request includes saving, committing, pushing, merging, tagging, deploying, releasing, promoting, or other named effects, execute them after the relevant target/collision readback rather than adding a redundant blanket prohibition. Unknown and peer-owned work remains preserved.

## Installed gate CLI

The non-destructive gate implementation lives with this skill:

```bash
GATE="$HERMES_HOME/skills/devops/worktree-reconciliation-gate/scripts/worktree_reconciliation_gate.py"

python3 "$GATE" open \
  --repo <task-worktree> \
  --run-id <run-id> \
  --owner <session-or-worker> \
  --owned-path <bounded-prefix> \
  --output <outside-repo>/open.json

python3 "$GATE" audit \
  --open-receipt <outside-repo>/open.json \
  --output <outside-repo>/audit.json

python3 "$GATE" close \
  --open-receipt <outside-repo>/open.json \
  --disposition <committed_clean|no_change|patch_handoff|blocked_dirty> \
  --output <outside-repo>/closeout.json
```

It writes immutable receipts and performs no Git or filesystem cleanup mutations. Verify it with:

```bash
python3 "$HERMES_HOME/skills/devops/worktree-reconciliation-gate/scripts/harness_worktree_reconciliation_gate.py"
```

The enabled Hermes plugin supplies the session lease and authorized mutating checkpoint surface:

```bash
hermes worktree-gate open \
  --repo <clean-task-worktree> \
  --session-id <exact-hermes-session-id> \
  --run-id <unique-run-id> \
  --owned-path <bounded-prefix>

hermes worktree-gate extend \
  --session-id <exact-hermes-session-id> \
  --run-id <unique-run-id> \
  --owned-path <additional-bounded-prefix>

hermes worktree-gate checkpoint \
  --session-id <exact-hermes-session-id> \
  --run-id <unique-run-id> \
  --reason <boundary> \
  --finalize

# Resolve an old BLOCKED_DIRTY lease only through a named durable clean
# successor for the same worktree and live HEAD. The immutable blocker receipt
# remains preserved; the old lease becomes SUPERSEDED_CLEAN.
hermes worktree-gate supersede \
  --session-id <exact-hermes-session-id> \
  --run-id <old-blocked-run-id> \
  --superseded-by <later-clean-run-id> \
  --reason <bounded-recovery-reason>

hermes worktree-gate status --session-id <exact-hermes-session-id>
```

The plugin stores mutable lease pointers and immutable receipts under `$HERMES_HOME/worktree-reconciliation/`, outside source repositories.

## Required lifecycle

Every repository-writing run follows this state machine:

```text
UNREGISTERED
  -> OPEN_CLEAN | OPEN_ADOPTED_DIRTY
  -> ACTIVE_OWNED
  -> CHECKPOINTED_WIP | CHECKPOINT_RETRY_REQUIRED
  -> REVIEWABLE
  -> COMMITTED_CLEAN | PATCH_HANDOFF | BLOCKED_DIRTY
```

`COMPLETE` is allowed only for `COMMITTED_CLEAN` or a verified `NO_CHANGE` closeout. `CHECKPOINTED_WIP` is durable and clean but explicitly incomplete. `PATCH_HANDOFF` is preserved and resumable, but not integrated. `BLOCKED_DIRTY` is visible failure/parking, never completion.

## 1. OPEN — before the first write

1. Resolve the exact Git root, branch, `HEAD`, upstream, worktree path, and common Git directory.
2. Run the canonical read-only guard from the governing workspace when available:

```bash
python3 scripts/worktree_hygiene_guard.py preflight \
  --repo <task-worktree> \
  --mode task-worktree \
  --task-token <run-id> \
  --output <outside-repo>/preflight.json
```

3. Require a non-main, task-owned worktree created from a recorded commit.
4. Require a clean baseline. If dirt already exists, stop unless an explicit adoption manifest inventories every dirty path, its hash, provenance class, owner, and intended disposition.
5. Record an immutable open receipt outside the repository containing:
   - run ID and owner/session
   - worktree, branch, starting `HEAD`, upstream
   - starting status bytes and SHA-256
   - every baseline dirty path, including untracked files
   - exact owned path prefixes
   - peer-worktree collision result
6. Scan all registered peer worktrees. If any peer dirty path overlaps the requested ownership scope, stop before writing.

## 2. WORK — while editing

- Write only inside the claimed path set.
- After mutations, compare the live dirty path set with the claim. A new path outside the claim is a collision and stops further edits.
- Never import directly from an uncheckpointed dirty peer lane. The source lane must first produce an exact commit or a full patch handoff that includes tracked binary diff **and** untracked-file hashes/content.
- Never use broad `git add -A`, unscoped stash, `git reset`, `git clean`, or checkout to make status look clean.
- Preserve unknown and peer-owned work. Do not absorb it into the task commit.
- Checkpoint before delegation handoff, context compression, long autonomous continuation, or expected tool-budget exhaustion.

## 3. CHECKPOINT

Authorized default checkpoint in this installation:

- local WIP commit on the isolated task branch;
- explicitly stage only the live leased dirty paths (`git add -A -- <exact paths>`), including modifications and untracked additions but never a broad repository add;
- refuse every tracked deletion in the automatic path; intentional removals require an explicit reviewed commit;
- reject prohibited filename/file classes and escaping symlinks, then run real `gitleaks --staged` before committing;
- require the staged change-kind manifest to equal the committed change-kind manifest exactly;
- create an immutable `refs/hermes/checkpoints/.../<commit>` preservation ref;
- never push, merge, tag, or promote the WIP commit automatically;
- use the fixed local checkpoint identity `Hermes Worktree Gate <checkpoint@local.invalid>`;
- record tests as un-attested unless a separate test receipt proves them;
- require an empty final `git status --porcelain` readback.

Suggested subject:

```text
wip(<run-id>): checkpoint <n>
```

Without commit authority, create a content-addressed patch handoff outside the repository. It must contain the binary tracked diff, all untracked files or their approved archival representation, path manifest, hashes, modes, base `HEAD`, tests, owner, and next action. Do not claim this makes the worktree clean.

## 4. RECONCILE — before stopping

Classify every current dirty path as exactly one of:

- `authored_owned`
- `adopted_baseline`
- `generated`
- `foreign_peer`
- `unknown`

Then run relevant tests, `git diff --check`, path-overlap checks, and final status readback. Untracked production code is a high-severity closeout failure until committed or included in a verified handoff.

## 5. CLOSE — exactly one disposition

### `CHECKPOINTED_WIP`

Requires:
- all changed paths were preclaimed and collision-free;
- sensitive-file policy, `gitleaks --staged`, and `git diff --cached --check` passed;
- an actual local commit exists on the isolated task branch;
- final Git status is empty;
- receipt says `complete=false` and records tests as passed, failed, or not attested.

May be reported checkpointed/preserved and clean, never complete, reviewed, integrated, or product-GREEN.

### `COMMITTED_CLEAN`

Requires:
- task-owned branch;
- explicit commit authority;
- only claimed/adopted paths in the commit;
- required checks recorded;
- `git status --porcelain` empty after commit;
- ending commit hash and closeout receipt.

May be reported complete, subject to product/runtime acceptance gates.

### `PATCH_HANDOFF`

Requires:
- exact base `HEAD`;
- content-addressed artifact covering tracked and untracked work;
- path-level manifest and tests;
- owner and intended integrator.

May be reported preserved/parked, not complete or integrated.

### `BLOCKED_DIRTY`

Requires:
- exact current status and hashes;
- path classifications;
- blocker, owner, next action, and alert destination;
- no cleanup or promotion claim.

This is the mandatory emergency disposition when interruption occurs and no authorized checkpoint can be made.

## Mechanical enforcement

The enabled `worktree-reconciliation` plugin currently registers:

- `pre_tool_call`: block repository writes without a valid open receipt/lease; block paths outside the claim.
- lease open: enforce one active lease per worktree under a worktree-scoped lock; later scopes extend that lease instead of opening siblings.
- `pre_llm_call`: inject only active/blocked lease metadata for the owning session.
- `pre_verify`: create the exact-path local WIP checkpoint on a normal coding boundary, or keep the turn running on a fail-closed blocker.
- `on_session_end`: independently checkpoint on success, error, iteration limit, or interruption; unresolved failures close `BLOCKED_DIRTY`.
- `subagent_stop`: checkpoint leases owned by the stopping child session.

`pre_verify` alone is insufficient because it does not cover every interrupted exit. `on_session_end` is required for the tool-limit failure class.

Known enforcement boundary: direct `write_file`/`patch` calls and explicit terminal Git/file mutators are intercepted before mutation. An opaque arbitrary program launched through `terminal` may write files without declaring that behavior; final status classification and checkpoint closeout still fail closed on any unclaimed path. A future `post_tool_call` inventory and orphan sweeper remain defense-in-depth, not claims of current activation.

## Closeout receipt

Use the machine-checkable contract in `references/closeout-receipt.md`.

## Stop rules

Stop and report `BLOCKED_DIRTY` rather than guessing when:

- exact starting state was not recorded;
- dirty baseline lacks an adoption manifest;
- a peer-path collision exists;
- current dirt escapes the claimed path set;
- untracked files are omitted from the preservation artifact;
- the standing checkpoint authority conditions do not apply;
- sensitive/restricted content might be captured;
- final status readback disagrees with the claimed disposition.
