# Channel deletion

New channel removals commit one `DeleteChannel` operation with no `nonce`.
Its position in the strict log determines the subtree removed on every replica.
There is no pending join gate, timeout cancellation, or second deletion proposal.

## Ordering and local cleanup

The channel repository syncs the deletion record before publishing the tree
change. Removing the subtree also removes its external links and invalidates
its ACL caches. An operation admitted earlier is checked against the tree at
its final log position: a late child creation, reparent, or link cannot refer to
a channel already removed by an earlier deletion.

After the durable change, each node relocates its own occupants. The deleted
subtree's parent is the first fallback; existing forced-move permission and
default-channel rules choose an enterable destination. Listener references and
cached listener subscriptions are cleaned up locally. Client projection emits
moves and listener removals before channel removal, using retained deletion
context even if projection runs after the tree change.

A shared check at local client transaction commit prevents an earlier validated
join or listener addition from restoring a deleted channel reference. The check
runs with the channel read lock and the client write lock. Deletion either
precedes that check or is followed by local occupant repair.

## Client view and owner convergence

Before sending `ChannelRemove`, each connection moves every known occupant out
of the removed subtree or sends `UserRemove` if that session has already left.
This applies to ordinary deletion, installed snapshots, log-gap snapshots, and
visibility configuration reloads. The socket shadow supplies the occupant list,
so a delayed owner update or queued disconnect cannot leave a visible occupant
behind when the channel disappears.

Projection prefers an already-valid owner location. Otherwise it records a
temporary location in that connection's shadow without changing remote owner
state. Initial user snapshots and delayed updates also replace missing or
pending-delete destinations before sending them. A subsequent owner update,
including a channel-less update, reconciles a temporary location once the
owner's destination is valid. Client-log catch-up and snapshot replay use the
same projection path. Convergence requires owner replication to resume; a
permanent partition cannot establish the owner's final location.

These viewer-local moves add no strict channel WAL operations.

## Temporary channels

The reaper checks all known local and remote occupants before submitting a
deletion. Once committed, deletion is irrevocable. Users who join during the
proposal, including occupants learned late from another node, are relocated.
The operation does not promise an atomic cluster-wide emptiness check.

## Persistence and compatibility

WAL replay and channel snapshots preserve the completed tree change. Strict
terminal journals retain delivery identity across reconnects and restarts.
Cleanup needs no replicated completion record. Local sessions are not persisted;
new sessions resolve saved channel references against the recovered tree.

Historical `MarkPendingDelete`, `CancelPendingDelete`, and nonce-bearing
`DeleteChannel` records remain readable. A nonce-bearing delete still applies
only to a matching pending marker, so replay preserves historical cancellation.
The legacy watchdog completes abandoned markers with an ordered, nonce-checked
delete instead of cancelling them. Those compatibility completions can create
additional records; new deletion requests never enter this path.

The absent-nonce operation is a channel schema change. Upgrade all channel
replicas together before issuing new deletions. Older binaries require a nonce
and cannot replay these new records; downgrade after new writes is unsupported.
The underlying strict transport/recovery protocol is unchanged.

## Regression and hostile tests

`shitspeak-state` tests cover one-record deletion, WAL sync failure, missing
channels, stale creates, historical cancellation, and delivery deduplication
across snapshot/restart and channel-ID reuse. Runtime tests cover delayed client
transactions, occupant fallback, listener cleanup, dropped commits, duplicated
and reordered strict frames, and catch-up after an offline node restarts.

The ignored `strict_live_abandoned_delete_eventually_finishes_without_cancellation`
test boots six captured production repositories and terminal journals on local
addresses. Set `SHITSPEAK_DELETE_STATE_ROOT` to a directory containing `wz`, `eu`,
`sjc`, `dfw`, `jnb`, and `syd`. Each subdirectory contains
`channels.snapshot.json`, `channels.wal.jsonl`, and `terminal-channels.sqlite3`.
Fixtures remain local and are not committed.

## Validation run: 2026-09-06

- Captured channel repositories and consistent SQLite terminal images through
  read-only SSH from six production nodes. The baseline local cluster emitted
  cancellations and retained the abandoned channel on nodes 1, 4, and 7.
  The same reproduction passed after the change, including a final rerun.
- All 125 state tests passed. The final focused runtime run passed both the
  delayed-admission regression and the dropped/duplicated/reordered-frame plus
  offline-restart scenario. Formatting and diff checks passed.
- The full runtime run reported 631 passed, two failed, and five ignored. The
  new hostile test hit its original 60-second convergence deadline in that run;
  it passed separately. Its final version records node/version diagnostics,
  allows 180 seconds for recovery, waits for both occupant and listener cleanup,
  and passed the focused rerun. This does not establish the cause of the earlier
  convergence timeout.
- The 500-recipient cross-node voice test passed separately and in the later full
  run. The existing 1,000-client voice matrix failed whole-server delivery both
  in the full run and separately: the isolated run lost 58 of 501 frames for one
  recipient against a budget of six. Its first six routing cases had zero
  missing frames. No baseline comparison establishes whether this load failure
  predates the change, so the full suite is not reported as passing.

## Client projection follow-up validation

Eight deletion-view regressions passed, covering remote occupants, queued user
removal, an owner move arriving before deletion projection, delayed invalid
updates, channel-less reconciliation, initial snapshots, installed snapshots,
filtered views, and configuration reloads. Five failures were reproduced before
the corresponding fixes.

The related runtime batch passed 232 tests with zero failures and one ignored
live-state reproduction. It includes authentication, ACL visibility, channel
movement, listener cleanup, projection/replay parity, and the hostile strict
replication scenario. The ignored reproduction then passed separately against
the same six captured node repositories and terminal journals, with no
cancellations or surviving abandoned channel. Formatting and diff checks passed. The earlier full-suite
voice-load failure above was not rerun in this projection follow-up.

Follow-up logs are under `tmp/deleted-view-*.log`.

Local logs are under `tmp/delete-*.log`; copied live state is under
`tmp/delete-state-20260906`. Production was not modified or deployed.
