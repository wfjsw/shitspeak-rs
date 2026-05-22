# Voice Remaining Performance Report - 2026-05-18

Created repo-root report `voice_remaining_perf_wins.md` covering remaining meaningful voice-path performance wins after UDP batching, OCB2 encryption copy reduction, checksum precompute, and Rayon threshold tuning.

Report contents:
- Current measured baseline for encode/decode/encrypt/decrypt/fanout/dispatch.
- Ranked remaining wins:
  1. Add production-shape `DatagramBatch` fanout benchmarks.
  2. Reduce UDP receive decrypt allocation/zero-fill with reusable scratch or `decrypt_into`.
  3. Investigate OCB2 decrypt copy reduction.
  4. Avoid zero-filling send batch destination slices only if measured visible.
  5. Tune large-fanout Rayon work partitioning.
  6. Profile live UDP send syscall cost on Linux.
- Low-value/not recommended items: removing `Box<dyn CryptoMode>`, more encode tuning, borrowed packets across async channels, avoiding per-recipient encryption under current protocol.
- Recommended order and verification checklist.

No runtime code changes were made for this report turn; existing worktree still includes prior voice routing/DatagramBatch/OCB2 changes.