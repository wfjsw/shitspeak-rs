# Voice dispatch calibration

Run `SHITSPEAK_BENCH_REPORT=1` with the `voice_hotpath` benchmark executable.
The report calls the same calibration implementation as server startup, then
checks the resulting policy against fresh measurements of all partition counts.
No server instance is started.

For a standalone musl executable without the Criterion harness:

```
cross build --release --bin voice_dispatch_bench --target x86_64-unknown-linux-musl
```

Run `voice_dispatch_bench` without arguments. It uses the same allocator and
shared calibration/report functions as `voice_hotpath`.

For each payload class (170 and 768 Opus bytes), calibration fits:

```
S(n)    = a0 + a1*x
R(n, p) = b0 + b1*x + b2*x/p + b3*p + b4*x*log2(p) + b5*p*p/x + b6*x*log2(1+x)/p
x       = n / 1024
```

The seven Rayon terms approximate dispatch overhead, serial work, parallel
encryption, partition overhead, tree merging, partition density, and working-set
growth in encryption cost. Coefficients
are fitted with nonnegative, relative-error least squares and Huber reweighting.
The nonnegative constraints prevent negative costs and negative fragmentation
penalties caused by measurement noise.

At the actual listener count, the policy evaluates every integer partition count
from 2 through the smaller of listener count, available workers, and calibrated
workers. It uses the global minimum of the fitted Rayon surface only when that
minimum is at least 5% faster than the fitted sequential cost. Thus both the
dispatch decision and partition count can change with fanout. The existing
bounded breakpoint metrics summarize the first transitions; they do not limit
the model's decisions.

Training covers 8, 16, 32, 64, 128, 256, and 512 listeners, then 1024 through
8192 listeners, and measures every available partition count. Validation uses
the non-training geometric midpoints 12, 24, 48, 96, 192, 384, 768, 1536,
3072, and 6144 listeners.
Repeated rounds shuffle candidate order and use medians. Crypto states live
across rounds, as connected clients do, and their construction/destruction is
excluded from both timers. Rayon timing includes `spawn_blocking`, the worker
pool, encryption, merging, and the async join. Output-buffer destruction is
excluded from both paths. Routing, socket I/O, and per-stage telemetry are outside
this encryption calibration.

The diagnostic sweep also exposed unbounded retention in `DatagramBatch`'s
thread-local pool. Cleared batches now retain one arena, and each thread retains
at most eight batches with at most 2048 datagram slots each. Oversized buffers are
released. This applies to both the benchmark and production buffering.

Validation checks independent listener counts against a complete measured
partition sweep, including sequential. If selected latency exceeds the measured
minimum by more than 10%, those samples refine the fit, for at most two rounds.
A noisy holdout no longer disables Rayon for the entire payload class. The
standalone report then performs fresh sweeps and prints selected versus measured
best latency and regret (`selected / best - 1`), making remaining model error
visible. Optimality is with respect to the fitted objective; actual measurements
can differ due to model error and scheduler noise. Predictions beyond 8192
listeners extrapolate the fitted costs.

The report includes per-payload calibration time, total startup calibration
time, and full diagnostic time. Shell timing can additionally include process
creation and exit.
