//! Compare direct fanout to per-recipient queues against a shared broadcast
//! channel with one subscriber per recipient.
//!
//! These benches isolate channel mechanics from protocol projection and socket
//! writes. They are meant to answer whether the fanout primitive itself is a
//! bottleneck under bursts like "150 clients observe 150 user moves".

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::runtime::Runtime;
use tokio::sync::{broadcast, mpsc};

const BURST: usize = 150;
const QUEUE_CAPACITY: usize = 1024;

#[derive(Clone, Debug)]
struct BenchMessage {
    version: u64,
    payload: [u8; 64],
}

fn make_message(version: u64) -> BenchMessage {
    BenchMessage {
        version,
        payload: [0xAB; 64],
    }
}

fn recipient_counts() -> [usize; 5] {
    [1, 16, 64, 150, 512]
}

async fn bench_mpsc_fanout_once(recipients: usize, burst: usize) -> u64 {
    let mut senders = Vec::with_capacity(recipients);
    let mut receivers = Vec::with_capacity(recipients);
    for _ in 0..recipients {
        let (tx, rx) = mpsc::channel::<BenchMessage>(QUEUE_CAPACITY);
        senders.push(tx);
        receivers.push(rx);
    }

    for version in 0..burst as u64 {
        let msg = make_message(version);
        for tx in &senders {
            tx.send(msg.clone()).await.expect("recipient queue open");
        }
    }

    let mut checksum = 0u64;
    for rx in &mut receivers {
        for _ in 0..burst {
            let msg = rx.recv().await.expect("message");
            checksum ^= msg.version;
            checksum = checksum.wrapping_add(u64::from(msg.payload[0]));
        }
    }
    checksum
}

async fn bench_broadcast_once(recipients: usize, burst: usize) -> u64 {
    let (tx, _) = broadcast::channel::<BenchMessage>(QUEUE_CAPACITY);
    let mut receivers = (0..recipients).map(|_| tx.subscribe()).collect::<Vec<_>>();

    for version in 0..burst as u64 {
        tx.send(make_message(version)).expect("subscribers");
    }

    let mut checksum = 0u64;
    for rx in &mut receivers {
        for _ in 0..burst {
            let msg = rx.recv().await.expect("message");
            checksum ^= msg.version;
            checksum = checksum.wrapping_add(u64::from(msg.payload[0]));
        }
    }
    checksum
}

async fn bench_broadcast_drain_limited_once(
    recipients: usize,
    burst: usize,
    drain_limit: usize,
) -> u64 {
    let (tx, _) = broadcast::channel::<BenchMessage>(QUEUE_CAPACITY);
    let mut receivers = (0..recipients).map(|_| tx.subscribe()).collect::<Vec<_>>();

    for version in 0..burst as u64 {
        tx.send(make_message(version)).expect("subscribers");
    }

    let mut checksum = 0u64;
    for rx in &mut receivers {
        let mut received = 0usize;
        while received < burst {
            let first = rx.recv().await.expect("message");
            checksum ^= first.version;
            checksum = checksum.wrapping_add(u64::from(first.payload[0]));
            received += 1;

            for _ in 1..drain_limit {
                if received >= burst {
                    break;
                }
                match rx.try_recv() {
                    Ok(msg) => {
                        checksum ^= msg.version;
                        checksum = checksum.wrapping_add(u64::from(msg.payload[0]));
                        received += 1;
                    }
                    Err(broadcast::error::TryRecvError::Empty) => break,
                    Err(err) => panic!("unexpected broadcast drain error: {err:?}"),
                }
            }
        }
    }
    checksum
}

fn bench_fanout_vs_broadcast(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("fanout_vs_broadcast");
    group.measurement_time(Duration::from_secs(5));

    for recipients in recipient_counts() {
        group.throughput(Throughput::Elements((recipients * BURST) as u64));

        group.bench_with_input(
            BenchmarkId::new("mpsc_direct_fanout", recipients),
            &recipients,
            |b, &recipients| {
                b.iter(|| {
                    black_box(rt.block_on(bench_mpsc_fanout_once(
                        black_box(recipients),
                        black_box(BURST),
                    )))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("broadcast_recv_each", recipients),
            &recipients,
            |b, &recipients| {
                b.iter(|| {
                    black_box(rt.block_on(bench_broadcast_once(
                        black_box(recipients),
                        black_box(BURST),
                    )))
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("broadcast_drain_64", recipients),
            &recipients,
            |b, &recipients| {
                b.iter(|| {
                    black_box(rt.block_on(bench_broadcast_drain_limited_once(
                        black_box(recipients),
                        black_box(BURST),
                        black_box(64),
                    )))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_fanout_vs_broadcast);
criterion_main!(benches);
