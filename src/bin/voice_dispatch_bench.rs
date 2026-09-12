//! Standalone entry point for the shared startup calibration and validation.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let started = std::time::Instant::now();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let report = runtime
        .block_on(shitspeak_rs::voice::voice_dispatch_benchmark_report())
        .map_err(std::io::Error::other)?;
    print!("{report}");
    println!(
        "report_process_elapsed_s={:.3}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
