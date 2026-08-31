use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let worker_threads = shitspeak_runtime::runtime_workers::all_cpu_workers();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("main-runtime-worker")
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = shitspeak_rs::cli::Args::parse();
    shitspeak_runtime::forwarder::run_forwarder(args.config).await
}
