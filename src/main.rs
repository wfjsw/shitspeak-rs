use clap::Parser;

fn main() {
    #[cfg(all(target_os = "linux", feature = "memory-profile"))]
    let _memory_profile = shitspeak_rs::start_memory_profile().unwrap_or_else(|error| {
        eprintln!("error starting memory profile: {error}");
        std::process::exit(1);
    });
    let worker_threads = shitspeak_runtime::runtime_workers::runtime_worker_allocation().main();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("main-runtime-worker")
        .enable_all()
        .build()
        .unwrap_or_else(|error| {
            eprintln!("error: failed to build main runtime: {error}");
            std::process::exit(1);
        });
    runtime.block_on(run());
}

async fn run() {
    let args = shitspeak_rs::cli::Args::parse();

    #[cfg(feature = "web")]
    let extensions = shitspeak_web::server_extensions();

    #[cfg(not(feature = "web"))]
    let extensions = shitspeak_runtime::server::ServerExtensions::default();

    if let Err(e) = shitspeak_runtime::ServerBuilder::new()
        .with_extension(extensions)
        .with_config_path(args.config)
        .run()
        .await
    {
        eprintln!("error: {e}");
        shitspeak_runtime::logging::flush();
        std::process::exit(1);
    }
}
