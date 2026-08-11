use clap::Parser;

#[tokio::main]
async fn main() {
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
