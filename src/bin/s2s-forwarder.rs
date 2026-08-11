use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = shitspeak_rs::cli::Args::parse();
    shitspeak_runtime::forwarder::run_forwarder(args.config).await
}
