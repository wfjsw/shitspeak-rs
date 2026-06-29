#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    shitspeak_runtime::forwarder::run_forwarder().await
}
