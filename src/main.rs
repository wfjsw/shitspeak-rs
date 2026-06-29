#[tokio::main]
async fn main() {
    #[cfg(feature = "web")]
    let extensions = shitspeak_web::server_extensions();

    #[cfg(not(feature = "web"))]
    let extensions = shitspeak_runtime::server::ServerExtensions::default();

    if let Err(e) = shitspeak_runtime::run_server_with_extensions(extensions).await {
        eprintln!("error: {e}");
        shitspeak_runtime::logging::flush();
        std::process::exit(1);
    }
}
