pub use shitspeak_runtime::*;

// The main and S2S runtimes otherwise contend on musl's shared malloc lock.
#[cfg(all(target_os = "linux", target_env = "musl"))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod cli {
    use std::path::PathBuf;

    use clap::Parser;

    #[derive(Debug, Parser)]
    #[command(author, version, about)]
    pub struct Args {
        /// Path to the TOML configuration file.
        #[arg(short = 'c', long, value_name = "PATH", default_value = "config.toml")]
        pub config: PathBuf,
    }
}
