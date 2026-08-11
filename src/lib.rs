pub use shitspeak_runtime::*;

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
