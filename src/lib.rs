pub use shitspeak_runtime::*;

// The main and S2S runtimes otherwise contend on musl's shared malloc lock.
#[cfg(all(
    target_os = "linux",
    target_env = "musl",
    not(feature = "memory-profile")
))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(target_os = "linux", feature = "memory-profile"))]
#[global_allocator]
static ALLOCATOR: shitspeak_memory_profile::ProfiledAllocator<shitspeak_memory_profile::MiMalloc> =
    shitspeak_memory_profile::ProfiledAllocator::new(shitspeak_memory_profile::MiMalloc);

#[cfg(all(target_os = "linux", feature = "memory-profile"))]
pub fn start_memory_profile() -> std::io::Result<Option<shitspeak_memory_profile::Observation>> {
    shitspeak_memory_profile::start_from_env(&ALLOCATOR)
}

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
