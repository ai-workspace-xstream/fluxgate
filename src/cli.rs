use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "fluxgate",
    about = "Lightweight HTTP/HTTPS Reverse Proxy powered by Cloudflare Pingora",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Validate Fluxgate configuration file and exit
    Validate {
        #[arg(short, long, default_value = "/etc/fluxgate/Fluxgatefile")]
        config: PathBuf,
    },
    /// Run Fluxgate reverse proxy server
    Run {
        #[arg(short, long, default_value = "/etc/fluxgate/Fluxgatefile")]
        config: PathBuf,
    },
    /// Print Fluxgate version
    Version,
}
