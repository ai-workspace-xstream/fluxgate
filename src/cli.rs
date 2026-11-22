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
        /// Skip network connectivity checks (default offline syntax & schema check)
        #[arg(long)]
        offline: bool,
        /// Enforce strict GitOps compliance (reject literal secrets or private keys)
        #[arg(long)]
        strict_gitops: bool,
    },
    /// Run Fluxgate reverse proxy server
    Run {
        #[arg(short, long, default_value = "/etc/fluxgate/Fluxgatefile")]
        config: PathBuf,
    },
    /// Hot-reload running Fluxgate configuration via SIGHUP
    Reload {
        #[arg(long, default_value = "/tmp/fluxgate.pid")]
        pid_file: PathBuf,
    },
    /// Inspect configuration, Vault connectivity, and certificate health
    Doctor {
        #[arg(short, long, default_value = "/etc/fluxgate/Fluxgatefile")]
        config: PathBuf,
    },
    /// Print Fluxgate version
    Version,
}
