use clap::Parser;

use crate::{commands::Commands, config::Config};

#[derive(Debug, Parser)]
#[command(name = "trusty", about = "CLI for interacting with the Trustify API")]
#[command(version)]
pub struct Cli {
    #[command(flatten)]
    pub config: Config,

    #[command(subcommand)]
    pub command: Commands,
}
