mod sbom;

use clap::Subcommand;

use crate::api::ApiClient;

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Browse and inspect SBOMs
    Sbom {
        #[command(subcommand)]
        command: sbom::SbomCommands,
    },
}

impl Commands {
    pub async fn run(&self, client: &ApiClient) -> anyhow::Result<()> {
        match self {
            Self::Sbom { command } => command.run(client).await,
        }
    }
}
