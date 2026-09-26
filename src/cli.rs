use clap::{ArgAction, CommandFactory, Parser};

use crate::{commands::Commands, config::Config};

#[derive(Debug, Parser)]
#[command(name = "trusty", about = "CLI for interacting with the Trustify API")]
#[command(version)]
#[command(
    after_help = "Run without a subcommand in a terminal to open the interactive entity menu."
)]
pub struct Cli {
    /// Increase diagnostic logging (-v, -vv, -vvv, -vvvv)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    pub verbosity: u8,

    /// Enable full diagnostic logging
    #[arg(long, global = true)]
    pub debug: bool,

    #[command(flatten)]
    pub config: Config,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

impl Cli {
    pub fn print_help() -> anyhow::Result<()> {
        Self::command().print_help()?;
        println!();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn verbosity_and_debug_flags_are_available_after_subcommands() {
        let cli = Cli::try_parse_from(["trusty", "sbom", "list", "-vvvv", "--debug"])
            .expect("global logging options parse after subcommands");

        assert_eq!(cli.verbosity, 4);
        assert!(cli.debug);
    }

    #[test]
    fn no_subcommand_is_a_valid_invocation() {
        let cli = Cli::try_parse_from(["trusty"]).expect("bare invocation parses");
        assert!(cli.command.is_none());
    }
}
