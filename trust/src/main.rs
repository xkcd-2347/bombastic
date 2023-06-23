use std::process::{ExitCode, Termination};

use clap::Parser;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Vexination(vexination::Command),
    #[command(subcommand)]
    Bombastic(bombastic::Command),
    #[command(subcommand)]
    Spog(spog::Command),
    Exporter(exporter::Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = trustification_version::version(),
    about = "Trustification",
    long_about = Some("Trustification is a collection of services that allow you to store bill of materials (SBOM), vulnerability information (VEX) for your organization and use that information to learn impact of vulnerabilities and dependency changes."),
)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    async fn run(self) -> ExitCode {
        match self.run_command().await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("Error: {err}");
                for (n, err) in err.chain().skip(1).enumerate() {
                    if n == 0 {
                        eprintln!("Caused by:");
                    }
                    eprintln!("\t{err}");
                }

                ExitCode::FAILURE
            }
        }
    }

    async fn run_command(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Vexination(run) => run.run().await,
            Command::Bombastic(run) => run.run().await,
            Command::Spog(run) => run.run().await,
            Command::Exporter(run) => run.run().await,
        }
    }
}

#[tokio::main]
async fn main() -> impl Termination {
    tracing_subscriber::fmt::init();
    Cli::parse().run().await
}
