#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
//#![deny(clippy::cargo)]

use clap::ValueHint;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use vtpipeline::{PipelineAction, PipelineConfiguration, VTPipeline, VERSION};

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Parser;
use constcat::concat;
use malwaredb_virustotal::VirusTotalClient;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter, fmt, Layer, Registry};

const CONFIG_FILE: &str = "/etc/vtpipeline/vt.toml";

/// VirusTotal Pipeline
#[derive(Parser)]
#[command(author, about, name = "VT Pipeline", version = VERSION)]
pub struct PipelineArgs {
    /// Base directory for hashes, logs, samples, etc.
    #[arg(long, value_hint = ValueHint::DirPath)]
    pub data_dir: Option<PathBuf>,

    /// Virus Total API key
    pub vt_client: Option<VirusTotalClient>,

    /// Load configuration from a file
    #[arg(long, value_hint = ValueHint::FilePath)]
    pub config_file: Option<PathBuf>,

    /// Specific action to take
    #[clap(subcommand)]
    pub action: PipelineAction,
}

impl PipelineArgs {
    /// Parse run the pipeline by using provided arguments or loading configuration from a file.
    pub async fn run(self) -> Result<()> {
        let config = if let Some(path) = self.config_file {
            let contents = std::fs::read_to_string(&path)?;
            let cfg = match path.extension().and_then(OsStr::to_str) {
                Some("json") => serde_json::from_str::<PipelineConfiguration>(&contents)?,
                None | Some("toml") => toml::from_str::<PipelineConfiguration>(&contents)?,
                Some(ext) => {
                    bail!("Unknown extension {ext}");
                }
            };
            cfg
        } else if self.vt_client.is_some() && self.data_dir.is_some() {
            let data_dir = self.data_dir.unwrap();
            if !data_dir.exists() {
                bail!("VT directory {data_dir:?} does not exist");
            }
            PipelineConfiguration {
                data_dir,
                vt_key: self.vt_client.unwrap(),
            }
        } else if std::fs::exists(CONFIG_FILE)? {
            let contents = std::fs::read_to_string(CONFIG_FILE)?;
            toml::from_str::<PipelineConfiguration>(&contents)?
        } else {
            bail!(concat!("Nothing provided! Provide a config file or a VT API key and path to the data directory or have a config file at", CONFIG_FILE));
        };

        let pipeline = VTPipeline::new(config.data_dir, self.action, config.vt_key);

        pipeline.run().await
    }
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let err_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("log-error.log")
        .expect("failed to open log-error.log");

    let subscriber = Registry::default()
        .with(
            // stdout layer, to view everything in the console
            fmt::layer().compact().with_ansi(true),
        )
        .with(
            // log-error file, to log the errors that arise
            fmt::layer()
                .json()
                .with_writer(err_file)
                .with_filter(filter::LevelFilter::from_level(Level::ERROR)),
        );

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let pipeline = PipelineArgs::parse();
    pipeline.run().await?;

    Ok(ExitCode::SUCCESS)
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;

    PipelineArgs::command().debug_assert();
}
