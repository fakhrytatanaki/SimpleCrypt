use std::{
    io::{self, IsTerminal},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use directories::BaseDirs;
use simplecrypt::{app::App, storage::VaultFile, terminal, theme::Theme};

#[derive(Parser)]
#[command(
    name = "simplecrypt",
    version,
    about = "Small vault. Quiet secrets.",
    long_about = "A local-first, encrypted password manager for your terminal.\nAll labels and fields are encrypted on disk. There is no password recovery."
)]
struct Args {
    /// Encrypted vault location (default: $XDG_DATA_HOME/simplecrypt/vault.scv)
    #[arg(long, value_name = "PATH")]
    vault: Option<PathBuf>,
    /// Catppuccin color palette
    #[arg(long, value_enum, default_value_t = Theme::Mocha)]
    theme: Theme,
    /// Lock after this many seconds without keyboard input (1–86400)
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    idle_timeout: u64,
}

fn start() -> Result<()> {
    let args = Args::parse();
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("SimpleCrypt needs an interactive terminal. Run it directly, not through a pipe.");
    }
    let path = match args.vault {
        Some(path) => path,
        None => BaseDirs::new()
            .context("Cannot locate a home directory; specify --vault")?
            .data_dir()
            .join("simplecrypt")
            .join("vault.scv"),
    };
    let file = VaultFile::open(path)?;
    let app = App::new(file, args.theme, Duration::from_secs(args.idle_timeout))?;
    terminal::run(app)
}

fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "SimpleCrypt: {}",
                simplecrypt::ui::safe_text(&error.to_string())
            );
            ExitCode::FAILURE
        }
    }
}
