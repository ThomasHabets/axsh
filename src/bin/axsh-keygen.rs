//! axsh key generator.
#![allow(clippy::unnecessary_debug_formatting)]
use clap::Parser;

/// axsh key generator.
///
/// Generates the long lives `ConnSign` key that's a combination of ML-DSA and
/// ed25519.
#[derive(Parser)]
#[command(version)]
struct Args {
    output: std::path::PathBuf,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let key = axsh::ConnSign::new().map_err(std::io::Error::other)?;
    key.write_to_file(&args.output)
        .map_err(std::io::Error::other)?;
    println!("wrote {:?}", args.output);
    Ok(())
}
