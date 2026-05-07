#![allow(clippy::unnecessary_debug_formatting)]
use clap::Parser;

#[derive(Parser)]
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
