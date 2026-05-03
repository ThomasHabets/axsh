use clap::Parser;

#[derive(Parser)]
struct Args {
    input: std::path::PathBuf,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let key = axsh::ConnSign::from_file(&args.input).map_err(std::io::Error::other)?;
    let public_key = key.public_key_bytes().map_err(std::io::Error::other)?;
    println!("{}", axsh::format_authorized_conn_key(&public_key));
    Ok(())
}
