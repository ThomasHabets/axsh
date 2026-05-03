use axsh::{ClientStream, ConnSign};
use clap::Parser;
use tokio::io::AsyncWriteExt;

#[derive(Parser)]
struct Args {
    #[arg()]
    addr: String,

    #[arg(short = 'k', long = "key", default_value = "axsh-conn-sign.pk8")]
    key_path: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let conn_sign = ConnSign::from_file(&args.key_path).map_err(std::io::Error::other)?;
    let stream = tokio::net::TcpStream::connect(&args.addr).await?;
    let mut client = ClientStream::new(stream, conn_sign).await?;
    client.write_all(b"hello").await?;
    client.flush().await?;
    Ok(())
}
