use axsh::{ClientStream, ConnSign, LogLevel, init_logging};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
struct Args {
    /// Address to connect to.
    #[arg()]
    addr: String,

    /// Private client key.
    #[arg(short = 'k', long = "key", default_value = "axsh-conn-sign.pk8")]
    key_path: std::path::PathBuf,

    /// Log level for stderr diagnostics.
    #[arg(short = 'v', long = "log-level", value_enum, default_value = "info")]
    log_level: LogLevel,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    init_logging(args.log_level).map_err(std::io::Error::other)?;
    let conn_sign = ConnSign::from_file(&args.key_path).map_err(std::io::Error::other)?;
    let stream = tokio::net::TcpStream::connect(&args.addr).await?;
    let mut client = ClientStream::new(stream, conn_sign).await?;
    client.write_all(b"hello").await?;
    client.flush().await?;

    loop {
        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let buf = &buf[..n];
        print!("{}", String::from_utf8_lossy(&buf));
    }
    Ok(())
}
