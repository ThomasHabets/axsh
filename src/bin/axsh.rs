use axsh::{ClientStream, ConnSign, LogLevel, init_logging};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

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
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut stdin_open = true;

    loop {
        let mut buf = [0u8; 1024];
        tokio::select! {
            read_result = client.read(&mut buf) => {
                let n = read_result?;
                if n == 0 {
                    break;
                }
                print!("{}", String::from_utf8_lossy(&buf[..n]));
            }
            line_result = stdin.next_line(), if stdin_open => {
                match line_result? {
                    Some(line) => {
                        client.write_all(line.as_bytes()).await?;
                        client.write_all(b"\n").await?;
                        client.flush().await?;
                    }
                    None => {
                        stdin_open = false;
                        client.shutdown().await?;
                    }
                }
            }
        }
    }
    Ok(())
}
