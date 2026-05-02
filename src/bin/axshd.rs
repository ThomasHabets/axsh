use anyhow::Result;

use axsh::{PacketSign, ConnSign};
use axsh::SignVerify;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    stream.write_all(b"hello world\n").await?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:12345").await?;

    loop {
        let (stream, addr) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("connection {addr} error: {e}");
            }
        });
    }
}

