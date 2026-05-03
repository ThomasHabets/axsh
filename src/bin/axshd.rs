use std::sync::Arc;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use axsh::{ConnSign, Packet, PacketSign, ServerHello, hdlc};

async fn handle_connection(
    mut stream: TcpStream,
    conn_sign: Arc<ConnSign>,
    unique: u64,
) -> std::io::Result<()> {
    let _packet_sign = PacketSign::new().map_err(std::io::Error::other)?;
    let packet = Packet::ServerHello(ServerHello::new(unique));
    let wire = packet
        .serialize(conn_sign.as_ref())
        .map_err(std::io::Error::other)?;
    let frame = hdlc::encode(&wire);
    stream.write_all(&frame).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let conn_sign = Arc::new(ConnSign::new().map_err(std::io::Error::other)?);
    let mut next_unique = 1u64;
    let listener = TcpListener::bind("0.0.0.0:12345").await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        let unique = next_unique;
        next_unique += 1;
        let conn_sign = Arc::clone(&conn_sign);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, conn_sign, unique).await {
                eprintln!("connection {addr} error: {e}");
            }
        });
    }
}
