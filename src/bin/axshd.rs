use std::sync::Arc;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use axsh::{
    ConnSign, ConnVerify, Packet, PacketSign, PacketVerify, ServerComplete, ServerHello, hdlc,
};

async fn handle_connection(
    mut stream: TcpStream,
    conn_sign: Arc<ConnSign>,
    unique: u64,
) -> std::io::Result<()> {
    let packet_sign = PacketSign::new().map_err(std::io::Error::other)?;
    let packet = Packet::ServerHello(ServerHello::new(
        unique,
        conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?,
        packet_sign.public_key_bytes(),
    ));
    let server_hello_wire = packet
        .serialize(conn_sign.as_ref())
        .map_err(std::io::Error::other)?;
    let frame = hdlc::encode(&server_hello_wire);
    stream.write_all(&frame).await?;

    let frame = hdlc::read_frame(&mut stream).await?;
    let client_hello_wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
    let packet =
        Packet::deserialize(&client_hello_wire, None, None).map_err(std::io::Error::other)?;
    match packet {
        Packet::ClientHello(hello) => {
            eprintln!(
                "received ClientHello: server_unique={}, client_unique={}, conn_key={} bytes, packet_key={} bytes",
                hello.server_unique(),
                hello.unique(),
                hello.conn_sign_public_key().len(),
                hello.packet_sign_public_key().len()
            );
            if hello.server_unique() != unique {
                return Err(std::io::Error::other(format!(
                    "client echoed server_unique={} but expected {}",
                    hello.server_unique(),
                    unique
                )));
            }
            let _client_conn_verify = ConnVerify::new(hello.conn_sign_public_key().to_vec());
            let _client_packet_verify = PacketVerify::new(hello.packet_sign_public_key());

            let mut transcript = server_hello_wire;
            transcript.extend(&client_hello_wire);
            let packet = Packet::ServerComplete(ServerComplete::new(
                conn_sign
                    .sign_detached(&transcript)
                    .map_err(std::io::Error::other)?,
            ));
            let wire = packet
                .serialize(conn_sign.as_ref())
                .map_err(std::io::Error::other)?;
            let frame = hdlc::encode(&wire);
            stream.write_all(&frame).await?;
        }
        other => {
            return Err(std::io::Error::other(format!(
                "expected ClientHello, got {other:?}"
            )));
        }
    }
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
