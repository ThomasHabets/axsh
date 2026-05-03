use std::{env, fs::File};

use axsh::{ClientHello, ConnSign, ConnVerify, Packet, PacketSign, PacketVerify, hdlc};
use tokio::{io::AsyncWriteExt, net::TcpStream};

fn random_u64() -> std::io::Result<u64> {
    let mut bytes = [0u8; 8];
    let mut file = File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut file, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:12345".to_string());
    let conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
    let packet_sign = PacketSign::new().map_err(std::io::Error::other)?;
    let mut stream = TcpStream::connect(&addr).await?;

    let frame = hdlc::read_frame(&mut stream).await?;
    let wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
    let packet = Packet::deserialize(&wire, None, None).map_err(std::io::Error::other)?;

    match packet {
        Packet::ServerHello(hello) => {
            eprintln!(
                "received ServerHello: server_unique={}, conn_key={} bytes, packet_key={} bytes",
                hello.unique(),
                hello.conn_sign_public_key().len(),
                hello.packet_sign_public_key().len()
            );
            let _server_conn_verify = ConnVerify::new(hello.conn_sign_public_key().to_vec());
            let _server_packet_verify = PacketVerify::new(hello.packet_sign_public_key());

            let packet = Packet::ClientHello(ClientHello::new(
                hello.unique(),
                random_u64()?,
                conn_sign
                    .public_key_bytes()
                    .map_err(std::io::Error::other)?,
                packet_sign.public_key_bytes(),
            ));
            let wire = packet
                .serialize(&conn_sign)
                .map_err(std::io::Error::other)?;
            let frame = hdlc::encode(&wire);
            stream.write_all(&frame).await?;
        }
        other => {
            return Err(std::io::Error::other(format!(
                "expected ServerHello, got {other:?}"
            )));
        }
    }

    Ok(())
}
