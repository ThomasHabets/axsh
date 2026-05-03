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
    let mut args = env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:12345".to_string());
    let key_path = args
        .next()
        .unwrap_or_else(|| "axsh-conn-sign.pk8".to_string());
    let conn_sign = ConnSign::from_file(&key_path).map_err(std::io::Error::other)?;
    let packet_sign = PacketSign::new().map_err(std::io::Error::other)?;
    let mut stream = TcpStream::connect(&addr).await?;

    let frame = hdlc::read_frame(&mut stream).await?;
    let server_hello_wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
    let packet =
        Packet::deserialize(&server_hello_wire, None, None).map_err(std::io::Error::other)?;

    match packet {
        Packet::ServerHello(hello) => {
            eprintln!(
                "received ServerHello: server_unique={}, conn_key={} bytes, packet_key={} bytes",
                hello.unique(),
                hello.conn_sign_public_key().len(),
                hello.packet_sign_public_key().len()
            );
            let server_conn_verify = ConnVerify::new(hello.conn_sign_public_key().to_vec());
            let _server_packet_verify = PacketVerify::new(hello.packet_sign_public_key());

            let packet = Packet::ClientHello(ClientHello::new(
                hello.unique(),
                random_u64()?,
                conn_sign
                    .public_key_bytes()
                    .map_err(std::io::Error::other)?,
                packet_sign.public_key_bytes(),
            ));
            let client_hello_wire = packet
                .serialize(&conn_sign)
                .map_err(std::io::Error::other)?;
            let frame = hdlc::encode(&client_hello_wire);
            stream.write_all(&frame).await?;

            let frame = hdlc::read_frame(&mut stream).await?;
            let wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
            let packet = Packet::deserialize(&wire, None, None).map_err(std::io::Error::other)?;
            match packet {
                Packet::ServerComplete(complete) => {
                    eprintln!(
                        "received ServerComplete: signature={} bytes",
                        complete.signature().len()
                    );
                    let mut transcript = server_hello_wire;
                    transcript.extend(&client_hello_wire);
                    if !server_conn_verify.verify_detached(complete.signature(), &transcript) {
                        return Err(std::io::Error::other(
                            "server complete transcript signature verification failed",
                        ));
                    }
                }
                other => {
                    return Err(std::io::Error::other(format!(
                        "expected ServerComplete, got {other:?}"
                    )));
                }
            }
        }
        other => {
            return Err(std::io::Error::other(format!(
                "expected ServerHello, got {other:?}"
            )));
        }
    }

    Ok(())
}
