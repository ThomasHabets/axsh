use std::collections::HashSet;
use std::fs::File;
use std::sync::Arc;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use axsh::{
    ConnSign, ConnVerify, Packet, PacketSign, PacketVerify, ServerComplete, ServerHello,
    decode_base64, hdlc,
};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short = 'k', long = "key", default_value = "axshd-conn-sign.pk8")]
    key_path: std::path::PathBuf,

    #[arg(short = 'a', long = "authorized-keys")]
    authorized_keys_path: std::path::PathBuf,
}

fn random_u64() -> std::io::Result<u64> {
    let mut bytes = [0u8; 8];
    let mut file = File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut file, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn load_authorized_keys(path: &std::path::Path) -> std::io::Result<HashSet<Vec<u8>>> {
    let contents = std::fs::read_to_string(path)?;
    let mut keys = HashSet::new();
    for (lineno, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let key = decode_base64(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}:{}: {e}", path.display(), lineno + 1),
            )
        })?;
        keys.insert(key);
    }
    Ok(keys)
}

async fn handle_connection(
    mut stream: TcpStream,
    conn_sign: Arc<ConnSign>,
    authorized_keys: Arc<HashSet<Vec<u8>>>,
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
            if !authorized_keys.contains(hello.conn_sign_public_key()) {
                return Err(std::io::Error::other(
                    "client ConnSign key is not authorized",
                ));
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
    let args = Args::parse();
    let conn_sign = Arc::new(ConnSign::from_file(&args.key_path).map_err(std::io::Error::other)?);
    let authorized_keys = Arc::new(load_authorized_keys(&args.authorized_keys_path)?);
    let listener = TcpListener::bind("0.0.0.0:12345").await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        let unique = random_u64()?;
        let conn_sign = Arc::clone(&conn_sign);
        let authorized_keys = Arc::clone(&authorized_keys);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, conn_sign, authorized_keys, unique).await {
                eprintln!("connection {addr} error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // TODO: use a real temp file generator.
    fn unique_test_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::temp_dir().join(format!("axshd-{name}-{}-{nanos}.txt", std::process::id()))
    }

    #[test]
    fn load_authorized_keys_parses_base64_lines() {
        let path = unique_test_path("authorized");
        std::fs::write(&path, "Zg==\n\nZm9v\n").expect("failed to write allowlist");

        let keys = load_authorized_keys(&path).expect("failed to load allowlist");
        let expected = HashSet::from([b"f".to_vec(), b"foo".to_vec()]);
        assert_eq!(keys, expected);

        std::fs::remove_file(path).expect("failed to remove allowlist");
    }

    #[test]
    fn load_authorized_keys_rejects_invalid_base64() {
        let path = unique_test_path("invalid-authorized");
        std::fs::write(&path, "not-base64!\n").expect("failed to write allowlist");

        let err = load_authorized_keys(&path).expect_err("loaded invalid allowlist");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(path).expect("failed to remove allowlist");
    }
}
