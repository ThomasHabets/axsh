use std::collections::HashSet;
use std::sync::Arc;

use clap::Parser;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

use axsh::{ConnSign, ServerStream, decode_base64};

#[derive(Parser)]
struct Args {
    /// File containing server private key.
    #[arg(short = 'k', long = "key", default_value = "axshd-conn-sign.pk8")]
    key_path: std::path::PathBuf,

    /// File containing authorized public keys.
    #[arg(short = 'a', long = "authorized-keys")]
    authorized_keys_path: std::path::PathBuf,
}

/// Load authorized keys from file. One pubkey per line.
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

/// Handle one connected client.
async fn handle_connection(
    stream: TcpStream,
    conn_sign: Arc<ConnSign>,
    authorized_keys: Arc<HashSet<Vec<u8>>>,
) -> std::io::Result<()> {
    let mut stream =
        ServerStream::new(stream, conn_sign.as_ref(), authorized_keys.as_ref()).await?;
    let mut buf = [0u8; 4096];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            eprintln!("Client disconnected");
            return Ok(());
        }
        println!("Got data {:?}", &buf[..n]);
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let conn_sign = Arc::new(ConnSign::from_file(&args.key_path).map_err(std::io::Error::other)?);
    let authorized_keys = Arc::new(load_authorized_keys(&args.authorized_keys_path)?);
    let listener = TcpListener::bind("0.0.0.0:12345").await?;

    loop {
        let (stream, addr) = listener.accept().await?;
        let conn_sign = Arc::clone(&conn_sign);
        let authorized_keys = Arc::clone(&authorized_keys);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, conn_sign, authorized_keys).await {
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
