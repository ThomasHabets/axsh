#![allow(clippy::unnecessary_debug_formatting)]
use std::collections::HashMap;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;

use agw::r#async::AGW;
use anyhow::anyhow;
use clap::Parser;
use log::info;
use tokio::io::AsyncBufReadExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};

use axsh::{
    ConnSign, LogLevel, SHA256_DIGEST_LEN, ServerStream, init_logging, parse_authorized_conn_key,
    sha256_bytes,
};

#[derive(Parser)]
struct Args {
    /// Address of AGW server, if using AX.25.
    #[arg(long)]
    agw_addr: Option<String>,

    /// Address to listen to. E.g. `M0QQQ-9` or `[::]:12345`.
    #[arg(short, long)]
    listen: Option<String>,

    /// File containing server private key.
    #[arg(short = 'k', long = "key", default_value = "axshd-conn-sign.pk8")]
    key_path: std::path::PathBuf,

    /// File containing authorized public keys.
    #[arg(short = 'a', long = "authorized-keys")]
    authorized_keys_path: std::path::PathBuf,

    /// Log level for stderr diagnostics.
    #[arg(short = 'v', long = "log-level", value_enum, default_value = "info")]
    log_level: LogLevel,
}

/// Load authorized keys from file. One typed pubkey per line.
fn load_authorized_keys(
    path: &std::path::Path,
) -> std::io::Result<HashMap<[u8; SHA256_DIGEST_LEN], Vec<u8>>> {
    let contents = std::fs::read_to_string(path).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to read authorized_keys file {path:?}: {err}"),
        )
    })?;
    let mut keys = HashMap::new();
    for (lineno, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let key = parse_authorized_conn_key(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{path:?}:{}: {e}", lineno + 1),
            )
        })?;
        let digest = sha256_bytes(&key);
        if keys.insert(digest, key).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{path:?}:{}: duplicate authorized key digest", lineno + 1),
            ));
        }
    }
    Ok(keys)
}

/// Run one shell command line and stream its stdout and stderr to the client.
async fn run_command_line<W: tokio::io::AsyncWrite + Unpin>(
    write: &mut W,
    command: &str,
) -> std::io::Result<()> {
    let mut child = Command::new("/bin/sh")
        .arg("-lc")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("child stdout was not captured"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("child stderr was not captured"))?;
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut stdout_buf = [0u8; 4096];
    let mut stderr_buf = [0u8; 4096];

    while stdout_open || stderr_open {
        tokio::select! {
            read_result = stdout.read(&mut stdout_buf), if stdout_open => {
                let n = read_result?;
                if n == 0 {
                    stdout_open = false;
                } else {
                    write.write_all(&stdout_buf[..n]).await?;
                    write.flush().await?;
                }
            }
            read_result = stderr.read(&mut stderr_buf), if stderr_open => {
                let n = read_result?;
                if n == 0 {
                    stderr_open = false;
                } else {
                    write.write_all(&stderr_buf[..n]).await?;
                    write.flush().await?;
                }
            }
        }
    }

    let status = child.wait().await?;
    let exit_status = status
        .code()
        .map_or_else(|| format!("unknown ({status})"), |code| code.to_string());
    write
        .write_all(format!(">>> Exit status {exit_status}\n").as_bytes())
        .await?;
    write.flush().await?;
    Ok(())
}

/// Handle one connected client.
async fn handle_connection(
    stream: impl AsyncReadWrite,
    conn_sign: Arc<ConnSign>,
    authorized_keys: Arc<HashMap<[u8; SHA256_DIGEST_LEN], Vec<u8>>>,
) -> std::io::Result<()> {
    let mut stream =
        ServerStream::new(stream, conn_sign.as_ref(), authorized_keys.as_ref()).await?;
    if false {
        stream.keepalive().await?;
    }
    let (read, mut write) = tokio::io::split(stream);
    let mut linereader = tokio::io::BufReader::new(read).lines();

    loop {
        let Some(command) = linereader.next_line().await? else {
            break;
        };
        log::info!("executing command from client: {command}");
        run_command_line(&mut write, &command).await?;
    }
    log::info!("client disconnected");
    Ok(())
}

trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_logging(args.log_level).map_err(std::io::Error::other)?;
    let conn_sign = Arc::new(ConnSign::from_file(&args.key_path).map_err(std::io::Error::other)?);
    let authorized_keys = Arc::new(load_authorized_keys(&args.authorized_keys_path)?);

    if let Some(agw_addr) = args.agw_addr {
        let Some(my_addr) = args.listen else {
            return Err(anyhow!("Must provide a -l listen address"));
        };
        let agw = AGW::new(&agw_addr).await.map_err(std::io::Error::other)?;
        let my_addr = &agw::Call::from_str(&my_addr).map_err(std::io::Error::other)?;
        let mut listener = agw
            .listen(agw::Port(0), my_addr)
            .await
            .map_err(std::io::Error::other)?;
        loop {
            let mut stream = listener.accept().await.unwrap();
            let addr = stream.dst().clone();
            info!("Got connection from {addr}");
            if false {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                stream.write_all(b"Hello from server\n").await?;
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                stream.shutdown().await?;
                loop {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).await?;
                    let buf = &buf[..n];
                    if buf.is_empty() {
                        return Ok(());
                    }
                    println!("{:?}", String::from_utf8_lossy(buf));
                }
            }
            let conn_sign = Arc::clone(&conn_sign);
            let authorized_keys = Arc::clone(&authorized_keys);

            if let Err(e) = handle_connection(stream, conn_sign, authorized_keys).await {
                log::error!("connection {addr} error: {e}");
            }
        }
    } else {
        let Some(my_addr) = args.listen else {
            return Err(anyhow!("Must provide a -l listen address"));
        };
        let listener = TcpListener::bind(my_addr).await?;
        loop {
            let (stream, addr) = listener.accept().await?;
            let conn_sign = Arc::clone(&conn_sign);
            let authorized_keys = Arc::clone(&authorized_keys);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, conn_sign, authorized_keys).await {
                    log::error!("connection {addr} error: {e}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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
        std::fs::write(&path, "mldsa-ed25519 Zg==\n\nmldsa-ed25519 Zm9v\n")
            .expect("failed to write allowlist");

        let keys = load_authorized_keys(&path).expect("failed to load allowlist");
        let expected = HashMap::from([
            (sha256_bytes(b"f"), b"f".to_vec()),
            (sha256_bytes(b"foo"), b"foo".to_vec()),
        ]);
        assert_eq!(keys, expected);

        std::fs::remove_file(path).expect("failed to remove allowlist");
    }

    #[test]
    fn load_authorized_keys_rejects_invalid_base64() {
        let path = unique_test_path("invalid-authorized");
        std::fs::write(&path, "mldsa-ed25519 not-base64!\n").expect("failed to write allowlist");

        let err = load_authorized_keys(&path).expect_err("loaded invalid allowlist");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(path).expect("failed to remove allowlist");
    }

    #[test]
    fn load_authorized_keys_rejects_wrong_key_type() {
        let path = unique_test_path("wrong-type");
        std::fs::write(&path, "ed25519 Zg==\n").expect("failed to write allowlist");

        let err = load_authorized_keys(&path).expect_err("loaded wrong key type");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(path).expect("failed to remove allowlist");
    }

    #[test]
    fn load_authorized_keys_rejects_duplicate_digest() {
        let path = unique_test_path("duplicate-authorized");
        std::fs::write(&path, "mldsa-ed25519 Zg==\nmldsa-ed25519 Zg==\n")
            .expect("failed to write allowlist");

        let err = load_authorized_keys(&path).expect_err("loaded duplicate allowlist");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(path).expect("failed to remove allowlist");
    }

    #[tokio::test]
    async fn run_command_line_streams_output() {
        let (mut read, mut write) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            run_command_line(&mut write, "printf 'out\\n'; printf 'err\\n' >&2")
                .await
                .expect("command failed");
        });

        let mut output = Vec::new();
        read.read_to_end(&mut output)
            .await
            .expect("failed to read command output");
        writer.await.expect("writer task panicked");

        let output = String::from_utf8(output).expect("output was not utf-8");
        assert!(
            output.contains("out\n"),
            "missing stdout output: {output:?}"
        );
        assert!(
            output.contains("err\n"),
            "missing stderr output: {output:?}"
        );
        assert!(
            output.contains(">>> Exit status 0\n"),
            "missing exit status output: {output:?}"
        );
    }
}
