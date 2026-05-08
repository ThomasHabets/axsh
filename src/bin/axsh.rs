//! axsh secure shell client.
#![allow(clippy::unnecessary_debug_formatting)]

use std::collections::HashMap;
use std::str::FromStr;

use agw::r#async::AGW;
use clap::Parser;
use log::{debug, info};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use axsh::{
    CONN_AUTHORIZED_KEY_KIND, ClientStream, ConnSign, LogLevel, ServerHello, format_known_host,
    format_sha256_digest, format_sha256_fingerprint, init_logging, parse_known_host,
};

/// axsh secure shell client.
///
/// Connects to a server securing authentication and integrity, but not
/// encrypted or obfuscated (because it's an amateur radio license requirement).
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to connect to.
    #[arg()]
    addr: String,

    /// Source callsign to use. E.g. M0QQQ-1.
    #[arg(short)]
    src: Option<String>,

    #[arg(long)]
    agw_addr: Option<String>,

    /// Private client key.
    #[arg(short = 'k', long = "key", default_value = "axsh-conn-sign.pk8")]
    key_path: std::path::PathBuf,

    /// File containing known server public keys.
    #[arg(long = "known-hosts", default_value = "known_hosts")]
    known_hosts_path: std::path::PathBuf,

    /// Log level for stderr diagnostics.
    #[arg(short = 'v', long = "log-level", value_enum, default_value = "info")]
    log_level: LogLevel,
}

/// Load known-hosts entries from file.
fn load_known_hosts(path: &std::path::Path) -> std::io::Result<HashMap<String, Vec<u8>>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => {
            return Err(std::io::Error::new(
                err.kind(),
                format!("failed to read known_hosts file {path:?}: {err}"),
            ));
        }
    };
    let mut hosts = HashMap::new();
    for (lineno, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (host, key) = parse_known_host(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{path:?}:{}: {e}", lineno + 1),
            )
        })?;
        if hosts.insert(host.clone(), key).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{path:?}:{}: duplicate known-host entry for {host}",
                    lineno + 1
                ),
            ));
        }
    }
    Ok(hosts)
}

/// Append one known-hosts entry to `path`.
fn append_known_host(path: &std::path::Path, host: &str, public_key: &[u8]) -> std::io::Result<()> {
    let needs_newline = match std::fs::read(path) {
        Ok(contents) => !contents.is_empty() && contents.last().copied() != Some(b'\n'),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => {
            return Err(std::io::Error::new(
                err.kind(),
                format!("failed to read known_hosts file {path:?}: {err}"),
            ));
        }
    };

    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to open known_hosts file {path:?}: {err}"),
        )
    })?;
    if needs_newline {
        std::io::Write::write_all(&mut file, b"\n")?;
    }
    std::io::Write::write_all(&mut file, format_known_host(host, public_key).as_bytes())?;
    std::io::Write::write_all(&mut file, b"\n")?;
    Ok(())
}

/// Ask whether to trust a previously unknown server key and record it.
fn confirm_and_add_known_host(
    path: &std::path::Path,
    host: &str,
    public_key: &[u8],
) -> std::io::Result<()> {
    let fingerprint = format_sha256_fingerprint(public_key);
    let mut stderr = std::io::stderr().lock();
    std::io::Write::write_all(
        &mut stderr,
        format!("The authenticity of host '{host}' can't be established.\n").as_bytes(),
    )?;
    std::io::Write::write_all(
        &mut stderr,
        format!("{CONN_AUTHORIZED_KEY_KIND} key fingerprint is {fingerprint}.\n").as_bytes(),
    )?;
    std::io::Write::write_all(
        &mut stderr,
        b"Are you sure you want to continue connecting (yes/no)? ",
    )?;
    std::io::Write::flush(&mut stderr)?;

    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    if response.trim() != "yes" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server key not accepted",
        ));
    }

    append_known_host(path, host, public_key)?;
    std::io::Write::write_all(
        &mut stderr,
        format!(
            "Warning: Permanently added '{host}' ({CONN_AUTHORIZED_KEY_KIND}) to the list of known hosts.\n"
        )
        .as_bytes(),
    )?;
    std::io::Write::flush(&mut stderr)?;
    Ok(())
}

trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> AsyncReadWrite for T {}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    init_logging(args.log_level).map_err(std::io::Error::other)?;
    info!("Starting");

    let agw;
    let stream: Box<dyn AsyncReadWrite> = if let Some(agw_addr) = args.agw_addr {
        agw = AGW::new(&agw_addr).await.map_err(std::io::Error::other)?;
        let Some(src) = args.src else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "For AGW streams -s must be provided",
            ));
        };
        let src = &agw::Call::from_str(&src).map_err(std::io::Error::other)?;
        let dst = &agw::Call::from_str(&args.addr).map_err(std::io::Error::other)?;
        Box::new(
            agw.connect(agw::Port(0), agw::Pid(0xF0), src, dst, &[])
                .await
                .map_err(std::io::Error::other)?,
        )
    } else {
        Box::new(tokio::net::TcpStream::connect(&args.addr).await?)
    };
    debug!("Connected");
    if false {
        let mut stream = stream;
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

    info!("Handshaking…");
    let mut client = {
        let addr = args.addr.clone();
        let conn_sign = ConnSign::from_file(&args.key_path).map_err(std::io::Error::other)?;
        let known_hosts = load_known_hosts(&args.known_hosts_path)?;
        let known_hosts_path = args.known_hosts_path.clone();
        let expected_server_key = known_hosts.get(&args.addr).cloned();
        let is_known_host = expected_server_key.is_some();
        ClientStream::new_with_server_pubkey_lookup(
            stream,
            conn_sign,
            move |_server_hello| Ok(expected_server_key),
            move |server_hello: &ServerHello, server_public_key| {
                debug!(
                    "Verifying ServerPubkey {}",
                    format_sha256_digest(&server_hello.conn_sign_public_key_sha256())
                );
                if is_known_host {
                    // Already checked and in `known_hosts`.
                    Ok(())
                } else {
                    confirm_and_add_known_host(&known_hosts_path, &addr, server_public_key)
                }
            },
        )
    }
    .await?;
    info!("Handshake successful");
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
                if let Some(line) = line_result? {
                        let mut buf = line.as_bytes().to_vec();
                        buf.push(b'\n');
                        client.write_all(&buf).await?;
                        if false {
                            client.keepalive().await?;
                        }
                        client.flush().await?;
                    } else {
                        stdin_open = false;
                        client.shutdown().await?;
                        client.flush().await?;
                }
            }
        }
    }
    client.shutdown().await?;
    client.flush().await?;
    // Direwolf seems to need a bit of time before exiting, or it won't send a
    // `DISC`.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::temp_dir().join(format!("axsh-{name}-{}-{nanos}.txt", std::process::id()))
    }

    #[test]
    fn load_known_hosts_parses_host_key_lines() {
        let path = unique_test_path("known-hosts");
        std::fs::write(
            &path,
            format!(
                "# comment\n\n{}\n{}\n",
                format_known_host("host1:12345", b"foo"),
                format_known_host("host2:12345", b"bar"),
            ),
        )
        .expect("failed to write known_hosts");

        let hosts = load_known_hosts(&path).expect("failed to load known_hosts");
        assert_eq!(hosts.get("host1:12345"), Some(&b"foo".to_vec()));
        assert_eq!(hosts.get("host2:12345"), Some(&b"bar".to_vec()));

        std::fs::remove_file(path).expect("failed to remove known_hosts");
    }

    #[test]
    fn load_known_hosts_rejects_duplicate_hosts() {
        let path = unique_test_path("known-hosts-duplicate");
        std::fs::write(
            &path,
            format!(
                "{}\n{}\n",
                format_known_host("host1:12345", b"foo"),
                format_known_host("host1:12345", b"bar"),
            ),
        )
        .expect("failed to write known_hosts");

        let err = load_known_hosts(&path).expect_err("loaded duplicate known_hosts");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(path).expect("failed to remove known_hosts");
    }

    #[test]
    fn load_known_hosts_returns_empty_for_missing_file() {
        let path = unique_test_path("known-hosts-missing");
        let hosts = load_known_hosts(&path).expect("failed to handle missing known_hosts");
        assert!(hosts.is_empty());
    }

    #[test]
    fn append_known_host_writes_one_line() {
        let path = unique_test_path("known-hosts-append");
        append_known_host(&path, "host1:12345", b"foo").expect("failed to append known host");
        append_known_host(&path, "host2:12345", b"bar").expect("failed to append known host");

        let contents = std::fs::read_to_string(&path).expect("failed to read known_hosts");
        assert_eq!(
            contents,
            format!(
                "{}\n{}\n",
                format_known_host("host1:12345", b"foo"),
                format_known_host("host2:12345", b"bar"),
            )
        );

        std::fs::remove_file(path).expect("failed to remove known_hosts");
    }
}
