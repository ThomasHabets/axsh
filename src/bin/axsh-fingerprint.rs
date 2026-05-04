use clap::Parser;

#[derive(Parser)]
struct Args {
    input: std::path::PathBuf,
}

/// Load one public key from an authorized-key or known-hosts line.
fn load_public_key(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let contents = std::fs::read_to_string(path)?;
    let mut public_key = None;

    for (lineno, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let key = match line.split_whitespace().count() {
            2 => axsh::parse_authorized_conn_key(line),
            3 => axsh::parse_known_host(line).map(|(_, key)| key),
            _ => Err(anyhow::anyhow!(
                "expected 'mldsa-ed25519 <base64>' or '<host> mldsa-ed25519 <base64>'"
            )),
        }
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}:{}: {e}", path.display(), lineno + 1),
            )
        })?;

        if public_key.replace(key).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: expected exactly one public key entry", path.display()),
            ));
        }
    }

    public_key.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: no public key entry found", path.display()),
        )
    })
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let public_key = load_public_key(&args.input)?;
    println!("{}", axsh::format_sha256_fingerprint(&public_key));
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
        std::env::temp_dir().join(format!(
            "axsh-fingerprint-{name}-{}-{nanos}.txt",
            std::process::id()
        ))
    }

    #[test]
    fn load_public_key_parses_authorized_key_line() {
        let path = unique_test_path("authorized");
        std::fs::write(&path, "mldsa-ed25519 Zm9v\n").expect("failed to write public key file");

        let public_key = load_public_key(&path).expect("failed to load public key");
        assert_eq!(public_key, b"foo");

        std::fs::remove_file(path).expect("failed to remove public key file");
    }

    #[test]
    fn load_public_key_parses_known_host_line() {
        let path = unique_test_path("known-host");
        std::fs::write(&path, "example:12345 mldsa-ed25519 YmFy\n")
            .expect("failed to write public key file");

        let public_key = load_public_key(&path).expect("failed to load public key");
        assert_eq!(public_key, b"bar");

        std::fs::remove_file(path).expect("failed to remove public key file");
    }

    #[test]
    fn load_public_key_rejects_multiple_entries() {
        let path = unique_test_path("multiple");
        std::fs::write(&path, "mldsa-ed25519 Zm9v\nmldsa-ed25519 YmFy\n")
            .expect("failed to write public key file");

        let err = load_public_key(&path).expect_err("loaded multiple public key entries");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(path).expect("failed to remove public key file");
    }
}
