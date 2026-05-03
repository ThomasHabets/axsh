use clap::Parser;

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Parser)]
struct Args {
    input: std::path::PathBuf,
}

fn encode_base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let word = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);

        out.push(BASE64_ALPHABET[((word >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((word >> 12) & 0x3f) as usize] as char);
        if chunk.len() >= 2 {
            out.push(BASE64_ALPHABET[((word >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() == 3 {
            out.push(BASE64_ALPHABET[(word & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let key = axsh::ConnSign::from_file(&args.input).map_err(std::io::Error::other)?;
    let public_key = key.public_key_bytes().map_err(std::io::Error::other)?;
    println!("{}", encode_base64(&public_key));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::encode_base64;

    #[test]
    fn base64_encodes_known_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"hello world"), "aGVsbG8gd29ybGQ=");
    }
}
