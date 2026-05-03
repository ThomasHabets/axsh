use anyhow::{Result, bail, ensure};

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_char(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => bail!("invalid base64 character"),
    }
}

pub fn encode_base64(data: &[u8]) -> String {
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

pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
    ensure!(data.len() % 4 == 0, "base64 length must be a multiple of 4");

    let bytes = data.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let is_last_chunk = i + 1 == bytes.len() / 4;
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        out.push((a << 2) | (b >> 4));

        match (chunk[2], chunk[3]) {
            (b'=', b'=') => {
                ensure!(is_last_chunk, "padding must appear only in the final chunk");
                break;
            }
            (b'=', _) => bail!("invalid base64 padding"),
            (c, b'=') => {
                ensure!(is_last_chunk, "padding must appear only in the final chunk");
                let c = decode_char(c)?;
                out.push((b << 4) | (c >> 2));
                break;
            }
            (c, d) => {
                let c = decode_char(c)?;
                let d = decode_char(d)?;
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{decode_base64, encode_base64};

    #[test]
    fn base64_encodes_known_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn base64_decodes_known_vectors() {
        assert_eq!(decode_base64("").expect("decode failed"), b"");
        assert_eq!(decode_base64("Zg==").expect("decode failed"), b"f");
        assert_eq!(decode_base64("Zm8=").expect("decode failed"), b"fo");
        assert_eq!(decode_base64("Zm9v").expect("decode failed"), b"foo");
        assert_eq!(
            decode_base64("aGVsbG8gd29ybGQ=").expect("decode failed"),
            b"hello world"
        );
    }

    #[test]
    fn base64_rejects_invalid_input() {
        assert!(decode_base64("abc").is_err());
        assert!(decode_base64("ab=c").is_err());
        assert!(decode_base64("!!!!").is_err());
    }
}
