use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt};

const FLAG: u8 = 0x7e;
const ESCAPE: u8 = 0x7d;
const ESCAPE_XOR: u8 = 0x20;
const INITIAL_FCS: u16 = 0xffff;
const FCS_POLY: u16 = 0x8408;

/// Encode a payload into an HDLC frame with byte-stuffing and a CRC-16 FCS.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let fcs = frame_fcs(payload);
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.push(FLAG);
    escape_into(payload, &mut framed);
    escape_into(&fcs.to_le_bytes(), &mut framed);
    framed.push(FLAG);
    framed
}

/// Decode an HDLC frame, removing byte-stuffing and validating the CRC-16 FCS.
pub fn decode(frame: &[u8]) -> Result<Vec<u8>> {
    ensure!(frame.len() >= 4, "frame too short");
    ensure!(frame.first() == Some(&FLAG), "frame missing opening flag");
    ensure!(frame.last() == Some(&FLAG), "frame missing closing flag");

    let mut unescaped = Vec::with_capacity(frame.len().saturating_sub(2));
    let mut escaped = false;
    for byte in &frame[1..frame.len() - 1] {
        if escaped {
            unescaped.push(byte ^ ESCAPE_XOR);
            escaped = false;
            continue;
        }
        match *byte {
            ESCAPE => escaped = true,
            FLAG => bail!("unexpected flag inside frame"),
            byte => unescaped.push(byte),
        }
    }

    ensure!(!escaped, "frame ends with dangling escape");
    ensure!(unescaped.len() >= 2, "frame missing FCS");

    let payload_len = unescaped.len() - 2;
    let payload = &unescaped[..payload_len];
    let received_fcs = u16::from_le_bytes([unescaped[payload_len], unescaped[payload_len + 1]]);
    ensure!(frame_fcs(payload) == received_fcs, "frame FCS mismatch");
    Ok(payload.to_vec())
}

/// Read a single HDLC frame from an async byte stream.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    let mut in_frame = false;

    loop {
        let byte = reader.read_u8().await?;
        if !in_frame {
            if byte == FLAG {
                frame.clear();
                frame.push(byte);
                in_frame = true;
            }
            continue;
        }

        frame.push(byte);
        if byte == FLAG {
            return Ok(frame);
        }
    }
}

fn escape_into(bytes: &[u8], out: &mut Vec<u8>) {
    for byte in bytes {
        match *byte {
            FLAG | ESCAPE => {
                out.push(ESCAPE);
                out.push(byte ^ ESCAPE_XOR);
            }
            byte => out.push(byte),
        }
    }
}

fn frame_fcs(payload: &[u8]) -> u16 {
    !payload
        .iter()
        .fold(INITIAL_FCS, |fcs, byte| update_fcs(fcs, *byte))
}

fn update_fcs(mut fcs: u16, byte: u8) -> u16 {
    fcs ^= u16::from(byte);
    for _ in 0..8 {
        if fcs & 1 != 0 {
            fcs = (fcs >> 1) ^ FCS_POLY;
        } else {
            fcs >>= 1;
        }
    }
    fcs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_frame() -> Result<()> {
        let payload = b"hello, world";
        let frame = encode(payload);
        assert_eq!(decode(&frame)?, payload);
        Ok(())
    }

    #[test]
    fn escape_flag_and_escape_bytes() -> Result<()> {
        let payload = [0x7e, 0x7d, 0x00, 0x7e];
        let frame = encode(&payload);
        assert!(frame[1..frame.len() - 1].contains(&ESCAPE));
        assert_eq!(decode(&frame)?, payload);
        Ok(())
    }

    #[test]
    fn reject_bad_fcs() {
        let mut frame = encode(b"payload");
        let idx = frame.len() - 2;
        frame[idx] ^= 0x01;
        let err = decode(&frame).unwrap_err();
        assert!(err.to_string().contains("FCS mismatch"));
    }

    #[test]
    fn reject_dangling_escape() {
        let err = decode(&[FLAG, 0x00, ESCAPE, FLAG]).unwrap_err();
        assert!(err.to_string().contains("dangling escape"));
    }

    #[test]
    fn reject_missing_flags() {
        let err = decode(&[1, 2, 3, 4]).unwrap_err();
        assert!(err.to_string().contains("opening flag"));
    }
}
