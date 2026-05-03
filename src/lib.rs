use anyhow::{Result, anyhow, bail, ensure};
use aws_lc_rs::{
    encoding::AsDer,
    signature::{ED25519, Ed25519KeyPair},
    signature::{KeyPair, UnparsedPublicKey},
    //unstable::signature::{ML_DSA_65_SIGNING, ML_DSA_87_SIGNING},
    unstable::signature::{ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHello {
    unique: u64,
    // TODO: public ML-DSA key.
    // TODO: public ed25519 key.
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    unique: u64,
    // TODO: public ML-DSA key.
    // TODO: public ed25519 key.
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerComplete {
    server_hello_bytes: Vec<u8>,
    client_hello_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// Server gives parameters, but unsigned.
    ServerHello(ServerHello),

    /// Client gives parameters, signed.
    ///
    /// Signed with connection signer.
    ClientHello(ClientHello),

    /// Server completes the handshake by signing its previous hello and the
    /// client challenge.
    ///
    /// Signed with connection signer.
    ServerComplete(ServerComplete),

    /// Renew packet signing key.
    // Rekey,

    /// User payload in either direction.
    ///
    /// Signed with the packet key.
    Payload(Vec<u8>),
}

const ED25519_SIGNATURE_LEN: usize = 64;
const PACKET_TYPE_SERVER_HELLO: u8 = 0;
const PACKET_TYPE_CLIENT_HELLO: u8 = 1;
const PACKET_TYPE_SERVER_COMPLETE: u8 = 2;
const PACKET_TYPE_PAYLOAD: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signed(Vec<u8>);

impl Packet {
    pub fn serialize(&self, signer: &dyn SignVerify) -> Result<Vec<u8>> {
        match self {
            Packet::ServerHello(ServerHello { unique }) => {
                let mut out = Vec::with_capacity(1 + std::mem::size_of::<u64>());
                out.push(PACKET_TYPE_SERVER_HELLO);
                out.extend(unique.to_be_bytes());
                Ok(out)
            }
            Packet::ClientHello(ClientHello { unique }) => {
                serialize_signed(PACKET_TYPE_CLIENT_HELLO, &unique.to_be_bytes(), signer)
            }
            Packet::ServerComplete(ServerComplete {
                server_hello_bytes,
                client_hello_bytes,
            }) => {
                let mut body = Vec::with_capacity(
                    len_varint_len(server_hello_bytes.len())
                        + server_hello_bytes.len()
                        + client_hello_bytes.len(),
                );
                encode_len(server_hello_bytes.len(), &mut body);
                body.extend(server_hello_bytes);
                body.extend(client_hello_bytes);
                serialize_signed(PACKET_TYPE_SERVER_COMPLETE, &body, signer)
            }
            Packet::Payload(data) => serialize_signed(PACKET_TYPE_PAYLOAD, data, signer),
        }
    }

    pub fn deserialize(
        data: &[u8],
        conn_verifier: &dyn SignVerify,
        packet_verifier: &dyn SignVerify,
    ) -> Result<Self> {
        let (&packet_type, rest) = data
            .split_first()
            .ok_or_else(|| anyhow!("packet is empty"))?;
        match packet_type {
            PACKET_TYPE_SERVER_HELLO => Ok(Packet::ServerHello(ServerHello {
                unique: decode_u64(rest)?,
            })),
            PACKET_TYPE_CLIENT_HELLO => {
                let body = verify_signed(rest, conn_verifier)?;
                Ok(Packet::ClientHello(ClientHello {
                    unique: decode_u64(body.as_ref())?,
                }))
            }
            PACKET_TYPE_SERVER_COMPLETE => {
                let body = verify_signed(rest, conn_verifier)?;
                let (server_hello_len, rest) = decode_len(body.as_ref())?;
                ensure!(
                    rest.len() >= server_hello_len,
                    "server complete truncated: {} < {}",
                    rest.len(),
                    server_hello_len
                );
                let (server_hello_bytes, client_hello_bytes) = rest.split_at(server_hello_len);
                Ok(Packet::ServerComplete(ServerComplete {
                    server_hello_bytes: server_hello_bytes.to_vec(),
                    client_hello_bytes: client_hello_bytes.to_vec(),
                }))
            }
            PACKET_TYPE_PAYLOAD => Ok(Packet::Payload(verify_signed(rest, packet_verifier)?)),
            other => bail!("unknown packet type {other}"),
        }
    }
}

fn serialize_signed(packet_type: u8, body: &[u8], signer: &dyn SignVerify) -> Result<Vec<u8>> {
    let signed = signer.sign(body)?;
    let mut out = Vec::with_capacity(1 + signed.0.len());
    out.push(packet_type);
    out.extend(signed.0);
    Ok(out)
}

fn verify_signed(data: &[u8], verifier: &dyn SignVerify) -> Result<Vec<u8>> {
    let signed = Signed(data.to_vec());
    verifier
        .verify(&signed)
        .map(std::borrow::Cow::into_owned)
        .ok_or_else(|| anyhow!("packet signature verification failed"))
}

fn decode_u64(data: &[u8]) -> Result<u64> {
    let bytes: [u8; std::mem::size_of::<u64>()] = data.try_into().map_err(|_| {
        anyhow!(
            "expected {} bytes, got {}",
            std::mem::size_of::<u64>(),
            data.len()
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    let mut value = len;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_len(data: &[u8]) -> Result<(usize, &[u8])> {
    let mut value = 0usize;
    let mut shift = 0usize;
    for (idx, byte) in data.iter().copied().enumerate() {
        let chunk = usize::from(byte & 0x7f);
        let shifted = chunk
            .checked_shl(shift as u32)
            .ok_or_else(|| anyhow!("length varint overflow"))?;
        value = value
            .checked_add(shifted)
            .ok_or_else(|| anyhow!("length varint overflow"))?;
        if byte & 0x80 == 0 {
            return Ok((value, &data[idx + 1..]));
        }
        shift += 7;
        if shift >= usize::BITS as usize {
            bail!("length varint overflow");
        }
    }
    bail!("truncated length varint")
}

const fn len_varint_len(mut len: usize) -> usize {
    let mut out = 1;
    while len >= 0x80 {
        len >>= 7;
        out += 1;
    }
    out
}

pub trait SignVerify {
    fn sign(&self, data: &[u8]) -> Result<Signed>;
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>>;
}

pub struct PacketSign {
    key_pair: Ed25519KeyPair,
}

impl PacketSign {
    pub fn new() -> Result<Self> {
        let key_pair = Ed25519KeyPair::generate()?;
        Ok(Self { key_pair })
    }
}

impl SignVerify for PacketSign {
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let mut sig = self.key_pair.sign(data).as_ref().to_vec();
        assert_eq!(sig.len(), ED25519_SIGNATURE_LEN);
        sig.extend(data);
        Ok(Signed(sig))
    }
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        if data.0.len() < ED25519_SIGNATURE_LEN {
            return None;
        }
        let alg = &ED25519;
        let (sig, msg) = data.0.split_at(ED25519_SIGNATURE_LEN);

        let public_key = UnparsedPublicKey::new(alg, self.key_pair.public_key().as_ref());
        public_key
            .verify(msg, sig.as_ref())
            .map(|_| std::borrow::Cow::Borrowed(msg))
            .ok()
        //Some(std::borrow::Cow::Borrowed(msg))
    }
}

pub struct ConnSign {
    key_pair: PqdsaKeyPair,
}

impl ConnSign {
    pub fn new() -> Result<Self> {
        let alg = &ML_DSA_44_SIGNING;
        Ok(ConnSign {
            key_pair: PqdsaKeyPair::generate(alg)?,
        })
    }
}

impl SignVerify for ConnSign {
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let alg = &ML_DSA_44_SIGNING;
        let mut sig = vec![0u8; alg.signature_len()];
        let n = self.key_pair.sign(data, &mut sig)?;
        assert_eq!(sig.len(), n);
        sig.truncate(n);
        sig.extend(data);
        Ok(Signed(sig))
    }
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        let alg = &ML_DSA_44;
        let algs = &ML_DSA_44_SIGNING;
        let public_key_der = self
            .key_pair
            .public_key()
            .as_der()
            .expect("failed to get public key");
        let public_key = UnparsedPublicKey::new(alg, public_key_der.as_ref());
        if data.0.len() < algs.signature_len() {
            return None;
        }
        let (sig, msg) = data.0.split_at(algs.signature_len());
        public_key
            .verify(msg, sig)
            .map(|_| std::borrow::Cow::Borrowed(msg))
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify_wire_body(signer: &dyn SignVerify, packet_type: u8, encoded: &[u8], body: &[u8]) {
        assert_eq!(encoded[0], packet_type);
        let signed = Signed(encoded[1..].to_vec());
        let verified = signer.verify(&signed).unwrap();
        assert_eq!(verified.as_ref(), body);
    }

    #[test]
    fn connsign() -> Result<()> {
        let msg = b"hello, world";
        {
            let signer = ConnSign::new()?;
            let signed = signer.sign(msg)?;
            signer.verify(&signed).unwrap();
            Ok(())
        }
    }

    #[test]
    fn packetsign() -> Result<()> {
        let msg = b"hello, world";
        {
            let signer = PacketSign::new()?;
            let signed = signer.sign(msg)?;
            signer.verify(&signed).unwrap();
            Ok(())
        }
    }

    #[test]
    fn packet_round_trip_server_hello() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let packet = Packet::ServerHello(ServerHello {
            unique: 0x0123_4567_89ab_cdef,
        });
        let encoded = packet.serialize(&conn_sign)?;
        assert_eq!(
            Packet::deserialize(&encoded, &conn_sign, &packet_sign)?,
            packet
        );
        Ok(())
    }

    #[test]
    fn packet_round_trip_client_hello() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let packet = Packet::ClientHello(ClientHello { unique: 42 });
        let encoded = packet.serialize(&conn_sign)?;
        verify_wire_body(
            &conn_sign,
            PACKET_TYPE_CLIENT_HELLO,
            &encoded,
            &42u64.to_be_bytes(),
        );
        assert_eq!(
            Packet::deserialize(&encoded, &conn_sign, &packet_sign)?,
            packet
        );
        Ok(())
    }

    #[test]
    fn packet_round_trip_server_complete() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let packet = Packet::ServerComplete(ServerComplete {
            server_hello_bytes: vec![0xaa; 140],
            client_hello_bytes: vec![0xbb; 17],
        });
        let encoded = packet.serialize(&conn_sign)?;
        let mut body = Vec::new();
        encode_len(140, &mut body);
        body.extend(vec![0xaa; 140]);
        body.extend(vec![0xbb; 17]);
        verify_wire_body(&conn_sign, PACKET_TYPE_SERVER_COMPLETE, &encoded, &body);
        assert_eq!(
            Packet::deserialize(&encoded, &conn_sign, &packet_sign)?,
            packet
        );
        Ok(())
    }

    #[test]
    fn packet_round_trip_payload() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let packet = Packet::Payload(vec![1, 2, 3, 4, 5]);
        let encoded = packet.serialize(&packet_sign)?;
        verify_wire_body(
            &packet_sign,
            PACKET_TYPE_PAYLOAD,
            &encoded,
            &[1, 2, 3, 4, 5],
        );
        assert_eq!(
            Packet::deserialize(&encoded, &conn_sign, &packet_sign)?,
            packet
        );
        Ok(())
    }

    #[test]
    fn server_hello_serialize_does_not_sign() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet = Packet::ServerHello(ServerHello { unique: 7 });
        let encoded = packet.serialize(&conn_sign)?;
        assert_eq!(encoded, [PACKET_TYPE_SERVER_HELLO, 0, 0, 0, 0, 0, 0, 0, 7]);
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_truncated_hello() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let err = Packet::deserialize(
            &[PACKET_TYPE_SERVER_HELLO, 1, 2, 3],
            &conn_sign,
            &packet_sign,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected 8 bytes"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_truncated_server_complete() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let body = [5, 1, 2, 3];
        let mut packet = vec![PACKET_TYPE_SERVER_COMPLETE];
        packet.extend(conn_sign.sign(&body)?.0);
        let err = Packet::deserialize(&packet, &conn_sign, &packet_sign).unwrap_err();
        assert!(err.to_string().contains("truncated"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_invalid_signature() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let mut encoded = Packet::Payload(vec![1, 2, 3]).serialize(&packet_sign)?;
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let err = Packet::deserialize(&encoded, &conn_sign, &packet_sign).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
        Ok(())
    }

    #[test]
    fn verify_rejects_short_signatures() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        assert!(
            packet_sign
                .verify(&Signed(vec![0; ED25519_SIGNATURE_LEN - 1]))
                .is_none()
        );

        let conn_sign = ConnSign::new()?;
        assert!(conn_sign.verify(&Signed(vec![])).is_none());
        Ok(())
    }
}
