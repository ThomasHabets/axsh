use anyhow::{Result, anyhow, bail, ensure};

use crate::{ConnVerify, ED25519_PUBLIC_KEY_LEN, conn_signature_len};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHello {
    unique: u64,
    conn_sign_public_key: Vec<u8>,
    packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl ServerHello {
    /// Create a server hello with a connection-unique identifier and public keys.
    pub fn new(
        unique: u64,
        conn_sign_public_key: Vec<u8>,
        packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            unique,
            conn_sign_public_key,
            packet_sign_public_key,
        }
    }

    /// Return the server's connection-unique identifier.
    pub fn unique(&self) -> u64 {
        self.unique
    }

    /// Return the server's bundled ConnSign public key bytes.
    pub fn conn_sign_public_key(&self) -> &[u8] {
        &self.conn_sign_public_key
    }

    /// Return the server's Ed25519 public key bytes.
    pub fn packet_sign_public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.packet_sign_public_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    server_unique: u64,
    unique: u64,
    conn_sign_public_key: Vec<u8>,
    packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl ClientHello {
    /// Create a client hello with both hello challenges and public keys.
    pub fn new(
        server_unique: u64,
        unique: u64,
        conn_sign_public_key: Vec<u8>,
        packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            server_unique,
            unique,
            conn_sign_public_key,
            packet_sign_public_key,
        }
    }

    /// Return the echoed server challenge.
    pub fn server_unique(&self) -> u64 {
        self.server_unique
    }

    /// Return the client's fresh challenge value.
    pub fn unique(&self) -> u64 {
        self.unique
    }

    /// Return the client's bundled ConnSign public key bytes.
    pub fn conn_sign_public_key(&self) -> &[u8] {
        &self.conn_sign_public_key
    }

    /// Return the client's Ed25519 public key bytes.
    pub fn packet_sign_public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.packet_sign_public_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerComplete {
    signature: Vec<u8>,
}

impl ServerComplete {
    /// Create a server-complete packet body from a detached transcript signature.
    pub fn new(signature: Vec<u8>) -> Self {
        Self { signature }
    }

    /// Return the detached server transcript signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// Server gives parameters, but unsigned.
    ServerHello(ServerHello),

    /// Client gives parameters, signed.
    ///
    /// Signed with connection signer.
    ClientHello(ClientHello),

    /// Server completes the handshake with a detached signature over the
    /// concatenated `ServerHello` and `ClientHello` packet bytes.
    ServerComplete(ServerComplete),

    /// Renew packet signing key.
    // Rekey,

    /// User payload in either direction.
    ///
    /// Signed with the packet key.
    Payload(Vec<u8>),
}

const PACKET_TYPE_SERVER_HELLO: u8 = 0;
const PACKET_TYPE_CLIENT_HELLO: u8 = 1;
const PACKET_TYPE_SERVER_COMPLETE: u8 = 2;
const PACKET_TYPE_PAYLOAD: u8 = 3;

/// Signed wire bytes: signature material first, followed by the original
/// message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signed(pub(crate) Vec<u8>);

/// Packet serialization uses this abstraction so handshake packets and payload
/// packets can be signed with different key types.
pub trait SignVerify {
    /// Produce signed wire bytes for `data`.
    fn sign(&self, data: &[u8]) -> Result<Signed>;

    /// Verify signed wire bytes and return the recovered message.
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>>;
}

impl Packet {
    /// Serialize a packet into the wire format.
    ///
    /// `ServerHello` is emitted unsigned. `ServerComplete` carries only a
    /// detached transcript signature. `ClientHello` and `Payload` sign only
    /// the bytes after the packet type byte.
    pub fn serialize(&self, signer: &dyn SignVerify) -> Result<Vec<u8>> {
        match self {
            Packet::ServerHello(hello) => {
                let body = encode_server_hello(hello);
                let mut out = Vec::with_capacity(1 + body.len());
                out.push(PACKET_TYPE_SERVER_HELLO);
                out.extend(body);
                Ok(out)
            }
            Packet::ClientHello(hello) => {
                let body = encode_client_hello(hello);
                serialize_signed(PACKET_TYPE_CLIENT_HELLO, &body, signer)
            }
            Packet::ServerComplete(complete) => {
                let mut out = Vec::with_capacity(1 + complete.signature.len());
                out.push(PACKET_TYPE_SERVER_COMPLETE);
                out.extend(&complete.signature);
                Ok(out)
            }
            Packet::Payload(data) => serialize_signed(PACKET_TYPE_PAYLOAD, data, signer),
        }
    }

    /// Parse a packet from the wire format, using external verifiers when the
    /// packet does not carry its own verification key.
    pub fn deserialize(
        data: &[u8],
        _conn_verifier: Option<&dyn SignVerify>,
        packet_verifier: Option<&dyn SignVerify>,
    ) -> Result<Self> {
        let (&packet_type, rest) = data
            .split_first()
            .ok_or_else(|| anyhow!("packet is empty"))?;
        match packet_type {
            PACKET_TYPE_SERVER_HELLO => Ok(Packet::ServerHello(decode_server_hello(rest)?)),
            PACKET_TYPE_CLIENT_HELLO => {
                let body = signed_message(rest, conn_signature_len())?;
                let hello = decode_client_hello(body)?;
                let verifier = ConnVerify::new(hello.conn_sign_public_key().to_vec());
                verify_signed(rest, &verifier)?;
                Ok(Packet::ClientHello(hello))
            }
            PACKET_TYPE_SERVER_COMPLETE => {
                Ok(Packet::ServerComplete(decode_server_complete(rest)?))
            }
            PACKET_TYPE_PAYLOAD => {
                let verifier = packet_verifier.ok_or_else(|| anyhow!("missing packet verifier"))?;
                Ok(Packet::Payload(verify_signed(rest, verifier)?))
            }
            other => bail!("unknown packet type {other}"),
        }
    }
}

/// Sign a packet body and prefix the packet type byte.
fn serialize_signed(packet_type: u8, body: &[u8], signer: &dyn SignVerify) -> Result<Vec<u8>> {
    let signed = signer.sign(body)?;
    let mut out = Vec::with_capacity(1 + signed.0.len());
    out.push(packet_type);
    out.extend(signed.0);
    Ok(out)
}

/// Verify a signed wire body and return owned message bytes for further
/// parsing.
fn verify_signed(data: &[u8], verifier: &dyn SignVerify) -> Result<Vec<u8>> {
    let signed = Signed(data.to_vec());
    verifier
        .verify(&signed)
        .map(std::borrow::Cow::into_owned)
        .ok_or_else(|| anyhow!("packet signature verification failed"))
}

/// Return the signed message portion after a fixed-width signature.
fn signed_message(data: &[u8], signature_len: usize) -> Result<&[u8]> {
    ensure!(
        data.len() >= signature_len,
        "signed packet truncated: {} < {}",
        data.len(),
        signature_len
    );
    Ok(&data[signature_len..])
}

/// Encode a server hello body with the server challenge and both public keys.
fn encode_server_hello(hello: &ServerHello) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        std::mem::size_of::<u64>()
            + len_varint_len(hello.conn_sign_public_key.len())
            + hello.conn_sign_public_key.len()
            + ED25519_PUBLIC_KEY_LEN,
    );
    out.extend(hello.unique.to_be_bytes());
    encode_len(hello.conn_sign_public_key.len(), &mut out);
    out.extend(&hello.conn_sign_public_key);
    out.extend(hello.packet_sign_public_key);
    out
}

/// Decode a server hello body.
fn decode_server_hello(data: &[u8]) -> Result<ServerHello> {
    let (unique, rest) = take_u64(data)?;
    let (conn_sign_public_key, rest) = take_len_prefixed(rest)?;
    let (packet_sign_public_key, rest) = take_fixed::<ED25519_PUBLIC_KEY_LEN>(rest)?;
    ensure!(rest.is_empty(), "server hello has trailing bytes");
    Ok(ServerHello::new(
        unique,
        conn_sign_public_key,
        packet_sign_public_key,
    ))
}

/// Encode a client hello body with both challenges and both public keys.
fn encode_client_hello(hello: &ClientHello) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        2 * std::mem::size_of::<u64>()
            + len_varint_len(hello.conn_sign_public_key.len())
            + hello.conn_sign_public_key.len()
            + ED25519_PUBLIC_KEY_LEN,
    );
    out.extend(hello.server_unique.to_be_bytes());
    out.extend(hello.unique.to_be_bytes());
    encode_len(hello.conn_sign_public_key.len(), &mut out);
    out.extend(&hello.conn_sign_public_key);
    out.extend(hello.packet_sign_public_key);
    out
}

/// Decode a client hello body.
fn decode_client_hello(data: &[u8]) -> Result<ClientHello> {
    let (server_unique, rest) = take_u64(data)?;
    let (unique, rest) = take_u64(rest)?;
    let (conn_sign_public_key, rest) = take_len_prefixed(rest)?;
    let (packet_sign_public_key, rest) = take_fixed::<ED25519_PUBLIC_KEY_LEN>(rest)?;
    ensure!(rest.is_empty(), "client hello has trailing bytes");
    Ok(ClientHello::new(
        server_unique,
        unique,
        conn_sign_public_key,
        packet_sign_public_key,
    ))
}

/// Decode a detached server-complete signature payload.
fn decode_server_complete(data: &[u8]) -> Result<ServerComplete> {
    ensure!(
        data.len() == conn_signature_len(),
        "server complete signature length {} != {}",
        data.len(),
        conn_signature_len()
    );
    Ok(ServerComplete::new(data.to_vec()))
}

/// Decode a fixed-width, big-endian `u64` and return the remaining bytes.
fn take_u64(data: &[u8]) -> Result<(u64, &[u8])> {
    ensure!(
        data.len() >= std::mem::size_of::<u64>(),
        "expected at least {} bytes, got {}",
        std::mem::size_of::<u64>(),
        data.len()
    );
    let (head, rest) = data.split_at(std::mem::size_of::<u64>());
    let bytes: [u8; std::mem::size_of::<u64>()] = head
        .try_into()
        .map_err(|_| anyhow!("failed to decode u64"))?;
    Ok((u64::from_be_bytes(bytes), rest))
}

/// Take a fixed-width byte array and return the remaining bytes.
fn take_fixed<const N: usize>(data: &[u8]) -> Result<([u8; N], &[u8])> {
    ensure!(
        data.len() >= N,
        "expected at least {} bytes, got {}",
        N,
        data.len()
    );
    let (head, rest) = data.split_at(N);
    let bytes: [u8; N] = head
        .try_into()
        .map_err(|_| anyhow!("failed to decode fixed-width bytes"))?;
    Ok((bytes, rest))
}

/// Take a length-prefixed byte vector and return the remaining bytes.
fn take_len_prefixed(data: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    let (len, rest) = decode_len(data)?;
    ensure!(
        rest.len() >= len,
        "length-prefixed field truncated: {} < {}",
        rest.len(),
        len
    );
    let (field, rest) = rest.split_at(len);
    Ok((field.to_vec(), rest))
}

/// Encode a length with a tight base-128 varint.
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

/// Decode the base-128 varint used by length-prefixed fields.
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

/// Calculate the encoded varint size so serialization can reserve once.
const fn len_varint_len(mut len: usize) -> usize {
    let mut out = 1;
    while len >= 0x80 {
        len >>= 7;
        out += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnSign, ConnVerify, ED25519_SIGNATURE_LEN, PacketSign, PacketVerify};

    fn test_server_hello(conn_sign: &ConnSign, packet_sign: &PacketSign) -> Result<ServerHello> {
        Ok(ServerHello::new(
            0x0123_4567_89ab_cdef,
            conn_sign.public_key_bytes()?,
            packet_sign.public_key_bytes(),
        ))
    }

    fn test_client_hello(conn_sign: &ConnSign, packet_sign: &PacketSign) -> Result<ClientHello> {
        Ok(ClientHello::new(
            0xfeed_face_cafe_babe,
            0x0123_4567_89ab_cdef,
            conn_sign.public_key_bytes()?,
            packet_sign.public_key_bytes(),
        ))
    }

    /// Verify that the encoded body is signed correctly and recover the expected plaintext bytes.
    fn verify_wire_body(verifier: &dyn SignVerify, packet_type: u8, encoded: &[u8], body: &[u8]) {
        assert_eq!(encoded[0], packet_type);
        let signed = Signed(encoded[1..].to_vec());
        let verified = verifier.verify(&signed).unwrap();
        assert_eq!(verified.as_ref(), body);
    }

    #[test]
    fn connsign() -> Result<()> {
        let msg = b"hello, world";
        let signer = ConnSign::new()?;
        let signed = signer.sign(msg)?;
        signer.verify(&signed).unwrap();
        Ok(())
    }

    #[test]
    fn packetsign() -> Result<()> {
        let msg = b"hello, world";
        let signer = PacketSign::new()?;
        let signed = signer.sign(msg)?;
        signer.verify(&signed).unwrap();
        Ok(())
    }

    #[test]
    fn public_only_verifiers() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let conn_verify = ConnVerify::new(conn_sign.public_key_bytes()?);
        let packet_verify = PacketVerify::new(packet_sign.public_key_bytes());

        let conn_signed = conn_sign.sign(b"conn-msg")?;
        let packet_signed = packet_sign.sign(b"packet-msg")?;
        let conn_detached = conn_sign.sign_detached(b"conn-msg")?;

        assert_eq!(
            conn_verify.verify(&conn_signed).unwrap().as_ref(),
            b"conn-msg"
        );
        assert!(conn_verify.verify_detached(&conn_detached, b"conn-msg"));
        assert_eq!(
            packet_verify.verify(&packet_signed).unwrap().as_ref(),
            b"packet-msg"
        );
        Ok(())
    }

    #[test]
    fn packet_round_trip_server_hello() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let packet = Packet::ServerHello(test_server_hello(&conn_sign, &packet_sign)?);
        let encoded = packet.serialize(&conn_sign)?;
        assert_eq!(Packet::deserialize(&encoded, None, None)?, packet);
        Ok(())
    }

    #[test]
    fn packet_round_trip_client_hello() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let hello = test_client_hello(&conn_sign, &packet_sign)?;
        let packet = Packet::ClientHello(hello.clone());
        let encoded = packet.serialize(&conn_sign)?;
        verify_wire_body(
            &conn_sign,
            PACKET_TYPE_CLIENT_HELLO,
            &encoded,
            &encode_client_hello(&hello),
        );
        assert_eq!(Packet::deserialize(&encoded, None, None)?, packet);
        Ok(())
    }

    #[test]
    fn packet_round_trip_server_complete() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let signature = conn_sign.sign_detached(b"server-hello||client-hello")?;
        let packet = Packet::ServerComplete(ServerComplete::new(signature.clone()));
        let encoded = packet.serialize(&conn_sign)?;
        assert_eq!(encoded[0], PACKET_TYPE_SERVER_COMPLETE);
        assert_eq!(&encoded[1..], signature.as_slice());
        assert_eq!(Packet::deserialize(&encoded, None, None)?, packet);
        Ok(())
    }

    #[test]
    fn packet_round_trip_payload() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let packet_verify = PacketVerify::new(packet_sign.public_key_bytes());
        let packet = Packet::Payload(vec![1, 2, 3, 4, 5]);
        let encoded = packet.serialize(&packet_sign)?;
        verify_wire_body(
            &packet_verify,
            PACKET_TYPE_PAYLOAD,
            &encoded,
            &[1, 2, 3, 4, 5],
        );
        assert_eq!(
            Packet::deserialize(
                &encoded,
                None,
                Some(&PacketVerify::new(packet_sign.public_key_bytes()))
            )?,
            packet
        );
        Ok(())
    }

    #[test]
    fn server_hello_serialize_does_not_sign() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let hello = test_server_hello(&conn_sign, &packet_sign)?;
        let packet = Packet::ServerHello(hello.clone());
        let encoded = packet.serialize(&conn_sign)?;
        let mut expected = vec![PACKET_TYPE_SERVER_HELLO];
        expected.extend(encode_server_hello(&hello));
        assert_eq!(encoded, expected);
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_truncated_hello() -> Result<()> {
        let err =
            Packet::deserialize(&[PACKET_TYPE_SERVER_HELLO, 1, 2, 3], None, None).unwrap_err();
        assert!(err.to_string().contains("expected at least 8 bytes"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_truncated_server_complete() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let mut signature = conn_sign.sign_detached(b"server-hello||client-hello")?;
        signature.pop();
        let mut packet = vec![PACKET_TYPE_SERVER_COMPLETE];
        packet.extend(signature);
        let err = Packet::deserialize(&packet, None, None).unwrap_err();
        assert!(err.to_string().contains("signature length"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_invalid_signature() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let mut encoded = Packet::Payload(vec![1, 2, 3]).serialize(&packet_sign)?;
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let err = Packet::deserialize(&encoded, None, Some(&packet_sign)).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_requires_payload_verifier() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let encoded = Packet::Payload(vec![1, 2, 3]).serialize(&packet_sign)?;
        let err = Packet::deserialize(&encoded, None, None).unwrap_err();
        assert!(err.to_string().contains("missing packet verifier"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_replayed_payload() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let packet_verify = PacketVerify::new(packet_sign.public_key_bytes());
        let encoded = Packet::Payload(vec![1, 2, 3]).serialize(&packet_sign)?;

        assert_eq!(
            Packet::deserialize(&encoded, None, Some(&packet_verify))?,
            Packet::Payload(vec![1, 2, 3])
        );

        let err = Packet::deserialize(&encoded, None, Some(&packet_verify)).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_out_of_order_payload() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let packet_verify = PacketVerify::new(packet_sign.public_key_bytes());
        let first = Packet::Payload(vec![1]).serialize(&packet_sign)?;
        let second = Packet::Payload(vec![2]).serialize(&packet_sign)?;

        let err = Packet::deserialize(&second, None, Some(&packet_verify)).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));

        assert_eq!(
            Packet::deserialize(&first, None, Some(&packet_verify))?,
            Packet::Payload(vec![1])
        );
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
