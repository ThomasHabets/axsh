use anyhow::{Result, anyhow, bail, ensure};

use crate::{
    ConnSign, ConnVerify, ED25519_PUBLIC_KEY_LEN, PacketSign, PacketVerify, SHA256_DIGEST_LEN,
    conn_signature_len,
};

const PACKET_TYPE_SERVER_HELLO: u8 = 0;
pub(crate) const PACKET_TYPE_REQUEST_SERVER_PUBKEY: u8 = 1;
const PACKET_TYPE_SERVER_PUBKEY: u8 = 2;
pub(crate) const PACKET_TYPE_CLIENT_HELLO: u8 = 3;
const PACKET_TYPE_SERVER_COMPLETE: u8 = 4;
const PACKET_TYPE_PAYLOAD: u8 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHello {
    unique: u64,
    conn_sign_public_key_sha256: [u8; SHA256_DIGEST_LEN],
    packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl ServerHello {
    /// Create a server hello with a connection-unique identifier, a server key digest, and a packet key.
    #[must_use]
    pub fn new(
        unique: u64,
        conn_sign_public_key_sha256: [u8; SHA256_DIGEST_LEN],
        packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            unique,
            conn_sign_public_key_sha256,
            packet_sign_public_key,
        }
    }

    /// Return the server's connection-unique identifier.
    #[must_use]
    pub fn unique(&self) -> u64 {
        self.unique
    }

    /// Return the SHA-256 digest of the server's bundled `ConnSign` public key bytes.
    #[must_use]
    pub fn conn_sign_public_key_sha256(&self) -> [u8; SHA256_DIGEST_LEN] {
        self.conn_sign_public_key_sha256
    }

    /// Return the server's Ed25519 public key bytes.
    #[must_use]
    pub fn packet_sign_public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.packet_sign_public_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPubkey(pub(crate) Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    unique: u64,
    conn_sign_public_key_sha256: [u8; SHA256_DIGEST_LEN],
    packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl ClientHello {
    /// Create a client hello with a client challenge, a client key digest, and a packet key.
    #[must_use]
    pub fn new(
        unique: u64,
        conn_sign_public_key_sha256: [u8; SHA256_DIGEST_LEN],
        packet_sign_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            unique,
            conn_sign_public_key_sha256,
            packet_sign_public_key,
        }
    }

    /// Return the client's fresh challenge value.
    #[must_use]
    pub fn unique(&self) -> u64 {
        self.unique
    }

    /// Return the SHA-256 digest of the client's bundled `ConnSign` public key bytes.
    #[must_use]
    pub fn conn_sign_public_key_sha256(&self) -> [u8; SHA256_DIGEST_LEN] {
        self.conn_sign_public_key_sha256
    }

    /// Return the client's Ed25519 public key bytes.
    #[must_use]
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
    #[must_use]
    pub fn new(signature: Vec<u8>) -> Self {
        Self { signature }
    }

    /// Return the detached server transcript signature.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// Server gives parameters, but unsigned.
    ServerHello(ServerHello),

    /// Client requests the server's full `ConnSign` public key, unsigned.
    RequestServerPubkey,

    /// Server provides its full `ConnSign` public key, unsigned.
    ServerPubkey(ServerPubkey),

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

impl Packet {
    /// Serialize an unsigned packet into the wire format.
    ///
    /// `ServerHello`, `RequestServerPubkey`, `ServerPubkey`, and
    /// `ServerComplete` are emitted unsigned.
    ///
    /// `ServerComplete` contains a signature, but its byte contents are not
    /// signed.
    pub fn serialize_unsigned(&self) -> Result<Vec<u8>> {
        match self {
            Packet::ServerHello(hello) => {
                let body = encode_server_hello(hello);
                let mut out = Vec::with_capacity(1 + body.len());
                out.push(PACKET_TYPE_SERVER_HELLO);
                out.extend(body);
                Ok(out)
            }
            Packet::RequestServerPubkey => Ok(vec![PACKET_TYPE_REQUEST_SERVER_PUBKEY]),
            Packet::ServerPubkey(server_pubkey) => {
                let mut out = Vec::with_capacity(1 + server_pubkey.0.len());
                out.push(PACKET_TYPE_SERVER_PUBKEY);
                out.extend(&server_pubkey.0);
                Ok(out)
            }
            Packet::ServerComplete(complete) => {
                let mut out = Vec::with_capacity(1 + complete.signature.len());
                out.push(PACKET_TYPE_SERVER_COMPLETE);
                out.extend(&complete.signature);
                Ok(out)
            }
            Packet::ClientHello(_) => bail!("ClientHello requires a ConnSign signer"),
            Packet::Payload(_) => bail!("Payload requires a PacketSign signer"),
        }
    }

    /// Serialize a `ClientHello` with a `ConnSign` signer and an implicit
    /// server challenge.
    pub fn serialize_conn_signed(&self, signer: &ConnSign, server_unique: u64) -> Result<Vec<u8>> {
        match self {
            Packet::ClientHello(hello) => {
                let body = encode_client_hello(hello);
                serialize_conn_signed(PACKET_TYPE_CLIENT_HELLO, server_unique, &body, signer)
            }
            _ => bail!("only ClientHello uses ConnSign packet signing"),
        }
    }

    /// Serialize a `Payload` with a `PacketSign` signer.
    pub fn serialize_packet_signed(&self, signer: &PacketSign) -> Result<Vec<u8>> {
        match self {
            Packet::Payload(data) => serialize_packet_signed(PACKET_TYPE_PAYLOAD, data, signer),
            _ => bail!("only Payload uses PacketSign packet signing"),
        }
    }

    /// Parse a packet from the wire format, using external verifiers when the
    /// packet does not carry its own verification key.
    pub fn deserialize(
        data: &[u8],
        client_hello_server_unique: Option<u64>,
        conn_verifier: Option<&ConnVerify>,
        packet_verifier: Option<&PacketVerify>,
    ) -> Result<Self> {
        let (&packet_type, rest) = data
            .split_first()
            .ok_or_else(|| anyhow!("packet is empty"))?;
        match packet_type {
            PACKET_TYPE_SERVER_HELLO => Ok(Packet::ServerHello(decode_server_hello(rest)?)),
            PACKET_TYPE_REQUEST_SERVER_PUBKEY => {
                ensure!(rest.is_empty(), "request server pubkey has trailing bytes");
                Ok(Packet::RequestServerPubkey)
            }
            PACKET_TYPE_SERVER_PUBKEY => Ok(Packet::ServerPubkey(ServerPubkey(rest.to_vec()))),
            PACKET_TYPE_CLIENT_HELLO => {
                let hello = Self::peek_client_hello(data)?;
                let server_unique = client_hello_server_unique
                    .ok_or_else(|| anyhow!("missing ClientHello server_unique"))?;
                let verifier = conn_verifier.ok_or_else(|| anyhow!("missing conn verifier"))?;
                verify_conn_signed(rest, server_unique, verifier)?;
                Ok(Packet::ClientHello(hello))
            }
            PACKET_TYPE_SERVER_COMPLETE => {
                Ok(Packet::ServerComplete(decode_server_complete(rest)?))
            }
            PACKET_TYPE_PAYLOAD => {
                let verifier = packet_verifier.ok_or_else(|| anyhow!("missing packet verifier"))?;
                Ok(Packet::Payload(verify_packet_signed(rest, verifier)?))
            }
            other => bail!("unknown packet type {other}"),
        }
    }

    /// Parse a `ClientHello` from wire bytes without verifying its signature.
    pub(crate) fn peek_client_hello(data: &[u8]) -> Result<ClientHello> {
        let (&packet_type, rest) = data
            .split_first()
            .ok_or_else(|| anyhow!("packet is empty"))?;
        ensure!(
            packet_type == PACKET_TYPE_CLIENT_HELLO,
            "expected ClientHello, got packet type {packet_type}"
        );
        let body = signed_message(rest, conn_signature_len())?;
        decode_client_hello(body)
    }

    /// Return the packet type byte from wire bytes.
    pub(crate) fn peek_type(data: &[u8]) -> Result<u8> {
        data.first()
            .copied()
            .ok_or_else(|| anyhow!("packet is empty"))
    }
}

/// Sign a connection-authenticated packet body and prefix the packet type byte.
fn serialize_conn_signed(
    packet_type: u8,
    server_unique: u64,
    body: &[u8],
    signer: &ConnSign,
) -> Result<Vec<u8>> {
    let signed = signer.sign_prefixed(&server_unique.to_be_bytes(), body)?;
    let mut out = Vec::with_capacity(1 + signed.len());
    out.push(packet_type);
    out.extend(signed);
    Ok(out)
}

/// Sign a payload packet body and prefix the packet type byte.
fn serialize_packet_signed(packet_type: u8, body: &[u8], signer: &PacketSign) -> Result<Vec<u8>> {
    let signed = signer.sign(body)?;
    let mut out = Vec::with_capacity(1 + signed.len());
    out.push(packet_type);
    out.extend(signed);
    Ok(out)
}

/// Verify a connection-authenticated wire body and return owned message bytes
/// for further parsing.
fn verify_conn_signed(data: &[u8], server_unique: u64, verifier: &ConnVerify) -> Result<Vec<u8>> {
    verifier
        .verify_prefixed(&server_unique.to_be_bytes(), data)
        .map(std::borrow::Cow::into_owned)
        .ok_or_else(|| anyhow!("packet signature verification failed"))
}

/// Verify a payload wire body and return owned message bytes for further
/// parsing.
fn verify_packet_signed(data: &[u8], verifier: &PacketVerify) -> Result<Vec<u8>> {
    verifier
        .verify(data)
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
#[must_use]
fn encode_server_hello(hello: &ServerHello) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(std::mem::size_of::<u64>() + SHA256_DIGEST_LEN + ED25519_PUBLIC_KEY_LEN);
    out.extend(hello.unique.to_be_bytes());
    out.extend(hello.conn_sign_public_key_sha256);
    out.extend(hello.packet_sign_public_key);
    out
}

/// Decode a server hello body.
fn decode_server_hello(data: &[u8]) -> Result<ServerHello> {
    let (unique, rest) = take_u64(data)?;
    let (conn_sign_public_key_sha256, rest) = take_fixed::<SHA256_DIGEST_LEN>(rest)?;
    let (packet_sign_public_key, rest) = take_fixed::<ED25519_PUBLIC_KEY_LEN>(rest)?;
    ensure!(rest.is_empty(), "server hello has trailing bytes");
    Ok(ServerHello::new(
        unique,
        conn_sign_public_key_sha256,
        packet_sign_public_key,
    ))
}

/// Encode a client hello body with the client challenge and both public keys.
#[must_use]
fn encode_client_hello(hello: &ClientHello) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(std::mem::size_of::<u64>() + SHA256_DIGEST_LEN + ED25519_PUBLIC_KEY_LEN);
    out.extend(hello.unique.to_be_bytes());
    out.extend(hello.conn_sign_public_key_sha256);
    out.extend(hello.packet_sign_public_key);
    out
}

/// Decode a client hello body.
fn decode_client_hello(data: &[u8]) -> Result<ClientHello> {
    let (unique, rest) = take_u64(data)?;
    let (conn_sign_public_key_sha256, rest) = take_fixed::<SHA256_DIGEST_LEN>(rest)?;
    let (packet_sign_public_key, rest) = take_fixed::<ED25519_PUBLIC_KEY_LEN>(rest)?;
    ensure!(rest.is_empty(), "client hello has trailing bytes");
    Ok(ClientHello::new(
        unique,
        conn_sign_public_key_sha256,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConnSign, ConnVerify, ED25519_SIGNATURE_LEN, PacketSign, PacketVerify, sha256_bytes,
    };

    fn test_server_hello(conn_sign: &ConnSign, packet_sign: &PacketSign) -> Result<ServerHello> {
        let conn_sign_public_key = conn_sign.public_key_bytes()?;
        Ok(ServerHello::new(
            0x0123_4567_89ab_cdef,
            sha256_bytes(&conn_sign_public_key),
            packet_sign.public_key_bytes(),
        ))
    }

    fn test_client_hello(conn_sign: &ConnSign, packet_sign: &PacketSign) -> Result<ClientHello> {
        let conn_sign_public_key = conn_sign.public_key_bytes()?;
        Ok(ClientHello::new(
            0x0123_4567_89ab_cdef,
            sha256_bytes(&conn_sign_public_key),
            packet_sign.public_key_bytes(),
        ))
    }

    /// Verify that a connection-authenticated body is signed correctly.
    fn verify_conn_wire_body(
        verifier: &ConnVerify,
        server_unique: u64,
        packet_type: u8,
        encoded: &[u8],
        body: &[u8],
    ) {
        assert_eq!(encoded[0], packet_type);
        let verified = verifier
            .verify_prefixed(&server_unique.to_be_bytes(), &encoded[1..])
            .unwrap();
        assert_eq!(verified.as_ref(), body);
    }

    /// Verify that a payload body is signed correctly.
    fn verify_packet_wire_body(
        verifier: &PacketVerify,
        packet_type: u8,
        encoded: &[u8],
        body: &[u8],
    ) {
        assert_eq!(encoded[0], packet_type);
        let verified = verifier.verify(&encoded[1..]).unwrap();
        assert_eq!(verified.as_ref(), body);
    }

    #[test]
    fn connsign() -> Result<()> {
        let msg = b"hello, world";
        let signer = ConnSign::new()?;
        let signed = signer.sign(msg)?;
        signer.verifier()?.verify(&signed).unwrap();
        Ok(())
    }

    #[test]
    fn packetsign() -> Result<()> {
        let msg = b"hello, world";
        let signer = PacketSign::new()?;
        let signed = signer.sign(msg)?;
        signer.verifier().verify(&signed).unwrap();
        Ok(())
    }

    #[test]
    fn public_only_verifiers() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let conn_verify = conn_sign.verifier()?;
        let packet_verify = packet_sign.verifier();

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
        let encoded = packet.serialize_unsigned()?;
        assert_eq!(Packet::deserialize(&encoded, None, None, None)?, packet);
        Ok(())
    }

    #[test]
    fn packet_round_trip_request_server_pubkey() -> Result<()> {
        let encoded = Packet::RequestServerPubkey.serialize_unsigned()?;
        assert_eq!(
            Packet::deserialize(&encoded, None, None, None)?,
            Packet::RequestServerPubkey
        );
        Ok(())
    }

    #[test]
    fn packet_round_trip_server_pubkey() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet = Packet::ServerPubkey(ServerPubkey(conn_sign.public_key_bytes()?.clone()));
        let encoded = packet.serialize_unsigned()?;
        assert_eq!(Packet::deserialize(&encoded, None, None, None)?, packet);
        Ok(())
    }

    #[test]
    fn packet_round_trip_client_hello() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let conn_verify = conn_sign.verifier()?;
        let server_unique = 0xfeed_face_cafe_babe;
        let hello = test_client_hello(&conn_sign, &packet_sign)?;
        let packet = Packet::ClientHello(hello.clone());
        let encoded = packet.serialize_conn_signed(&conn_sign, server_unique)?;
        verify_conn_wire_body(
            &conn_verify,
            server_unique,
            PACKET_TYPE_CLIENT_HELLO,
            &encoded,
            &encode_client_hello(&hello),
        );
        assert_eq!(
            Packet::deserialize(&encoded, Some(server_unique), Some(&conn_verify), None)?,
            packet
        );
        Ok(())
    }

    #[test]
    fn client_hello_rejects_wrong_server_unique() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let packet_sign = PacketSign::new()?;
        let conn_verify = conn_sign.verifier()?;
        let packet = Packet::ClientHello(test_client_hello(&conn_sign, &packet_sign)?);
        let encoded = packet.serialize_conn_signed(&conn_sign, 0xfeed_face_cafe_babe)?;
        let err = Packet::deserialize(
            &encoded,
            Some(0x0123_4567_89ab_cdef),
            Some(&conn_verify),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
        Ok(())
    }

    #[test]
    fn packet_round_trip_server_complete() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let signature = conn_sign.sign_detached(b"server-hello||client-hello")?;
        let packet = Packet::ServerComplete(ServerComplete::new(signature.clone()));
        let encoded = packet.serialize_unsigned()?;
        assert_eq!(encoded[0], PACKET_TYPE_SERVER_COMPLETE);
        assert_eq!(&encoded[1..], signature.as_slice());
        assert_eq!(Packet::deserialize(&encoded, None, None, None)?, packet);
        Ok(())
    }

    #[test]
    fn packet_round_trip_payload() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let packet_verify = packet_sign.verifier();
        let packet = Packet::Payload(vec![1, 2, 3, 4, 5]);
        let encoded = packet.serialize_packet_signed(&packet_sign)?;
        verify_packet_wire_body(
            &packet_verify,
            PACKET_TYPE_PAYLOAD,
            &encoded,
            &[1, 2, 3, 4, 5],
        );
        assert_eq!(
            Packet::deserialize(&encoded, None, None, Some(&packet_sign.verifier()))?,
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
        let encoded = packet.serialize_unsigned()?;
        let mut expected = vec![PACKET_TYPE_SERVER_HELLO];
        expected.extend(encode_server_hello(&hello));
        assert_eq!(encoded, expected);
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_truncated_hello() {
        let err = Packet::deserialize(&[PACKET_TYPE_SERVER_HELLO, 1, 2, 3], None, None, None)
            .unwrap_err();
        assert!(err.to_string().contains("expected at least 8 bytes"));
    }

    #[test]
    fn packet_deserialize_rejects_truncated_server_complete() -> Result<()> {
        let conn_sign = ConnSign::new()?;
        let mut signature = conn_sign.sign_detached(b"server-hello||client-hello")?;
        signature.pop();
        let mut packet = vec![PACKET_TYPE_SERVER_COMPLETE];
        packet.extend(signature);
        let err = Packet::deserialize(&packet, None, None, None).unwrap_err();
        assert!(err.to_string().contains("signature length"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_invalid_signature() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let mut encoded = Packet::Payload(vec![1, 2, 3]).serialize_packet_signed(&packet_sign)?;
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let verifier = packet_sign.verifier();
        let err = Packet::deserialize(&encoded, None, None, Some(&verifier)).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_requires_payload_verifier() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let encoded = Packet::Payload(vec![1, 2, 3]).serialize_packet_signed(&packet_sign)?;
        let err = Packet::deserialize(&encoded, None, None, None).unwrap_err();
        assert!(err.to_string().contains("missing packet verifier"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_replayed_payload() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let packet_verify = packet_sign.verifier();
        let encoded = Packet::Payload(vec![1, 2, 3]).serialize_packet_signed(&packet_sign)?;

        assert_eq!(
            Packet::deserialize(&encoded, None, None, Some(&packet_verify))?,
            Packet::Payload(vec![1, 2, 3])
        );

        let err = Packet::deserialize(&encoded, None, None, Some(&packet_verify)).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
        Ok(())
    }

    #[test]
    fn packet_deserialize_rejects_out_of_order_payload() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        let packet_verify = packet_sign.verifier();
        let first = Packet::Payload(vec![1]).serialize_packet_signed(&packet_sign)?;
        let second = Packet::Payload(vec![2]).serialize_packet_signed(&packet_sign)?;

        let err = Packet::deserialize(&second, None, None, Some(&packet_verify)).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));

        assert_eq!(
            Packet::deserialize(&first, None, None, Some(&packet_verify))?,
            Packet::Payload(vec![1])
        );
        Ok(())
    }

    #[test]
    fn verify_rejects_short_signatures() -> Result<()> {
        let packet_sign = PacketSign::new()?;
        assert!(
            packet_sign
                .verifier()
                .verify(&[0; ED25519_SIGNATURE_LEN - 1])
                .is_none()
        );

        let conn_sign = ConnSign::new()?;
        assert!(conn_sign.verifier()?.verify(&[]).is_none());
        Ok(())
    }
}
