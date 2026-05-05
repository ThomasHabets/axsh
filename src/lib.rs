#![allow(clippy::similar_names)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

// TODO: replace with thiserror.
use std::cell::Cell;

use anyhow::{Result, bail};
use aws_lc_rs::{
    digest,
    encoding::AsDer,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
    unstable::signature::{ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair},
};
use clap::ValueEnum;

mod base64;
mod client;
pub mod hdlc;
mod packet;
mod server;
mod transport;
pub use base64::{decode_base64, encode_base64};
pub use client::ClientStream;
pub use packet::{ClientHello, Packet, ServerComplete, ServerHello, SignVerify, Signed};
pub use server::ServerStream;

pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
const CONN_PUBLIC_KEY_VERSION: u8 = 1;
const CONN_PRIVATE_KEY_MAGIC: &[u8; 8] = b"AXSHCK02";
pub const CONN_AUTHORIZED_KEY_KIND: &str = "mldsa-ed25519";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[must_use]
pub(crate) fn conn_signature_len() -> usize {
    ML_DSA_44_SIGNING.signature_len() + ED25519_SIGNATURE_LEN
}

pub(crate) fn random_u64() -> std::io::Result<u64> {
    let mut bytes = [0u8; 8];
    let mut file = std::fs::File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut file, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Initialize stderr logging with the requested log level.
pub fn init_logging(level: LogLevel) -> Result<()> {
    stderrlog::new()
        .verbosity(level as usize)
        .init()
        .map_err(|e| anyhow::anyhow!("failed to initialize logging: {e}"))
}

/// Format a `ConnSign` public key for authorized-keys files.
#[must_use]
pub fn format_authorized_conn_key(public_key: &[u8]) -> String {
    format!("{CONN_AUTHORIZED_KEY_KIND} {}", encode_base64(public_key))
}

/// Parse one authorized-keys line for a `ConnSign` public key.
pub fn parse_authorized_conn_key(line: &str) -> Result<Vec<u8>> {
    let (kind, encoded) = line
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("missing key type or key data"))?;
    if kind != CONN_AUTHORIZED_KEY_KIND {
        bail!("unsupported key type {kind}");
    }
    if encoded.is_empty() {
        bail!("missing key data");
    }
    decode_base64(encoded)
}

/// Format one known-hosts line for a host and `ConnSign` public key.
#[must_use]
pub fn format_known_host(host: &str, public_key: &[u8]) -> String {
    format!("{host} {}", format_authorized_conn_key(public_key))
}

/// Parse one known-hosts line into a host and `ConnSign` public key.
pub fn parse_known_host(line: &str) -> Result<(String, Vec<u8>)> {
    let (host, key) = line
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("missing host or key data"))?;
    if host.is_empty() {
        bail!("missing host");
    }
    Ok((host.to_string(), parse_authorized_conn_key(key)?))
}

/// Format a SHA-256 fingerprint string for bytes in OpenSSH style.
#[must_use]
pub fn format_sha256_fingerprint(data: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, data);
    let encoded = encode_base64(digest.as_ref());
    format!("SHA256:{}", encoded.trim_end_matches('='))
}

/// Prefix the implicit payload packet counter to bytes for signing.
#[must_use]
fn packet_signature_input(counter: u64, data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(std::mem::size_of::<u64>() + data.len());
    input.extend(counter.to_be_bytes());
    input.extend(data);
    input
}

pub struct PacketSign {
    key_pair: Ed25519KeyPair,
    sign_counter: Cell<u64>,
    verify_counter: Cell<u64>,
}

impl PacketSign {
    /// Generate a fresh Ed25519 keypair for payload packet signing.
    pub fn new() -> Result<Self> {
        let key_pair = Ed25519KeyPair::generate()?;
        Ok(Self {
            key_pair,
            sign_counter: Cell::new(0),
            verify_counter: Cell::new(0),
        })
    }

    /// Return the Ed25519 public key bytes for this signer.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("unexpected Ed25519 public key length")
    }
}

impl SignVerify for PacketSign {
    /// Prepend the fixed-size Ed25519 signature over the next implicit counter and the message bytes.
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let counter = self.sign_counter.get();
        let input = packet_signature_input(counter, data);
        let mut sig = self.key_pair.sign(&input).as_ref().to_vec();
        assert_eq!(sig.len(), ED25519_SIGNATURE_LEN);
        sig.extend(data);
        self.sign_counter.set(counter + 1);
        Ok(Signed(sig))
    }

    /// Split the signature back off the wire bytes and verify it with the next implicit counter.
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        if data.0.len() < ED25519_SIGNATURE_LEN {
            return None;
        }
        let alg = &ED25519;
        let (sig, msg) = data.0.split_at(ED25519_SIGNATURE_LEN);
        let counter = self.verify_counter.get();
        let input = packet_signature_input(counter, msg);

        let public_key = UnparsedPublicKey::new(alg, self.key_pair.public_key().as_ref());
        public_key
            .verify(&input, sig.as_ref())
            .map(|()| {
                self.verify_counter.set(counter + 1);
                std::borrow::Cow::Borrowed(msg)
            })
            .ok()
    }
}

pub struct ConnSign {
    ml_dsa_key_pair: PqdsaKeyPair,
    ed25519_key_pair: Ed25519KeyPair,
    ml_dsa_pkcs8: Vec<u8>,
    ed25519_pkcs8: Vec<u8>,
}

impl ConnSign {
    /// Generate a fresh `ConnSign` key with independent ML-DSA and Ed25519 signing keys.
    pub fn new() -> Result<Self> {
        let alg = &ML_DSA_44_SIGNING;
        let ml_dsa_key_pair = PqdsaKeyPair::generate(alg)?;
        let ml_dsa_pkcs8 = ml_dsa_key_pair.to_pkcs8()?.as_ref().to_vec();
        let ed25519_key_pair = Ed25519KeyPair::generate()?;
        let ed25519_pkcs8 = ed25519_key_pair.to_pkcs8v1()?.as_ref().to_vec();
        Ok(ConnSign {
            ml_dsa_key_pair,
            ed25519_key_pair,
            ml_dsa_pkcs8,
            ed25519_pkcs8,
        })
    }

    /// Load a `ConnSign` key bundle from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ml_dsa_pkcs8, ed25519_pkcs8) = decode_conn_private_key_bundle(bytes)?;
        let alg = &ML_DSA_44_SIGNING;
        let ml_dsa_key_pair = PqdsaKeyPair::from_pkcs8(alg, &ml_dsa_pkcs8)?;
        let ed25519_key_pair = Ed25519KeyPair::from_pkcs8(&ed25519_pkcs8)?;
        Ok(ConnSign {
            ml_dsa_key_pair,
            ed25519_key_pair,
            ml_dsa_pkcs8,
            ed25519_pkcs8,
        })
    }

    /// Load a `ConnSign` key from a file.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Return the bundled ML-DSA and Ed25519 public key bytes for this signer.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let ml_dsa_public_key_der = self
            .ml_dsa_key_pair
            .public_key()
            .as_der()
            .expect("failed to get public key")
            .as_ref()
            .to_vec();
        Ok(encode_conn_public_key(
            &ml_dsa_public_key_der,
            self.ed25519_key_pair
                .public_key()
                .as_ref()
                .try_into()
                .expect("unexpected Ed25519 public key length"),
        ))
    }

    /// Produce a detached ML-DSA+Ed25519 signature bundle for `data`.
    pub fn sign_detached(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signed = self.sign(data)?;
        Ok(signed.0[..conn_signature_len()].to_vec())
    }

    /// Write the `ConnSign` private key bundle to a file.
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let path = path.as_ref();
        let bundle = encode_conn_private_key_bundle(&self.ml_dsa_pkcs8, &self.ed25519_pkcs8)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        std::io::Write::write_all(&mut file, &bundle)?;
        Ok(())
    }
}

impl SignVerify for ConnSign {
    /// Prepend the fixed-size ML-DSA and Ed25519 signatures to the message bytes.
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let alg = &ML_DSA_44_SIGNING;
        let mut ml_dsa_sig = vec![0u8; alg.signature_len()];
        let n = self.ml_dsa_key_pair.sign(data, &mut ml_dsa_sig)?;
        assert_eq!(ml_dsa_sig.len(), n);
        ml_dsa_sig.truncate(n);

        let ed25519_sig = self.ed25519_key_pair.sign(data);
        let mut sig =
            Vec::with_capacity(ml_dsa_sig.len() + ed25519_sig.as_ref().len() + data.len());
        sig.extend(ml_dsa_sig);
        sig.extend(ed25519_sig.as_ref());
        sig.extend(data);
        Ok(Signed(sig))
    }

    /// Split the signature bundle back off the wire bytes and verify it.
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        let ml_dsa_sig_len = ML_DSA_44_SIGNING.signature_len();
        let total_sig_len = conn_signature_len();
        if data.0.len() < total_sig_len {
            return None;
        }
        let (sig, msg) = data.0.split_at(total_sig_len);
        let (ml_dsa_sig, ed25519_sig) = sig.split_at(ml_dsa_sig_len);

        let ml_dsa_public_key_der = self
            .ml_dsa_key_pair
            .public_key()
            .as_der()
            .expect("failed to get public key");
        let ml_dsa_public_key = UnparsedPublicKey::new(&ML_DSA_44, ml_dsa_public_key_der.as_ref());
        ml_dsa_public_key.verify(msg, ml_dsa_sig).ok()?;

        let ed25519_public_key =
            UnparsedPublicKey::new(&ED25519, self.ed25519_key_pair.public_key().as_ref());
        ed25519_public_key.verify(msg, ed25519_sig).ok()?;
        Some(std::borrow::Cow::Borrowed(msg))
    }
}

pub struct PacketVerify {
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    verify_counter: Cell<u64>,
}

impl PacketVerify {
    /// Create an Ed25519 verifier from a public key.
    #[must_use]
    pub fn new(public_key: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        Self {
            public_key,
            verify_counter: Cell::new(0),
        }
    }
}

impl SignVerify for PacketVerify {
    /// Reject signing attempts for public-only Ed25519 verifiers.
    fn sign(&self, _data: &[u8]) -> Result<Signed> {
        bail!("public-only Ed25519 verifier cannot sign")
    }

    /// Verify signed bytes with the stored Ed25519 public key and the next implicit counter.
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        if data.0.len() < ED25519_SIGNATURE_LEN {
            return None;
        }
        let (sig, msg) = data.0.split_at(ED25519_SIGNATURE_LEN);
        let counter = self.verify_counter.get();
        let input = packet_signature_input(counter, msg);
        let public_key = UnparsedPublicKey::new(&ED25519, self.public_key);
        public_key
            .verify(&input, sig.as_ref())
            .map(|()| {
                self.verify_counter.set(counter + 1);
                std::borrow::Cow::Borrowed(msg)
            })
            .ok()
    }
}

pub struct ConnVerify {
    public_key_bundle: Vec<u8>,
}

impl ConnVerify {
    /// Create a `ConnSign` verifier from bundled ML-DSA and Ed25519 public key bytes.
    #[must_use]
    pub fn new(public_key_bundle: Vec<u8>) -> Self {
        Self { public_key_bundle }
    }

    /// Verify a detached ML-DSA+Ed25519 signature bundle against `data`.
    #[must_use]
    pub fn verify_detached(&self, signature: &[u8], data: &[u8]) -> bool {
        let mut signed = signature.to_vec();
        signed.extend(data);
        self.verify(&Signed(signed)).is_some()
    }
}

impl SignVerify for ConnVerify {
    /// Reject signing attempts for public-only `ConnSign` verifiers.
    fn sign(&self, _data: &[u8]) -> Result<Signed> {
        bail!("public-only ConnSign verifier cannot sign")
    }

    /// Verify signed bytes with the stored ML-DSA and Ed25519 public keys.
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        let (ml_dsa_public_key_der, ed25519_public_key) =
            decode_conn_public_key(&self.public_key_bundle).ok()?;
        let ml_dsa_sig_len = ML_DSA_44_SIGNING.signature_len();
        let total_sig_len = conn_signature_len();
        if data.0.len() < total_sig_len {
            return None;
        }
        let (sig, msg) = data.0.split_at(total_sig_len);
        let (ml_dsa_sig, ed25519_sig) = sig.split_at(ml_dsa_sig_len);

        let ml_dsa_public_key =
            UnparsedPublicKey::new(&ML_DSA_44, ml_dsa_public_key_der.as_slice());
        ml_dsa_public_key.verify(msg, ml_dsa_sig).ok()?;

        let ed25519_public_key = UnparsedPublicKey::new(&ED25519, ed25519_public_key);
        ed25519_public_key.verify(msg, ed25519_sig).ok()?;
        Some(std::borrow::Cow::Borrowed(msg))
    }
}

// Generate binary version of public key.
fn encode_conn_public_key(
    ml_dsa_public_key_der: &[u8],
    ed25519_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + ml_dsa_public_key_der.len() + ED25519_PUBLIC_KEY_LEN);
    out.push(CONN_PUBLIC_KEY_VERSION);
    out.extend(ml_dsa_public_key_der);
    out.extend(ed25519_public_key);
    out
}

fn decode_conn_public_key(data: &[u8]) -> Result<(Vec<u8>, [u8; ED25519_PUBLIC_KEY_LEN])> {
    if data.len() < 1 + 1 + ED25519_PUBLIC_KEY_LEN {
        bail!("ConnSign public key bundle is too short");
    }
    let (&version, rest) = data
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("ConnSign public key bundle is empty"))?;
    if version != CONN_PUBLIC_KEY_VERSION {
        bail!("unsupported ConnSign public key bundle version {version}");
    }
    let split_at = rest.len() - ED25519_PUBLIC_KEY_LEN;
    let (ml_dsa_public_key_der, ed25519_public_key) = rest.split_at(split_at);
    let ed25519_public_key: [u8; ED25519_PUBLIC_KEY_LEN] = ed25519_public_key
        .try_into()
        .expect("unexpected Ed25519 public key length");
    Ok((ml_dsa_public_key_der.to_vec(), ed25519_public_key))
}

fn encode_conn_private_key_bundle(ml_dsa_pkcs8: &[u8], ed25519_pkcs8: &[u8]) -> Result<Vec<u8>> {
    let ml_dsa_len = u32::try_from(ml_dsa_pkcs8.len())
        .map_err(|_| anyhow::anyhow!("ML-DSA PKCS#8 is too large"))?;
    let ed25519_len = u32::try_from(ed25519_pkcs8.len())
        .map_err(|_| anyhow::anyhow!("Ed25519 PKCS#8 is too large"))?;
    let mut out = Vec::with_capacity(
        CONN_PRIVATE_KEY_MAGIC.len() + 8 + ml_dsa_pkcs8.len() + ed25519_pkcs8.len(),
    );
    out.extend(CONN_PRIVATE_KEY_MAGIC);
    out.extend(ml_dsa_len.to_be_bytes());
    out.extend(ed25519_len.to_be_bytes());
    out.extend(ml_dsa_pkcs8);
    out.extend(ed25519_pkcs8);
    Ok(out)
}

fn decode_conn_private_key_bundle(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if data.len() < CONN_PRIVATE_KEY_MAGIC.len() + 8 {
        bail!("ConnSign private key bundle is too short");
    }
    let (magic, rest) = data.split_at(CONN_PRIVATE_KEY_MAGIC.len());
    if magic != CONN_PRIVATE_KEY_MAGIC {
        bail!("unsupported ConnSign private key bundle format");
    }
    let (ml_dsa_len_bytes, rest) = rest.split_at(4);
    let ml_dsa_len = u32::from_be_bytes(
        ml_dsa_len_bytes
            .try_into()
            .expect("unexpected ML-DSA length width"),
    ) as usize;
    let (ed25519_len_bytes, rest) = rest.split_at(4);
    let ed25519_len = u32::from_be_bytes(
        ed25519_len_bytes
            .try_into()
            .expect("unexpected Ed25519 length width"),
    ) as usize;
    if rest.len() != ml_dsa_len + ed25519_len {
        bail!("ConnSign private key bundle is truncated");
    }
    let (ml_dsa_pkcs8, ed25519_pkcs8) = rest.split_at(ml_dsa_len);
    Ok((ml_dsa_pkcs8.to_vec(), ed25519_pkcs8.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::{ConnSign, SignVerify, format_sha256_fingerprint};
    use aws_lc_rs::unstable::signature::ML_DSA_44_SIGNING;

    fn unique_test_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::temp_dir().join(format!("axsh-{name}-{}-{nanos}.pk8", std::process::id()))
    }

    #[test]
    fn connsign_round_trips_through_pkcs8_file() {
        let path = unique_test_path("connsign");
        let original = ConnSign::new().expect("failed to generate signer");
        original
            .write_to_file(&path)
            .expect("failed to write signer");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&path)
                .expect("failed to stat temp key file")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let loaded = ConnSign::from_file(&path).expect("failed to load signer");
        let original_public_key = original.public_key_bytes().expect("missing public key");
        let loaded_public_key = loaded.public_key_bytes().expect("missing public key");
        assert_eq!(original_public_key, loaded_public_key);

        let message = b"round-trip";
        let signed = loaded.sign(message).expect("failed to sign");
        let verified = original.verify(&signed).expect("failed to verify");
        assert_eq!(verified.as_ref(), message);

        std::fs::remove_file(path).expect("failed to remove temp key file");
    }

    #[test]
    fn connsign_requires_both_signature_algorithms() {
        let signer = ConnSign::new().expect("failed to generate signer");
        let message = b"dual-signature";
        let ml_dsa_sig_len = ML_DSA_44_SIGNING.signature_len();

        let mut ml_dsa_tampered = signer.sign(message).expect("failed to sign").0;
        ml_dsa_tampered[0] ^= 0x01;
        assert!(signer.verify(&super::Signed(ml_dsa_tampered)).is_none());

        let mut ed25519_tampered = signer.sign(message).expect("failed to sign").0;
        ed25519_tampered[ml_dsa_sig_len] ^= 0x01;
        assert!(signer.verify(&super::Signed(ed25519_tampered)).is_none());
    }

    #[test]
    fn sha256_fingerprint_matches_known_value() {
        assert_eq!(
            format_sha256_fingerprint(b"foo"),
            "SHA256:LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564"
        );
    }
}
