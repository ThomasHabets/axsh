// TODO: replace with thiserror.
use anyhow::{Result, bail};
use aws_lc_rs::{
    encoding::AsDer,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
    unstable::signature::{ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair},
};

pub mod hdlc;
mod packet;
pub use packet::{ClientHello, Packet, ServerComplete, ServerHello, SignVerify, Signed};

pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

pub(crate) fn conn_signature_len() -> usize {
    ML_DSA_44_SIGNING.signature_len()
}

pub struct PacketSign {
    key_pair: Ed25519KeyPair,
}

impl PacketSign {
    /// Generate a fresh Ed25519 keypair for payload packet signing.
    pub fn new() -> Result<Self> {
        let key_pair = Ed25519KeyPair::generate()?;
        Ok(Self { key_pair })
    }

    /// Return the Ed25519 public key bytes for this signer.
    pub fn public_key_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("unexpected Ed25519 public key length")
    }
}

impl SignVerify for PacketSign {
    /// Prepend the fixed-size Ed25519 signature to the message bytes.
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let mut sig = self.key_pair.sign(data).as_ref().to_vec();
        assert_eq!(sig.len(), ED25519_SIGNATURE_LEN);
        sig.extend(data);
        Ok(Signed(sig))
    }

    /// Split the signature back off the wire bytes and verify it.
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
    }
}

pub struct ConnSign {
    key_pair: PqdsaKeyPair,
}

impl ConnSign {
    /// Generate a fresh ML-DSA keypair for handshake packet signing.
    pub fn new() -> Result<Self> {
        let alg = &ML_DSA_44_SIGNING;
        Ok(ConnSign {
            key_pair: PqdsaKeyPair::generate(alg)?,
        })
    }

    /// Return the ML-DSA public key bytes for this signer, encoded as DER.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        Ok(self
            .key_pair
            .public_key()
            .as_der()
            .expect("failed to get public key")
            .as_ref()
            .to_vec())
    }
}

impl SignVerify for ConnSign {
    /// Prepend the fixed-size ML-DSA signature to the message bytes.
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let alg = &ML_DSA_44_SIGNING;
        let mut sig = vec![0u8; alg.signature_len()];
        let n = self.key_pair.sign(data, &mut sig)?;
        assert_eq!(sig.len(), n);
        sig.truncate(n);
        sig.extend(data);
        Ok(Signed(sig))
    }

    /// Split the signature back off the wire bytes and verify it.
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

pub struct PacketVerify {
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl PacketVerify {
    /// Create an Ed25519 verifier from a public key.
    pub fn new(public_key: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        Self { public_key }
    }
}

impl SignVerify for PacketVerify {
    /// Reject signing attempts for public-only Ed25519 verifiers.
    fn sign(&self, _data: &[u8]) -> Result<Signed> {
        bail!("public-only Ed25519 verifier cannot sign")
    }

    /// Verify signed bytes with the stored Ed25519 public key.
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        if data.0.len() < ED25519_SIGNATURE_LEN {
            return None;
        }
        let (sig, msg) = data.0.split_at(ED25519_SIGNATURE_LEN);
        let public_key = UnparsedPublicKey::new(&ED25519, self.public_key);
        public_key
            .verify(msg, sig.as_ref())
            .map(|_| std::borrow::Cow::Borrowed(msg))
            .ok()
    }
}

pub struct ConnVerify {
    public_key_der: Vec<u8>,
}

impl ConnVerify {
    /// Create an ML-DSA verifier from a DER-encoded public key.
    pub fn new(public_key_der: Vec<u8>) -> Self {
        Self { public_key_der }
    }
}

impl SignVerify for ConnVerify {
    /// Reject signing attempts for public-only ML-DSA verifiers.
    fn sign(&self, _data: &[u8]) -> Result<Signed> {
        bail!("public-only ML-DSA verifier cannot sign")
    }

    /// Verify signed bytes with the stored ML-DSA public key.
    fn verify<'a>(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        let sig_len = conn_signature_len();
        if data.0.len() < sig_len {
            return None;
        }
        let (sig, msg) = data.0.split_at(sig_len);
        let public_key = UnparsedPublicKey::new(&ML_DSA_44, self.public_key_der.as_slice());
        public_key
            .verify(msg, sig)
            .map(|_| std::borrow::Cow::Borrowed(msg))
            .ok()
    }
}
