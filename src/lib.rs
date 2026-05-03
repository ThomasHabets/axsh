// TODO: replace with thiserror.
use anyhow::Result;
use aws_lc_rs::{
    encoding::AsDer,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
    unstable::signature::{ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair},
};

pub mod hdlc;
mod packet;
pub use packet::{ClientHello, Packet, ServerComplete, ServerHello, SignVerify, Signed};

pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;

pub struct PacketSign {
    key_pair: Ed25519KeyPair,
}

impl PacketSign {
    /// Generate a fresh Ed25519 keypair for payload packet signing.
    pub fn new() -> Result<Self> {
        let key_pair = Ed25519KeyPair::generate()?;
        Ok(Self { key_pair })
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
