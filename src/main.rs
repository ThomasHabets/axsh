use anyhow::Result;
use aws_lc_rs::{
    encoding::AsDer,
    signature::{ED25519, Ed25519KeyPair},
    signature::{KeyPair, UnparsedPublicKey},
    //unstable::signature::{ML_DSA_65_SIGNING, ML_DSA_87_SIGNING},
    unstable::signature::{ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair},
};

struct ServerHello {
    unique: u64,
    // TODO: public ML-DSA key.
    // TODO: public ed25519 key.
}

struct ClientHello {
    unique: u64,
    // TODO: public ML-DSA key.
    // TODO: public ed25519 key.
}

enum Packet {
    /// Server gives parameters, but unsigned.
    ServerHello(ServerHello),
    /// Client gives parameters, signed.
    ///
    /// Client also provides a random
    ClientHello(ClientHello),
    /// Server completes the handshake by signing its previous hello and the
    /// client challenge.
    ServerComplete,

    /// Renew packet signing key.
    // Rekey,

    /// User payload in either direction.
    ///
    /// Signed with the packet key.
    Payload(Signed),
}

const ED25519_SIGNATURE_LEN: usize = 64;

struct Signed(Vec<u8>);

trait SignVerify<'a> {
    fn sign(&self, data: &[u8]) -> Result<Signed>;
    fn verify(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>>;
}

struct PacketSign {
    key_pair: Ed25519KeyPair,
}

impl PacketSign {
    fn new() -> Result<Self> {
        let key_pair = Ed25519KeyPair::generate()?;
        Ok(Self { key_pair })
    }
}

impl<'a> SignVerify<'a> for PacketSign {
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let mut sig = self.key_pair.sign(data).as_ref().to_vec();
        assert_eq!(sig.len(), ED25519_SIGNATURE_LEN);
        sig.extend(data);
        Ok(Signed(sig))
    }
    fn verify(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
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

struct ConnSign {
    key_pair: PqdsaKeyPair,
}

impl ConnSign {
    fn new() -> Result<Self> {
        let alg = &ML_DSA_44_SIGNING;
        Ok(ConnSign {
            key_pair: PqdsaKeyPair::generate(alg)?,
        })
    }
}

impl<'a> SignVerify<'a> for ConnSign {
    fn sign(&self, data: &[u8]) -> Result<Signed> {
        let alg = &ML_DSA_44_SIGNING;
        let mut sig = vec![0u8; alg.signature_len()];
        let n = self.key_pair.sign(data, &mut sig)?;
        assert_eq!(sig.len(), n);
        sig.truncate(n);
        sig.extend(data);
        Ok(Signed(sig))
    }
    fn verify(&self, data: &'a Signed) -> Option<std::borrow::Cow<'a, [u8]>> {
        let alg = &ML_DSA_44;
        let algs = &ML_DSA_44_SIGNING;
        let public_key_der = self
            .key_pair
            .public_key()
            .as_der()
            .expect("failed to get public key");
        let public_key = UnparsedPublicKey::new(alg, public_key_der.as_ref());
        let (sig, msg) = data.0.split_at(algs.signature_len());
        public_key.verify(msg, sig).unwrap();
        Some(std::borrow::Cow::Borrowed(msg))
    }
}

fn main() -> Result<()> {
    let msg = b"hello, world";
    {
        let signer = ConnSign::new()?;
        let signed = signer.sign(msg)?;
        signer.verify(&signed).unwrap();
    }

    {
        let signer = PacketSign::new()?;
        let signed = signer.sign(msg)?;
        signer.verify(&signed).unwrap();
    }

    println!("ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
