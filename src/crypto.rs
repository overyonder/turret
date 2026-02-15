use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::ed25519::signature::Signer;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("bad signature")]
    BadSignature,
}

pub fn canonical_signing_bytes(principal: &[u8], ts_ms: u64, nonce: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(principal.len() + nonce.len() + body.len() + 32);
    out.extend_from_slice(principal);
    out.push(b'\n');
    out.extend_from_slice(ts_ms.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce);
    out.push(b'\n');
    out.extend_from_slice(body);
    out
}

pub fn sign(sk: &SigningKey, principal: &[u8], ts_ms: u64, nonce: &[u8], body: &[u8]) -> Signature {
    let bytes = canonical_signing_bytes(principal, ts_ms, nonce, body);
    sk.sign(&bytes)
}

pub fn verify(
    vk: &VerifyingKey,
    principal: &[u8],
    ts_ms: u64,
    nonce: &[u8],
    body: &[u8],
    sig: &Signature,
) -> Result<(), CryptoError> {
    let bytes = canonical_signing_bytes(principal, ts_ms, nonce, body);
    vk.verify_strict(&bytes, sig)
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn signing_bytes_are_canonical() {
        let b = canonical_signing_bytes(b"agent-1", 123, b"nonce", b"body");
        assert_eq!(b, b"agent-1\n123\nnonce\nbody".to_vec());
    }

    #[test]
    fn ed25519_verify_roundtrip() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let sig = sign(&sk, b"agent-1", 123, b"nonce", b"body");
        verify(&vk, b"agent-1", 123, b"nonce", b"body", &sig).unwrap();
    }
}
