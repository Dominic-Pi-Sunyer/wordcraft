//! Zero-trust E2EE + capability-based write verification for gossip payloads.
//!
//! Wire format of every gossip message (`SignedEncryptedFrame`, bincode):
//!
//! ```text
//! nonce(12) || ChaCha20-Poly1305_{read_key}( bincode(SignedPayload) )
//! SignedPayload { author, seq, payload, signature = Ed25519_{write_signing_key}(author || seq || payload) }
//! ```
//!
//! * **Read capability** = `read_key`: lets you decrypt.
//! * **Write capability** = `write_signing_key`: lets you produce signatures that
//!   every peer (who only knows the public `write_verifying_key`) will accept.
//!
//! A View-Only ticket carries the read key and verifying key but no signing key,
//! so its holder can read everything and forge nothing. Frames that fail to
//! decrypt or verify must be dropped silently by the caller.
//!
//! `seq` is a per-sender counter inside the signed bytes; receivers drop a repeated
//! `(author, seq)` (see [`crate::replay`]), so a peer that merely *holds* a captured frame,
//! including a View-Only peer, cannot re-publish it to have it applied twice.
//!
//! Note: all writers share one signing key, so `author` identifies a peer for
//! display/echo-suppression but is only authenticated as "some authorized writer".

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const NONCE_LEN: usize = 12;

/// 32 random bytes from the OS CSPRNG (read keys, signing seeds, topic ids).
pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

/// What travels over gossip: a random nonce plus the AEAD ciphertext.
#[derive(Serialize, Deserialize)]
pub struct SignedEncryptedFrame {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// The plaintext inside a frame.
#[derive(Serialize, Deserialize)]
pub struct SignedPayload {
    pub author: [u8; 32],
    pub seq: u64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

fn signed_message(author: &[u8; 32], seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(40 + payload.len());
    m.extend_from_slice(author);
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(payload);
    m
}

/// Encrypt `plaintext` into a serialized [`SignedEncryptedFrame`] with a fresh random nonce.
pub fn encrypt(read_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(read_key))
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(bincode::serialize(&SignedEncryptedFrame {
        nonce,
        ciphertext,
    })?)
}

/// Inverse of [`encrypt`]; fails if tampered or the key is wrong.
pub fn decrypt(read_key: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>> {
    let f: SignedEncryptedFrame = bincode::deserialize(frame)?;
    ChaCha20Poly1305::new(Key::from_slice(read_key))
        .decrypt(Nonce::from_slice(&f.nonce), f.ciphertext.as_slice())
        .map_err(|_| anyhow!("decryption failed (wrong key or tampered frame)"))
}

/// Sign `(author || payload)` and encrypt. Fails with `Session is View-Only`
/// when no signing key is available, before anything touches the network.
pub fn seal(
    read_key: &[u8; 32],
    signing_key: Option<&SigningKey>,
    author: [u8; 32],
    seq: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let sk = signing_key.ok_or_else(|| anyhow!("Session is View-Only"))?;
    let signature = sk
        .sign(&signed_message(&author, seq, payload))
        .to_bytes()
        .to_vec();
    let inner = SignedPayload {
        author,
        seq,
        payload: payload.to_vec(),
        signature,
    };
    encrypt(read_key, &bincode::serialize(&inner)?)
}

/// Decrypt, then verify the write signature against the ticket's verifying key.
/// Returns `(author, seq, payload)`; any failure means the frame must be dropped.
pub fn open(
    read_key: &[u8; 32],
    verifying_key: &VerifyingKey,
    frame: &[u8],
) -> Result<([u8; 32], u64, Vec<u8>)> {
    let inner: SignedPayload = bincode::deserialize(&decrypt(read_key, frame)?)?;
    let sig: [u8; 64] = match inner.signature.as_slice().try_into() {
        Ok(s) => s,
        Err(_) => bail!("bad signature length"),
    };
    verifying_key
        .verify(
            &signed_message(&inner.author, inner.seq, &inner.payload),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| anyhow!("write signature verification failed"))?;
    Ok((inner.author, inner.seq, inner.payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> ([u8; 32], SigningKey) {
        (random_key(), SigningKey::from_bytes(&random_key()))
    }

    #[test]
    fn encrypt_roundtrip_and_fresh_nonce() {
        let key = random_key();
        let a = encrypt(&key, b"hello pdf").unwrap();
        assert!(!a.windows(9).any(|w| w == b"hello pdf"));
        assert_eq!(decrypt(&key, &a).unwrap(), b"hello pdf");
        assert_ne!(a, encrypt(&key, b"hello pdf").unwrap());
    }

    #[test]
    fn wrong_key_and_tamper_fail() {
        let key = random_key();
        let mut ct = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&random_key(), &ct).is_err());
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(decrypt(&key, &ct).is_err());
        assert!(decrypt(&key, &[1, 2, 3]).is_err());
    }

    #[test]
    fn seal_open_roundtrip() {
        let (rk, sk) = keys();
        let frame = seal(&rk, Some(&sk), [7; 32], 9, b"mutation").unwrap();
        let (author, seq, data) = open(&rk, &sk.verifying_key(), &frame).unwrap();
        assert_eq!(author, [7; 32]);
        assert_eq!(seq, 9);
        assert_eq!(data, b"mutation");
    }

    #[test]
    fn view_only_cannot_seal() {
        let err = seal(&random_key(), None, [0; 32], 0, b"x").unwrap_err();
        assert!(err.to_string().contains("View-Only"));
    }

    #[test]
    fn forged_frames_rejected() {
        let (rk, sk) = keys();
        let vk = sk.verifying_key();

        // Signed by a key that is not the session's write key.
        let attacker = SigningKey::from_bytes(&random_key());
        let wrong_signer = seal(&rk, Some(&attacker), [1; 32], 1, b"evil").unwrap();
        assert!(open(&rk, &vk, &wrong_signer).is_err());

        // Unsigned / garbage signature, correctly encrypted with the read key.
        let unsigned = SignedPayload {
            author: [1; 32],
            seq: 1,
            payload: b"evil".to_vec(),
            signature: vec![0; 64],
        };
        let f = encrypt(&rk, &bincode::serialize(&unsigned).unwrap()).unwrap();
        assert!(open(&rk, &vk, &f).is_err());

        // Valid signature but payload swapped afterwards.
        let good = SignedPayload {
            author: [1; 32],
            seq: 1,
            payload: b"evil".to_vec(),
            signature: sk
                .sign(&signed_message(&[1; 32], 1, b"good"))
                .to_bytes()
                .to_vec(),
        };
        let f = encrypt(&rk, &bincode::serialize(&good).unwrap()).unwrap();
        assert!(open(&rk, &vk, &f).is_err());

        // Valid signature over seq 1, but the sequence number rewritten afterwards.
        let one = SignedPayload {
            author: [1; 32],
            seq: 2,
            payload: b"good".to_vec(),
            signature: sk
                .sign(&signed_message(&[1; 32], 1, b"good"))
                .to_bytes()
                .to_vec(),
        };
        let f = encrypt(&rk, &bincode::serialize(&one).unwrap()).unwrap();
        assert!(open(&rk, &vk, &f).is_err());
    }
}
