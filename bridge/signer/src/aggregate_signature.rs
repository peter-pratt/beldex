//! Check a combined signature against the group keys this node loaded from its own shares.
//!
//! The coordinator calls this on its own signing result and on every `Signature` a peer
//! distributes. Mesh authentication only proves which member sent the bytes; a single
//! hostile member could otherwise announce garbage and have the duty treated as settled.
//! The keys are never taken from the message.

use crate::transport::Leg;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

pub struct AggregateVerifier {
    /// The wBDX signer address the `Pevm` group key controls.
    pub pevm_address: [u8; 20],
    /// The `Pgw` group (gateway owner) ed25519 key.
    pub pgw_group_vk: [u8; 32],
}

impl AggregateVerifier {
    /// `message` is what the policy hands the scheme: the mint preimage for `Pevm` (hashed
    /// here, as the contract does), the 32-byte gateway digest for `Pgw`.
    pub fn verify(&self, leg: Leg, message: &[u8], signature: &[u8]) -> bool {
        match leg {
            Leg::Pgw => {
                let Ok(sig) = <&[u8; 64]>::try_from(signature) else { return false };
                message.len() == 32
                    && crate::ffi::ed25519_verify_consensus(sig, message, &self.pgw_group_vk)
            }
            Leg::Pevm => {
                pevm_signer(message, signature).is_some_and(|a| a == self.pevm_address)
            }
        }
    }
}

/// The address a 65-byte `r‖s‖v` recovers to, under the same rules the contract's
/// `ECDSA.recover` applies: `v` of 27 or 28 and a low `s`. Anything else recovers nothing.
pub fn pevm_signer(preimage: &[u8], signature: &[u8]) -> Option<[u8; 20]> {
    if signature.len() != 65 || !matches!(signature[64], 27 | 28) {
        return None;
    }
    let sig = Signature::from_slice(&signature[..64]).ok()?;
    if sig.normalize_s().is_some() {
        return None; // high-s: the contract rejects it, so it settles nothing
    }
    let recovery = RecoveryId::from_byte(signature[64] - 27)?;
    let digest = Keccak256::digest(preimage);
    let vk = VerifyingKey::recover_from_prehash(&digest, &sig, recovery).ok()?;
    Some(eth_address(&vk))
}

/// The Ethereum address of a secp256k1 key.
pub fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
    let enc = vk.to_encoded_point(false);
    let h = Keccak256::digest(&enc.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn evm_sign(sk: &SigningKey, preimage: &[u8]) -> Vec<u8> {
        let (sig, rec) = sk.sign_digest_recoverable(Keccak256::new_with_prefix(preimage)).unwrap();
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + rec.to_byte());
        out
    }

    #[test]
    fn both_legs_reject_malformed_wrong_message_and_wrong_key_aggregates() {
        let sk = SigningKey::from_slice(&[7; 32]).unwrap();
        let other = SigningKey::from_slice(&[8; 32]).unwrap();
        let (pgw, secret) = crate::ffi::ed25519_keypair().unwrap();
        let (other_pgw, _) = crate::ffi::ed25519_keypair().unwrap();
        let ok = AggregateVerifier { pevm_address: eth_address(sk.verifying_key()), pgw_group_vk: pgw };
        let wrong = AggregateVerifier {
            pevm_address: eth_address(other.verifying_key()),
            pgw_group_vk: other_pgw,
        };
        let message = [42u8; 32];
        let evm = evm_sign(&sk, &message);
        let native = crate::ffi::ed25519_sign_detached(&secret, &message).unwrap();
        for (leg, sig) in [(Leg::Pevm, evm.as_slice()), (Leg::Pgw, native.as_slice())] {
            assert!(ok.verify(leg, &message, sig));
            assert!(!ok.verify(leg, &[43u8; 32], sig), "another message");
            assert!(!wrong.verify(leg, &message, sig), "another group key");
            for bad in [vec![], vec![0u8; 64], vec![0u8; 65], sig[..sig.len() - 1].to_vec()] {
                assert!(!ok.verify(leg, &message, &bad));
            }
        }
    }

    #[test]
    fn pevm_rejects_what_the_contract_rejects() {
        let sk = SigningKey::from_slice(&[7; 32]).unwrap();
        let ok = AggregateVerifier { pevm_address: eth_address(sk.verifying_key()), pgw_group_vk: [0; 32] };
        let preimage = b"mint preimage".to_vec();
        let good = evm_sign(&sk, &preimage);
        assert!(ok.verify(Leg::Pevm, &preimage, &good));

        // v outside {27, 28}.
        let mut raw_v = good.clone();
        raw_v[64] -= 27;
        assert!(!ok.verify(Leg::Pevm, &preimage, &raw_v));

        // The high-s twin of a valid signature recovers the same key, but is malleable.
        let sig = Signature::from_slice(&good[..64]).unwrap();
        let (r, s) = (sig.r(), sig.s());
        let high = Signature::from_scalars(r.to_bytes(), (-*s.as_ref()).to_bytes()).unwrap();
        let mut malleated = high.to_bytes().to_vec();
        malleated.push(if good[64] == 27 { 28 } else { 27 });
        assert!(!ok.verify(Leg::Pevm, &preimage, &malleated));
    }
}
