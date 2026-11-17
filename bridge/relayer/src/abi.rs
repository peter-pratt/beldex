//! Minimal, self-contained ABI encoding for the three **already-signed** wBDX calls a
//! relayer carries (Phase I). No external ABI/EVM crate — the encoding is small, fixed,
//! and must match `bridge-contract/src/WrappedBDX.sol` **byte-for-byte** (a wrong selector
//! or offset makes the call revert), so it is spelled out and pinned by tests.
//!
//! A relayer is a **keyless courier**: it never holds a bridge key and forges nothing. The
//! committee signature is already complete and rides inside the call's `bytes sig` argument;
//! the relayer only wraps it in the correct calldata and (optionally) pays gas to broadcast.

use sha3::{Digest, Keccak256};

/// `mint(address,uint256,bytes32,uint32,bytes)` selector — `keccak256(sig)[..4]`.
/// `outputIndex` identifies the gateway output, not merely the transaction.
pub const MINT_SELECTOR: [u8; 4] = [0x7f, 0x00, 0x00, 0x0a];
/// `rotateSigner(address,uint64,uint64,uint256,bytes)` selector.
/// The nonce and deadline make an authorization single-use and time-bounded, so a
/// relayed proposal cannot be replayed to revive a vetoed hand-off or restart the
/// challenge window.
pub const ROTATE_SELECTOR: [u8; 4] = [0x95, 0x0c, 0x57, 0xf3];
/// `cancelStandbyTakeover(bytes)` selector: the live committee's cancel of a standby
/// takeover it can still sign against.
pub const CANCEL_TAKEOVER_SELECTOR: [u8; 4] = [0x54, 0x76, 0x85, 0x8c];
/// `beginStandbyTakeover(bytes)` selector: the standby committee starts the clock.
pub const BEGIN_TAKEOVER_SELECTOR: [u8; 4] = [0xca, 0xbc, 0xec, 0xea];
/// `completeStandbyTakeover(bytes)` selector: after the delay, the standby becomes the signer.
pub const COMPLETE_TAKEOVER_SELECTOR: [u8; 4] = [0x42, 0x9d, 0x05, 0xe2];

/// `setStandby(address,uint64,uint256,bytes)` selector: the live committee names its standby.
pub const SET_STANDBY_SELECTOR: [u8; 4] = [0xbe, 0x88, 0x7a, 0x32];
/// `activateRotation(bytes)` selector: the incoming committee's signature completes the
/// hand-off once the challenge window has passed.
pub const ACTIVATE_SELECTOR: [u8; 4] = [0x25, 0x09, 0x92, 0x04];

/// The canonical function signatures (used only by the drift-guard tests).
pub const MINT_SIG: &[u8] = b"mint(address,uint256,bytes32,uint32,bytes)";
pub const ROTATE_SIG: &[u8] = b"rotateSigner(address,uint64,uint64,uint256,bytes)";
pub const CANCEL_TAKEOVER_SIG: &[u8] = b"cancelStandbyTakeover(bytes)";
pub const BEGIN_TAKEOVER_SIG: &[u8] = b"beginStandbyTakeover(bytes)";
pub const COMPLETE_TAKEOVER_SIG: &[u8] = b"completeStandbyTakeover(bytes)";
pub const SET_STANDBY_SIG: &[u8] = b"setStandby(address,uint64,uint256,bytes)";
pub const ACTIVATE_SIG: &[u8] = b"activateRotation(bytes)";

/// `keccak256(fn_sig)[..4]` — the 4-byte selector for a function signature.
pub fn selector_of(fn_sig: &[u8]) -> [u8; 4] {
    let h: [u8; 32] = Keccak256::digest(fn_sig).into();
    [h[0], h[1], h[2], h[3]]
}

/// A `uint256` from a `u128`, big-endian in the low 16 bytes of a 32-byte word.
pub(crate) fn word_u256(x: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&x.to_be_bytes());
    w
}

/// A `uint64` as an ABI word (low 8 bytes).
fn word_u64(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

/// An `address` as an ABI word (right-aligned 20 bytes).
pub(crate) fn word_address(a: [u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a);
    w
}

/// Append a dynamic `bytes` tail: a length word then the data, zero-padded to a 32-byte
/// boundary. (The head must already carry the offset word pointing here.)
fn push_dynamic_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&word_u256(data.len() as u128));
    out.extend_from_slice(data);
    let pad = (32 - (data.len() % 32)) % 32;
    out.extend(std::iter::repeat(0u8).take(pad));
}

/// Build the calldata for
/// `mint(address to, uint256 amount, bytes32 beldexTxid, uint32 outputIndex, bytes sig)`.
///
/// Layout: `selector ‖ head[5 words] ‖ tail`, where the head is
/// `word(to) ‖ word(amount) ‖ beldexTxid ‖ word(outputIndex) ‖ offset(=0xa0)` and the
/// tail is the encoded `sig`. The offset moved 0x80 -> 0xa0 when `outputIndex` was added.
pub fn build_mint_calldata(
    to: [u8; 20],
    amount: u128,
    beldex_txid: [u8; 32],
    output_index: u32,
    sig: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 6 + sig.len() + 32);
    out.extend_from_slice(&MINT_SELECTOR);
    out.extend_from_slice(&word_address(to));
    out.extend_from_slice(&word_u256(amount));
    out.extend_from_slice(&beldex_txid);
    out.extend_from_slice(&word_u64(output_index as u64));
    out.extend_from_slice(&word_u256(0xa0)); // offset to `sig`: 5 head words = 160 bytes
    push_dynamic_bytes(&mut out, sig);
    out
}

/// Build the calldata for one of the `…StandbyTakeover(bytes sig)` calls (`selector` is
/// one of the three takeover selectors): one head word, the offset (0x20) to `sig`, then
/// `sig`.
pub fn build_takeover_calldata(selector: [u8; 4], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 2 + sig.len() + 32);
    out.extend_from_slice(&selector);
    out.extend_from_slice(&word_u256(0x20));
    push_dynamic_bytes(&mut out, sig);
    out
}

/// `cancelStandbyTakeover(bytes sig)`.
pub fn build_cancel_takeover_calldata(sig: &[u8]) -> Vec<u8> {
    build_takeover_calldata(CANCEL_TAKEOVER_SELECTOR, sig)
}

/// Build the calldata for `rotateSigner(address newSigner, uint64 newKeyEpoch,
/// uint64 nonce, uint256 deadline, bytes sig)`.
///
/// Head is `word(newSigner) ‖ word(newKeyEpoch) ‖ word(nonce) ‖ word(deadline) ‖
/// offset(=0xa0)`; tail is the encoded `sig`.
pub fn build_rotate_calldata(
    new_signer: [u8; 20],
    new_key_epoch: u64,
    nonce: u64,
    deadline: u128,
    sig: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 6 + sig.len() + 32);
    out.extend_from_slice(&ROTATE_SELECTOR);
    out.extend_from_slice(&word_address(new_signer));
    out.extend_from_slice(&word_u64(new_key_epoch));
    out.extend_from_slice(&word_u64(nonce));
    out.extend_from_slice(&word_u256(deadline));
    out.extend_from_slice(&word_u256(0xa0)); // offset to `sig`: 5 head words = 160 bytes
    push_dynamic_bytes(&mut out, sig);
    out
}

/// Build the calldata for `setStandby(address newStandby, uint64 nonce, uint256 deadline,
/// bytes currentSig)`: head `word(newStandby) ‖ word(nonce) ‖ word(deadline) ‖ offset(=0x80)`,
/// tail the encoded `sig`.
pub fn build_set_standby_calldata(standby: [u8; 20], nonce: u64, deadline: u128, sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 5 + sig.len() + 32);
    out.extend_from_slice(&SET_STANDBY_SELECTOR);
    out.extend_from_slice(&word_address(standby));
    out.extend_from_slice(&word_u64(nonce));
    out.extend_from_slice(&word_u256(deadline));
    out.extend_from_slice(&word_u256(0x80)); // offset to `sig`: 4 head words = 128 bytes
    push_dynamic_bytes(&mut out, sig);
    out
}

/// Build the calldata for `activateRotation(bytes incomingSig)`.
///
/// Head is the single offset word (=0x20); tail is the encoded `incomingSig`. The epoch and
/// signer it activates are the pending ones already on chain, so nothing else is passed.
pub fn build_activate_calldata(sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 2 + sig.len() + 32);
    out.extend_from_slice(&ACTIVATE_SELECTOR);
    out.extend_from_slice(&word_u256(0x20)); // offset to `incomingSig`: 1 head word
    push_dynamic_bytes(&mut out, sig);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_keccak_of_signatures() {
        assert_eq!(MINT_SELECTOR, selector_of(MINT_SIG));
        assert_eq!(ROTATE_SELECTOR, selector_of(ROTATE_SIG));
        assert_eq!(CANCEL_TAKEOVER_SELECTOR, selector_of(CANCEL_TAKEOVER_SIG));
        assert_eq!(BEGIN_TAKEOVER_SELECTOR, selector_of(BEGIN_TAKEOVER_SIG));
        assert_eq!(COMPLETE_TAKEOVER_SELECTOR, selector_of(COMPLETE_TAKEOVER_SIG));
        assert_eq!(SET_STANDBY_SELECTOR, selector_of(SET_STANDBY_SIG));
        assert_eq!(ACTIVATE_SELECTOR, selector_of(ACTIVATE_SIG));
        // Pin the exact bytes so a drift is caught even if the signature string changed.
        assert_eq!(MINT_SELECTOR, [0x7f, 0x00, 0x00, 0x0a]);
        assert_eq!(ROTATE_SELECTOR, [0x95, 0x0c, 0x57, 0xf3]);
        assert_eq!(ACTIVATE_SELECTOR, [0x25, 0x09, 0x92, 0x04]);
    }

    #[test]
    fn activate_calldata_is_abi_shaped() {
        let sig = vec![0xEE; 65];
        let cd = build_activate_calldata(&sig);

        assert_eq!(&cd[0..4], &ACTIVATE_SELECTOR);
        // selector + 1 head word + (length word + 65 bytes padded to 96)
        assert_eq!(cd.len(), 4 + 32 + 32 + 96);
        assert_eq!(cd[4 + 31], 0x20);                          // offset to `incomingSig`
        assert_eq!(cd[4 + 32 + 31], 65);                       // sig length
        assert_eq!(&cd[4 + 64..4 + 64 + 65], &sig[..]);
    }

    /// Byte-for-byte what `cast calldata "cancelStandbyTakeover(bytes)" 0xabab…` (65 bytes)
    /// produces.
    #[test]
    fn cancel_takeover_calldata_matches_cast() {
        let cd = build_cancel_takeover_calldata(&[0xAB; 65]);
        let hex: String = cd.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "5476858c00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000041ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab00000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(cd.len(), 4 + 32 + 32 + 96);
    }

    #[test]
    fn mint_calldata_is_abi_shaped() {
        let to = [0x11u8; 20];
        let sig = vec![0xAB; 65]; // r‖s‖v
        let txid = [0xCD; 32];
        let cd = build_mint_calldata(to, 1000, txid, 7, &sig);

        // selector + 5 head words + (len word + 65 bytes padded to 96).
        assert_eq!(&cd[0..4], &MINT_SELECTOR);
        assert_eq!(cd.len(), 4 + 32 * 5 + 32 + 96);

        // head word 0: to (right-aligned)
        assert_eq!(&cd[4 + 12..4 + 32], &to);
        // head word 1: amount low bytes
        assert_eq!(&cd[4 + 32 + 16..4 + 64], &1000u128.to_be_bytes());
        // head word 2: beldexTxid verbatim
        assert_eq!(&cd[4 + 64..4 + 96], &txid);
        // head word 3: outputIndex, right-aligned
        assert_eq!(&cd[4 + 96 + 24..4 + 128], &7u64.to_be_bytes());
        // head word 4: offset 0xa0
        assert_eq!(cd[4 + 128 + 31], 0xa0);
        // tail: length word 65
        assert_eq!(cd[4 + 160 + 31], 65);
        // tail data: the signature bytes
        assert_eq!(&cd[4 + 192..4 + 192 + 65], &sig[..]);
    }

    #[test]
    fn rotate_calldata_is_abi_shaped() {
        let ns = [0x22u8; 20];
        let sig = vec![0xEE; 65];
        let cd = build_rotate_calldata(ns, 7, 3, 1_700_000_000, &sig);

        assert_eq!(&cd[0..4], &ROTATE_SELECTOR);
        // selector + 5 head words + (length word + 65 bytes padded to 96)
        assert_eq!(cd.len(), 4 + 32 * 5 + 32 + 96);
        assert_eq!(&cd[4 + 12..4 + 32], &ns);                  // newSigner
        assert_eq!(cd[4 + 32 + 31], 7);                        // newKeyEpoch
        assert_eq!(cd[4 + 64 + 31], 3);                        // nonce
        assert_eq!(                                            // deadline
            u128::from_be_bytes(cd[4 + 96 + 16..4 + 128].try_into().unwrap()),
            1_700_000_000
        );
        assert_eq!(cd[4 + 128 + 31], 0xa0);                    // offset to `sig`
        assert_eq!(cd[4 + 160 + 31], 65);                      // sig length
        assert_eq!(&cd[4 + 192..4 + 192 + 65], &sig[..]);
    }

    #[test]
    fn dynamic_bytes_padding_is_correct() {
        // 65 bytes → padded to 96 (three words); an exact multiple stays unpadded.
        let mut a = Vec::new();
        push_dynamic_bytes(&mut a, &vec![1u8; 65]);
        assert_eq!(a.len(), 32 + 96);
        let mut b = Vec::new();
        push_dynamic_bytes(&mut b, &vec![1u8; 64]);
        assert_eq!(b.len(), 32 + 64);
    }

    /// Byte-for-byte what `cast calldata "setStandby(address,uint64,uint256,bytes)"
    /// 0x3333… 5 1700003600 0xabab…` (65 bytes) produces.
    #[test]
    fn set_standby_calldata_matches_cast() {
        let cd = build_set_standby_calldata([0x33; 20], 5, 1_700_003_600, &[0xAB; 65]);
        let hex: String = cd.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "be887a3200000000000000000000000033333333333333333333333333333333333333330000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000006553ff1000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab00000000000000000000000000000000000000000000000000000000000000");
    }
}
