//! A committee member's attestation that its committee generated a key.
//!
//! Consensus names a standby for the bridge gateway only when it knows which committee holds
//! each key, so it can check that the live key's committee and the standby's share few enough
//! members that losing one never silences both. A committee says so one member at a time:
//! each member signs, with its own signer key, the same genesis-bound statement
//! (committee epoch, gateway key, wBDX address) and puts it on chain in its own
//! `bridge_registration` tx (`tx_extra_bridge_key_attestation`). The key is attested once the
//! epoch's threshold have. No session is needed, so a member attests as soon as it holds a
//! share, whichever role it serves.

use crate::ffi::{ed25519_sign_detached, ed25519_verify_consensus};

/// `hashkey::BRIDGE_KEY_ATTESTATION` in beldexd.
pub const DOMAIN: &[u8] = b"bridge_key_attestation_v1";
/// `tx_extra_bridge_key_attestation::version`; consensus accepts no other.
pub const VERSION: u8 = 0;

/// The bytes every member of committee `epoch` signs:
/// `DOMAIN ‖ genesis(32) ‖ version(u8) ‖ epoch(u64 LE) ‖ pgw_vk(32) ‖ pevm_address(20)`.
/// The member is not in it: all sign the same statement.
pub fn message(genesis: &[u8; 32], epoch: u64, pgw_vk: &[u8; 32], pevm_address: &[u8; 20]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + 32 + 1 + 8 + 32 + 20);
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(genesis);
    v.push(VERSION);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(pgw_vk);
    v.extend_from_slice(pevm_address);
    v
}

/// This member's signature over [`message`], with its signer key (`sk64`, libsodium form).
pub fn sign(
    sk64: &[u8; 64],
    genesis: &[u8; 32],
    epoch: u64,
    pgw_vk: &[u8; 32],
    pevm_address: &[u8; 20],
) -> Result<[u8; 64], String> {
    let sig = ed25519_sign_detached(sk64, &message(genesis, epoch, pgw_vk, pevm_address)).map_err(str::to_string)?;
    // A key the daemon does not hold this member to would only be refused there; say so here.
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&sk64[32..]);
    if !ed25519_verify_consensus(&sig, &message(genesis, epoch, pgw_vk, pevm_address), &pubkey) {
        return Err("the key attestation does not verify under this node's signer key".into());
    }
    Ok(sig)
}

/// One record of the daemon's `bridge_get_standby` `attestations`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub pgw_vk: [u8; 32],
    pub pevm_address: [u8; 20],
    pub epoch: u64,
    pub voters: Vec<u32>,
    /// 0 while still collecting.
    pub attested_height: u64,
    /// How many members its committee shares with the live owner's, when known.
    pub overlap_with_owner: Option<u64>,
}

/// Where a key stands for one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Its committee reached the threshold: nothing more for anyone to send.
    Attested,
    /// This member is counted; the others are still to come.
    Counted,
    /// This member has not attested it yet.
    Missing,
}

/// Where the key (`epoch`, `pgw_vk`, `pevm_address`) stands for member `voter`.
pub fn status(records: &[Record], epoch: u64, pgw_vk: &[u8; 32], pevm_address: &[u8; 20], voter: u16) -> Status {
    match records
        .iter()
        .find(|r| r.epoch == epoch && r.pgw_vk == *pgw_vk && r.pevm_address == *pevm_address)
    {
        Some(r) if r.attested_height != 0 => Status::Attested,
        Some(r) if r.voters.contains(&u32::from(voter)) => Status::Counted,
        _ => Status::Missing,
    }
}

/// The record of the committee holding gateway key `pgw_vk`: the first to reach its
/// threshold for it, as consensus decides.
pub fn holder<'a>(records: &'a [Record], pgw_vk: &[u8; 32]) -> Option<&'a Record> {
    records
        .iter()
        .filter(|r| r.pgw_vk == *pgw_vk && r.attested_height != 0)
        .min_by_key(|r| r.attested_height)
}

/// The records of a `bridge_get_standby` JSON-RPC result; None if it has no `attestations`.
#[cfg(feature = "evm-watcher")]
pub fn parse_records(result: &serde_json::Value) -> Option<Vec<Record>> {
    fn bytes<const N: usize>(v: &serde_json::Value) -> Option<[u8; N]> {
        let s = v.as_str()?;
        if s.len() != 2 * N || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(out)
    }
    let mut out = Vec::new();
    for r in result.get("attestations")?.as_array()? {
        out.push(Record {
            pgw_vk: bytes(r.get("pgw_vk")?)?,
            pevm_address: bytes(r.get("pevm_address")?)?,
            epoch: r.get("epoch")?.as_u64()?,
            voters: r
                .get("voters")?
                .as_array()?
                .iter()
                .map(|v| v.as_u64().and_then(|v| u32::try_from(v).ok()))
                .collect::<Option<_>>()?,
            attested_height: r.get("attested_height")?.as_u64()?,
            overlap_with_owner: r.get("overlap_with_owner").and_then(serde_json::Value::as_u64),
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_is_the_consensus_layout() {
        let m = message(&[1; 32], 0x0102, &[2; 32], &[3; 20]);
        assert_eq!(m.len(), DOMAIN.len() + 32 + 1 + 8 + 32 + 20);
        assert!(m.starts_with(b"bridge_key_attestation_v1"));
        let rest = &m[DOMAIN.len()..];
        assert_eq!(&rest[..32], &[1; 32]);
        assert_eq!(rest[32], 0, "version");
        assert_eq!(&rest[33..41], &[0x02, 0x01, 0, 0, 0, 0, 0, 0], "epoch, little-endian");
        assert_eq!(&rest[41..73], &[2; 32]);
        assert_eq!(&rest[73..], &[3; 20]);
        assert_ne!(m, message(&[9; 32], 0x0102, &[2; 32], &[3; 20]), "bound to the network");
    }

    #[test]
    fn a_signature_verifies_under_the_members_key() {
        crate::ffi::ensure_init().unwrap();
        let (pk, sk) = crate::ffi::ed25519_keypair().unwrap();
        let sig = sign(&sk, &[1; 32], 4, &[2; 32], &[3; 20]).unwrap();
        assert!(ed25519_verify_consensus(&sig, &message(&[1; 32], 4, &[2; 32], &[3; 20]), &pk));
        assert!(!ed25519_verify_consensus(&sig, &message(&[1; 32], 5, &[2; 32], &[3; 20]), &pk));
    }

    #[test]
    fn a_member_attests_until_counted_and_the_holder_is_the_first_attested() {
        let rec = |epoch, voters: Vec<u32>, h| Record {
            pgw_vk: [2; 32],
            pevm_address: [3; 20],
            epoch,
            voters,
            attested_height: h,
            overlap_with_owner: None,
        };
        let records = vec![rec(4, vec![0, 2], 0)];
        assert_eq!(status(&records, 4, &[2; 32], &[3; 20], 1), Status::Missing);
        assert_eq!(status(&records, 4, &[2; 32], &[3; 20], 2), Status::Counted);
        assert_eq!(status(&records, 4, &[2; 32], &[4; 20], 2), Status::Missing, "another address");
        assert_eq!(status(&[], 4, &[2; 32], &[3; 20], 0), Status::Missing);
        assert!(holder(&records, &[2; 32]).is_none(), "collecting is not attested");

        let records = vec![rec(5, vec![0, 1, 2, 3], 90), rec(4, vec![0, 1, 2, 3], 80)];
        assert_eq!(status(&records, 4, &[2; 32], &[3; 20], 5), Status::Attested);
        assert_eq!(holder(&records, &[2; 32]).unwrap().epoch, 4);
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn the_daemons_records_parse() {
        let v = serde_json::json!({
            "attestations": [
                { "pgw_vk": "02".repeat(32), "pevm_address": "03".repeat(20), "epoch": 4,
                  "voters": [0, 2], "attested_height": 0, "overlap_with_owner": 1 },
                { "pgw_vk": "05".repeat(32), "pevm_address": "06".repeat(20), "epoch": 5,
                  "voters": [], "attested_height": 7 }
            ]
        });
        let r = parse_records(&v).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].voters, vec![0, 2]);
        assert_eq!(r[0].overlap_with_owner, Some(1));
        assert_eq!(r[1].pgw_vk, [5; 32]);
        assert_eq!(r[1].overlap_with_owner, None);
        assert!(parse_records(&serde_json::json!({})).is_none());
        assert!(parse_records(&serde_json::json!({ "attestations": [{ "pgw_vk": "02" }] })).is_none());
    }
}
