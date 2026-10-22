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

/// The key the live committee should name as its standby: attested, newer than the owner's
/// (`owner_epoch`; an older key was generated before it and has served already, or never
/// will), not the owner's own, and from a committee that shares at most `limit` members with
/// the owner's. The newest such; consensus applies the same overlap rule, and every live
/// member reads the same records, so they all pick the same one.
pub fn pick_standby<'a>(records: &'a [Record], owner_vk: &[u8; 32], owner_epoch: u64, limit: u64) -> Option<&'a Record> {
    records
        .iter()
        .filter(|r| r.attested_height != 0 && r.pgw_vk != *owner_vk && r.epoch > owner_epoch)
        .filter(|r| r.overlap_with_owner.is_some_and(|o| o <= limit))
        // The first committee to attest a key holds it; a later attestation of the same key by
        // another committee says nothing new.
        .filter(|r| holder(records, &r.pgw_vk).is_some_and(|h| h == *r))
        .max_by_key(|r| (r.epoch, std::cmp::Reverse(r.attested_height)))
}

/// What the daemon's `bridge_get_standby` says about the bridge gateway and the current
/// committee, beyond the attestation records.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StandbyView {
    pub owner_key: Option<[u8; 32]>,
    /// The epoch of the committee holding the owner key, once attested.
    pub owner_epoch: Option<u64>,
    pub standby_named: bool,
    pub committee_epoch: u64,
    /// How many members the current committee shares with the owner's, when known.
    pub committee_overlap: Option<u64>,
    pub overlap_limit: u64,
}

/// Whether the current committee should generate the next standby key now: Ok, or why not.
/// It should when no standby is named and none is waiting to be, and it is a newer committee
/// than the owner's that shares few enough members with it to be a standby consensus accepts.
pub fn standby_dkg_due(view: &StandbyView, records: &[Record]) -> Result<(), String> {
    if view.standby_named {
        return Err("a standby is named".into());
    }
    let (Some(owner), Some(owner_epoch)) = (view.owner_key, view.owner_epoch) else {
        return Err("the gateway owner's key is not attested yet".into());
    };
    if view.committee_epoch <= owner_epoch {
        return Err(format!(
            "the current committee (epoch {}) is not newer than the owner's ({owner_epoch})",
            view.committee_epoch
        ));
    }
    match view.committee_overlap {
        Some(o) if o <= view.overlap_limit => {}
        Some(o) => {
            return Err(format!(
                "the current committee shares {o} members with the owner's; at most {} may",
                view.overlap_limit
            ))
        }
        None => return Err("the current committee's overlap with the owner's is unknown".into()),
    }
    if pick_standby(records, &owner, owner_epoch, view.overlap_limit).is_some() {
        return Err("an attested key is waiting to be named".into());
    }
    if records.iter().any(|r| r.epoch >= view.committee_epoch) {
        return Err("a key of this committee is being attested".into());
    }
    Ok(())
}

/// The [`StandbyView`] of a `bridge_get_standby` JSON-RPC result.
#[cfg(feature = "evm-watcher")]
pub fn parse_view(result: &serde_json::Value) -> Option<StandbyView> {
    let key = |k: &str| -> Option<[u8; 32]> {
        let s = result.get(k)?.as_str()?;
        if s.len() != 64 || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(out)
    };
    Some(StandbyView {
        owner_key: key("owner_key"),
        owner_epoch: result.get("owner_epoch").and_then(serde_json::Value::as_u64),
        standby_named: result.get("standby_key").is_some(),
        committee_epoch: result.get("committee_epoch")?.as_u64()?,
        committee_overlap: result.get("committee_overlap").and_then(serde_json::Value::as_u64),
        overlap_limit: result.get("overlap_limit")?.as_u64()?,
    })
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

    #[test]
    fn the_standby_is_the_newest_attested_key_within_the_overlap_limit() {
        let rec = |vk: u8, epoch, h, overlap| Record {
            pgw_vk: [vk; 32],
            pevm_address: [vk; 20],
            epoch,
            voters: vec![],
            attested_height: h,
            overlap_with_owner: overlap,
        };
        let owner = [1; 32];
        let records = vec![
            rec(1, 4, 10, Some(20)), // the owner itself
            rec(2, 3, 11, Some(0)),  // older than the owner
            rec(3, 6, 30, Some(2)),
            rec(4, 7, 40, Some(9)),  // too much in common
            rec(5, 8, 0, Some(0)),   // still collecting
            rec(6, 5, 20, None),     // committee unknown
        ];
        assert_eq!(pick_standby(&records, &owner, 4, 6).unwrap().pgw_vk, [3; 32]);
        assert_eq!(pick_standby(&records, &owner, 4, 9).unwrap().pgw_vk, [4; 32]);
        assert!(pick_standby(&records, &owner, 6, 6).is_none(), "nothing newer than the owner");

        // A key a second committee attested later still belongs to the first.
        let mut records = vec![rec(3, 6, 30, Some(2))];
        records.push(Record { epoch: 7, attested_height: 25, ..rec(3, 7, 25, Some(1)) });
        let pick = pick_standby(&records, &owner, 4, 6).unwrap();
        assert_eq!((pick.epoch, pick.attested_height), (7, 25), "epoch 7 reached its threshold first");
    }

    #[test]
    fn the_next_standby_is_generated_by_a_newer_committee_that_barely_overlaps_and_only_once() {
        let view = StandbyView {
            owner_key: Some([1; 32]),
            owner_epoch: Some(4),
            standby_named: false,
            committee_epoch: 6,
            committee_overlap: Some(2),
            overlap_limit: 6,
        };
        assert_eq!(standby_dkg_due(&view, &[]), Ok(()));
        let no = |v: &StandbyView, r: &[Record]| standby_dkg_due(v, r).unwrap_err();
        assert!(no(&StandbyView { standby_named: true, ..view.clone() }, &[]).contains("named"));
        assert!(no(&StandbyView { owner_epoch: None, ..view.clone() }, &[]).contains("not attested"));
        assert!(no(&StandbyView { committee_epoch: 4, ..view.clone() }, &[]).contains("not newer"));
        assert!(no(&StandbyView { committee_overlap: Some(7), ..view.clone() }, &[]).contains("at most 6"));
        assert!(no(&StandbyView { committee_overlap: None, ..view.clone() }, &[]).contains("unknown"));

        let rec = |epoch, h, overlap| Record {
            pgw_vk: [9; 32],
            pevm_address: [9; 20],
            epoch,
            voters: vec![],
            attested_height: h,
            overlap_with_owner: overlap,
        };
        assert!(no(&view, &[rec(5, 50, Some(1))]).contains("waiting to be named"));
        assert!(no(&view, &[rec(6, 0, None)]).contains("being attested"));
        // An older committee's key that cannot be a standby does not hold this one back.
        assert_eq!(standby_dkg_due(&view, &[rec(5, 50, Some(9))]), Ok(()));
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn the_daemons_view_parses() {
        let v = serde_json::json!({
            "owner_key": "01".repeat(32), "owner_epoch": 4, "committee_epoch": 6,
            "committee_overlap": 2, "overlap_limit": 6, "threshold": 14, "attestations": []
        });
        let view = parse_view(&v).unwrap();
        assert_eq!(view.owner_key, Some([1; 32]));
        assert!(!view.standby_named);
        assert_eq!((view.committee_epoch, view.committee_overlap, view.overlap_limit), (6, Some(2), 6));
        let mut named = v.clone();
        named["standby_key"] = serde_json::json!("02".repeat(32));
        assert!(parse_view(&named).unwrap().standby_named);
    }
}
