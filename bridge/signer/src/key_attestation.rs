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
//!
//! A standby key comes from a standby round: while the bridge has no working standby, consensus
//! draws a committee every few blocks, from operators outside the owner's committee. Its
//! members first check in (version 2, no key yet) in the round's first blocks, to say their
//! signer is running; the members that did generate the key, and attest it naming the round
//! (`round_height`, its start) within the round's window.

use crate::ffi::{ed25519_sign_detached, ed25519_verify_consensus};

/// `hashkey::BRIDGE_KEY_ATTESTATION` in beldexd.
pub const DOMAIN: &[u8] = b"bridge_key_attestation_v1";
/// `tx_extra_bridge_key_attestation::version` of an epoch committee's attestation.
pub const VERSION: u8 = 0;
/// The version of a standby round committee's attestation.
pub const ROUND_VERSION: u8 = 1;
/// The version of a standby round member's check-in (`BRIDGE_STANDBY_CHECKIN_VERSION`).
pub const CHECKIN_VERSION: u8 = 2;

/// The bytes every member of committee `epoch` signs:
/// `DOMAIN ‖ genesis(32) ‖ version(u8) ‖ epoch(u64 LE) ‖ pgw_vk(32) ‖ pevm_address(20)`, and for
/// a standby round (`round_height` != 0) `‖ round_height(u64 LE)`.
/// The member is not in it: all sign the same statement.
pub fn message(genesis: &[u8; 32], epoch: u64, round_height: u64, pgw_vk: &[u8; 32], pevm_address: &[u8; 20]) -> Vec<u8> {
    let version = if round_height != 0 { ROUND_VERSION } else { VERSION };
    message_of(version, genesis, epoch, round_height, pgw_vk, pevm_address)
}

/// The bytes a member of the standby round at `round_height` signs to check in: the
/// attestation layout with version 2 and no key, which therefore never reads as an attestation.
pub fn checkin_message(genesis: &[u8; 32], epoch: u64, round_height: u64) -> Vec<u8> {
    message_of(CHECKIN_VERSION, genesis, epoch, round_height, &[0; 32], &[0; 20])
}

fn message_of(version: u8, genesis: &[u8; 32], epoch: u64, round_height: u64, pgw_vk: &[u8; 32], pevm_address: &[u8; 20]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + 32 + 1 + 8 + 32 + 20 + 8);
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(genesis);
    v.push(version);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(pgw_vk);
    v.extend_from_slice(pevm_address);
    if round_height != 0 {
        v.extend_from_slice(&round_height.to_le_bytes());
    }
    v
}

/// This member's signature over [`message`], with its signer key (`sk64`, libsodium form).
pub fn sign(
    sk64: &[u8; 64],
    genesis: &[u8; 32],
    epoch: u64,
    round_height: u64,
    pgw_vk: &[u8; 32],
    pevm_address: &[u8; 20],
) -> Result<[u8; 64], String> {
    sign_bytes(sk64, &message(genesis, epoch, round_height, pgw_vk, pevm_address))
}

/// This member's check-in for the standby round at `round_height` (in epoch `epoch`), signed
/// with its signer key: it says the signer is running and will take part in the round's key.
pub fn sign_checkin(sk64: &[u8; 64], genesis: &[u8; 32], epoch: u64, round_height: u64) -> Result<[u8; 64], String> {
    sign_bytes(sk64, &checkin_message(genesis, epoch, round_height))
}

fn sign_bytes(sk64: &[u8; 64], msg: &[u8]) -> Result<[u8; 64], String> {
    let sig = ed25519_sign_detached(sk64, msg).map_err(str::to_string)?;
    // A key the daemon does not hold this member to would only be refused there; say so here.
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&sk64[32..]);
    if !ed25519_verify_consensus(&sig, msg, &pubkey) {
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
    /// The standby round whose committee generated it (its start); 0 for an epoch committee.
    pub round_height: u64,
    /// The height whose committee generated it: later means a newer committee.
    pub committee_height: u64,
    pub voters: Vec<u32>,
    /// 0 while still collecting.
    pub attested_height: u64,
    /// How many of its committee's members are run by operators of the live owner's
    /// committee, when known (consensus counts operators, not nodes).
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

/// Where the key (`epoch`, `round_height`, `pgw_vk`, `pevm_address`) stands for member `voter`.
pub fn status(records: &[Record], epoch: u64, round_height: u64, pgw_vk: &[u8; 32], pevm_address: &[u8; 20], voter: u16) -> Status {
    match records
        .iter()
        .find(|r| r.epoch == epoch && r.round_height == round_height && r.pgw_vk == *pgw_vk && r.pevm_address == *pevm_address)
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

/// A standby round still taking attestations, as `bridge_get_standby` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StandbyRound {
    /// The round's start.
    pub round_height: u64,
    pub members: Vec<[u8; 32]>,
    /// The members that have checked in: once check-ins close, the ones that generate its key.
    pub checked_in: Vec<[u8; 32]>,
}

/// What the daemon's `bridge_get_standby` says about the bridge gateway and its standby, beyond
/// the attestation records.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StandbyView {
    pub owner_key: Option<[u8; 32]>,
    /// The epoch of the committee holding the owner key, once attested.
    pub owner_epoch: Option<u64>,
    /// The standby the gateway names, if any.
    pub standby_key: Option<[u8; 32]>,
    /// It has neither been named nor proved it can sign for a day: treated as gone.
    pub standby_stale: bool,
    /// The chain tip this view is for.
    pub height: u64,
    /// How many blocks from its start a standby round takes attestations.
    pub round_window: u64,
    /// How many blocks from its start a standby round takes check-ins (0 from a daemon without).
    pub checkin_blocks: u64,
    /// The standby rounds still taking attestations.
    pub rounds: Vec<StandbyRound>,
    /// The attested key waiting to be named: the one consensus will accept. Consensus decides
    /// this (first_waiting_bridge_key) and says so, so no member can come to another answer.
    pub waiting_key: Option<[u8; 32]>,
}

/// The standby round a member should check in to now: Ok with its start, or why none.
/// Consensus draws a round only while a standby is due, so this only has to find the latest one
/// and refuse to join it once a check-in sent now could no longer land in its check-in blocks.
/// Whether this node is on its committee is for the caller.
pub fn standby_round_due(view: &StandbyView) -> Result<u64, String> {
    if view.standby_key.is_some() && !view.standby_stale {
        return Err("a standby is named".into());
    }
    if view.owner_key.is_none() || view.owner_epoch.is_none() {
        return Err("the gateway owner's key is not attested yet".into());
    }
    if view.waiting_key.is_some() {
        return Err("an attested key is waiting to be named".into());
    }
    // A round above the tip is the mark of a block still being checked: the daemon applies a
    // block to its state before deciding whether to keep it, and it may yet refuse this one.
    let Some(round) = view.rounds.iter().map(|r| r.round_height).filter(|&r| r <= view.height).max() else {
        return Err("no standby round is open".into());
    };
    if view.checkin_blocks == 0 {
        return Err("the daemon reports no check-in blocks for standby rounds: update beldexd".into());
    }
    // A check-in sent now lands in the next block at the earliest, and only blocks up to
    // round + checkin_blocks take one.
    if view.height >= round + view.checkin_blocks {
        return Err(format!("standby round {round} started too long ago to check in; waiting for the next"));
    }
    Ok(round)
}

/// The standby the live committee should have now: the named one while it works, else the key
/// consensus says is waiting to be named. None if there is nothing to name.
pub fn standby_target<'a>(view: &StandbyView, records: &'a [Record]) -> Option<&'a Record> {
    view.owner_key?;
    view.owner_epoch?;
    match view.standby_key {
        Some(k) if !view.standby_stale => holder(records, &k),
        _ => holder(records, view.waiting_key.as_ref()?),
    }
}

/// Whether the named standby should prove it can still sign now: a proof slot is open
/// (`alive_height`, 0 for none) that no accepted proof covers yet (`last_seen`). A key that
/// reads stale is being replaced and proves nothing more: its holders step aside, and a proof
/// from holders that happen to come back in that wait would revive it or not depending only on
/// when a slot falls. Its own running takeover is the exception: only its holders can finish it.
pub fn standby_should_prove(alive_height: u64, last_seen: Option<u64>, stale: bool, own_takeover_running: bool) -> bool {
    if stale && !own_takeover_running {
        return false;
    }
    alive_height != 0 && last_seen.is_none_or(|seen| seen < alive_height)
}

/// Whether a standby share set should step aside, and why, so its members rejoin the pool and
/// can be drawn for the next standby. `ours_height` is the height whose committee holds it and
/// `ours_round` its standby round (0 for an epoch committee's). It steps aside when its key is
/// the named standby but has gone stale (its holders can no longer sign together), when a newer
/// key is named in its place, or, for a round's key, when it lost: another key was named, or it
/// was attested but consensus no longer has it waiting, or its round closed without attesting
/// it. Never for the owner's key: that set is promoted, not retired.
pub fn standby_set_retired(view: &StandbyView, records: &[Record], ours: &[u8; 32], ours_height: u64, ours_round: u64) -> Option<String> {
    if view.owner_key.as_ref() == Some(ours) {
        return None;
    }
    if view.standby_key.as_ref() == Some(ours) {
        return view
            .standby_stale
            .then(|| "this standby key has not proved it can sign for a day: its holders cannot sign together".to_string());
    }
    if ours_round == 0 {
        let named = holder(records, view.standby_key.as_ref()?)?;
        return (named.committee_height > ours_height)
            .then(|| format!("a newer standby (committee height {}) is named in its place", named.committee_height));
    }
    // What consensus has waiting cannot be judged without an attested owner.
    if view.owner_epoch.is_none() || view.waiting_key.as_ref() == Some(ours) {
        return None;
    }
    if view.standby_key.is_some() && !view.standby_stale {
        return Some(format!("another key is named as the standby, not round {ours_round}'s"));
    }
    if holder(records, ours).is_some() {
        return Some(format!("round {ours_round}'s key was attested, but is no longer the one waiting to be named"));
    }
    (view.height > ours_round + view.round_window).then(|| format!("standby round {ours_round} closed without attesting this key"))
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
    let keys = |list: Option<&serde_json::Value>| -> Option<Vec<[u8; 32]>> {
        let mut out = Vec::new();
        for m in list.and_then(serde_json::Value::as_array).into_iter().flatten() {
            let s = m.as_str()?;
            if s.len() != 64 || !s.is_ascii() {
                return None;
            }
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
            }
            out.push(k);
        }
        Some(out)
    };
    let mut rounds = Vec::new();
    for r in result.get("standby_rounds").and_then(serde_json::Value::as_array).into_iter().flatten() {
        rounds.push(StandbyRound {
            round_height: r.get("round_height")?.as_u64()?,
            members: keys(Some(r.get("members")?))?,
            checked_in: keys(r.get("checked_in"))?,
        });
    }
    Some(StandbyView {
        owner_key: key("owner_key"),
        owner_epoch: result.get("owner_epoch").and_then(serde_json::Value::as_u64),
        standby_key: key("standby_key"),
        standby_stale: result.get("standby_stale").and_then(serde_json::Value::as_bool).unwrap_or(false),
        height: result.get("height")?.as_u64()?,
        round_window: result.get("standby_round_window")?.as_u64()?,
        checkin_blocks: result.get("standby_round_checkin").and_then(serde_json::Value::as_u64).unwrap_or(0),
        rounds,
        waiting_key: key("waiting_key"),
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
            round_height: r.get("round_height").and_then(serde_json::Value::as_u64).unwrap_or(0),
            committee_height: r.get("committee_height").and_then(serde_json::Value::as_u64).unwrap_or(0),
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
    fn a_check_in_is_the_attestation_layout_with_version_2_and_no_key() {
        let g = [9u8; 32];
        let m = checkin_message(&g, 1, 130);
        assert_eq!(m.len(), DOMAIN.len() + 32 + 1 + 8 + 32 + 20 + 8);
        assert_eq!(m[DOMAIN.len() + 32], CHECKIN_VERSION);
        assert!(m[DOMAIN.len() + 32 + 1 + 8..DOMAIN.len() + 32 + 1 + 8 + 52].iter().all(|&b| b == 0), "no key");
        assert_eq!(&m[m.len() - 8..], &130u64.to_le_bytes());
        // Never the bytes of an attestation, even of an empty key in the same round.
        assert_ne!(m, message(&g, 1, 130, &[0; 32], &[0; 20]));
        assert_ne!(checkin_message(&g, 1, 140), m, "bound to its round");
    }

    #[test]
    fn the_message_is_the_consensus_layout() {
        let m = message(&[1; 32], 0x0102, 0, &[2; 32], &[3; 20]);
        assert_eq!(m.len(), DOMAIN.len() + 32 + 1 + 8 + 32 + 20);
        assert!(m.starts_with(b"bridge_key_attestation_v1"));
        let rest = &m[DOMAIN.len()..];
        assert_eq!(&rest[..32], &[1; 32]);
        assert_eq!(rest[32], 0, "version");
        assert_eq!(&rest[33..41], &[0x02, 0x01, 0, 0, 0, 0, 0, 0], "epoch, little-endian");
        assert_eq!(&rest[41..73], &[2; 32]);
        assert_eq!(&rest[73..], &[3; 20]);
        assert_ne!(m, message(&[9; 32], 0x0102, 0, &[2; 32], &[3; 20]), "bound to the network");

        // A standby round's: version 1, the round's start at the end.
        let r = message(&[1; 32], 0x0102, 0x0304, &[2; 32], &[3; 20]);
        assert_eq!(r.len(), m.len() + 8);
        assert_eq!(r[DOMAIN.len() + 32], 1, "version");
        assert_eq!(&r[m.len()..], &[0x04, 0x03, 0, 0, 0, 0, 0, 0], "round, little-endian");
        assert_ne!(r, message(&[1; 32], 0x0102, 0x0305, &[2; 32], &[3; 20]), "bound to the round");
    }

    #[test]
    fn a_signature_verifies_under_the_members_key() {
        crate::ffi::ensure_init().unwrap();
        let (pk, sk) = crate::ffi::ed25519_keypair().unwrap();
        let sig = sign(&sk, &[1; 32], 4, 0, &[2; 32], &[3; 20]).unwrap();
        assert!(ed25519_verify_consensus(&sig, &message(&[1; 32], 4, 0, &[2; 32], &[3; 20]), &pk));
        assert!(!ed25519_verify_consensus(&sig, &message(&[1; 32], 5, 0, &[2; 32], &[3; 20]), &pk));
        let sig = sign(&sk, &[1; 32], 4, 130, &[2; 32], &[3; 20]).unwrap();
        assert!(ed25519_verify_consensus(&sig, &message(&[1; 32], 4, 130, &[2; 32], &[3; 20]), &pk));
        assert!(!ed25519_verify_consensus(&sig, &message(&[1; 32], 4, 140, &[2; 32], &[3; 20]), &pk));
    }

    #[test]
    fn a_member_attests_until_counted_and_the_holder_is_the_first_attested() {
        let rec = |epoch, voters: Vec<u32>, h| Record {
            pgw_vk: [2; 32],
            pevm_address: [3; 20],
            epoch,
            round_height: 0,
            committee_height: 0,
            voters,
            attested_height: h,
            overlap_with_owner: None,
        };
        let records = vec![rec(4, vec![0, 2], 0)];
        assert_eq!(status(&records, 4, 0, &[2; 32], &[3; 20], 1), Status::Missing);
        assert_eq!(status(&records, 4, 0, &[2; 32], &[3; 20], 2), Status::Counted);
        assert_eq!(status(&records, 4, 0, &[2; 32], &[4; 20], 2), Status::Missing, "another address");
        assert_eq!(status(&[], 4, 0, &[2; 32], &[3; 20], 0), Status::Missing);
        assert!(holder(&records, &[2; 32]).is_none(), "collecting is not attested");

        let records = vec![rec(5, vec![0, 1, 2, 3], 90), rec(4, vec![0, 1, 2, 3], 80)];
        assert_eq!(status(&records, 4, 0, &[2; 32], &[3; 20], 5), Status::Attested);
        assert_eq!(holder(&records, &[2; 32]).unwrap().epoch, 4);
        // A round's key is its own claim, apart from the epoch's.
        assert_eq!(status(&records, 4, 130, &[2; 32], &[3; 20], 5), Status::Missing);
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn the_daemons_records_parse() {
        let v = serde_json::json!({
            "attestations": [
                { "pgw_vk": "02".repeat(32), "pevm_address": "03".repeat(20), "epoch": 4,
                  "voters": [0, 2], "attested_height": 0, "overlap_with_owner": 1 },
                { "pgw_vk": "05".repeat(32), "pevm_address": "06".repeat(20), "epoch": 5,
                  "round_height": 610, "committee_height": 610, "voters": [], "attested_height": 7 }
            ]
        });
        let r = parse_records(&v).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].voters, vec![0, 2]);
        assert_eq!(r[0].overlap_with_owner, Some(1));
        assert_eq!(r[1].pgw_vk, [5; 32]);
        assert_eq!(r[1].overlap_with_owner, None);
        assert_eq!((r[0].round_height, r[1].round_height, r[1].committee_height), (0, 610, 610));
        assert!(parse_records(&serde_json::json!({})).is_none());
        assert!(parse_records(&serde_json::json!({ "attestations": [{ "pgw_vk": "02" }] })).is_none());
    }

    fn rec(vk: u8, epoch: u64, round_height: u64, committee_height: u64, h: u64) -> Record {
        Record {
            pgw_vk: [vk; 32],
            pevm_address: [vk; 20],
            epoch,
            round_height,
            committee_height,
            voters: vec![],
            attested_height: h,
            overlap_with_owner: None,
        }
    }

    fn view() -> StandbyView {
        StandbyView {
            owner_key: Some([1; 32]),
            owner_epoch: Some(4),
            height: 131,
            round_window: 10,
            checkin_blocks: 2,
            rounds: vec![StandbyRound { round_height: 130, members: vec![[7; 32]], checked_in: vec![] }],
            ..StandbyView::default()
        }
    }

    #[test]
    fn a_member_joins_the_latest_round_only_while_it_is_new() {
        assert_eq!(standby_round_due(&view()), Ok(130));
        let no = |v: &StandbyView| standby_round_due(v).unwrap_err();
        assert!(no(&StandbyView { standby_key: Some([8; 32]), ..view() }).contains("named"));
        assert_eq!(standby_round_due(&StandbyView { standby_key: Some([8; 32]), standby_stale: true, ..view() }), Ok(130), "a stale standby is no standby");
        assert!(no(&StandbyView { owner_epoch: None, ..view() }).contains("not attested"));
        assert!(no(&StandbyView { waiting_key: Some([5; 32]), ..view() }).contains("waiting to be named"));
        assert!(no(&StandbyView { rounds: vec![], ..view() }).contains("no standby round"));

        // Rounds overlap by their windows: the latest is the one to join.
        let two = StandbyView {
            rounds: vec![StandbyRound { round_height: 130, ..Default::default() }, StandbyRound { round_height: 140, ..Default::default() }],
            height: 140,
            ..view()
        };
        assert_eq!(standby_round_due(&two), Ok(140));

        // A round from a block the daemon has not kept yet is not joined, whether or not an
        // older one is still in the state beside it.
        assert!(no(&StandbyView { height: 129, ..view() }).contains("no standby round"));
        assert_eq!(standby_round_due(&StandbyView { height: 131, ..two.clone() }), Ok(130));

        // A check-in sent now must land within the round's check-in blocks (130, 132]: from the
        // round's block or the next, not later.
        assert_eq!(standby_round_due(&StandbyView { height: 130, ..view() }), Ok(130));
        assert_eq!(standby_round_due(&StandbyView { height: 131, ..view() }), Ok(130));
        assert!(no(&StandbyView { height: 132, ..view() }).contains("too long ago"));
        assert!(no(&StandbyView { checkin_blocks: 0, ..view() }).contains("update beldexd"));
    }

    #[test]
    fn the_target_is_the_working_standby_else_what_consensus_has_waiting() {
        let records = vec![rec(1, 4, 0, 480, 10), rec(5, 5, 610, 610, 620), rec(6, 5, 620, 620, 630)];
        let named = StandbyView { standby_key: Some([6; 32]), ..view() };
        assert_eq!(standby_target(&named, &records).unwrap().pgw_vk, [6; 32]);
        // Consensus's choice, not the newest: a later round's key can lose to an earlier one.
        let waiting = StandbyView { waiting_key: Some([5; 32]), ..view() };
        assert_eq!(standby_target(&waiting, &records).unwrap().pgw_vk, [5; 32]);
        let stale = StandbyView { standby_key: Some([6; 32]), standby_stale: true, waiting_key: Some([5; 32]), ..view() };
        assert_eq!(standby_target(&stale, &records).unwrap().pgw_vk, [5; 32], "replaced, never by itself");
        assert!(standby_target(&StandbyView { standby_key: Some([6; 32]), standby_stale: true, ..view() }, &records).is_none());
        assert!(standby_target(&view(), &records).is_none(), "nothing to name");
        assert!(standby_target(&StandbyView { owner_epoch: None, ..waiting }, &records).is_none(), "the owner must be attested");
    }

    #[cfg(feature = "evm-watcher")]
    #[test]
    fn the_daemons_view_parses() {
        let v = serde_json::json!({
            "owner_key": "01".repeat(32), "owner_epoch": 4, "height": 131, "standby_round_window": 10,
            "standby_round_checkin": 2,
            "standby_rounds": [{ "round": 1, "round_height": 130, "checkin_end": 132, "window_end": 140,
                                 "members": ["07".repeat(32), "08".repeat(32)], "checked_in": ["08".repeat(32)] }],
            "attestations": []
        });
        let got = parse_view(&v).unwrap();
        assert_eq!(got.owner_key, Some([1; 32]));
        assert_eq!((got.standby_key, got.standby_stale, got.waiting_key), (None, false, None));
        assert_eq!((got.height, got.round_window), (131, 10));
        assert_eq!(got.checkin_blocks, 2);
        assert_eq!(got.rounds, vec![StandbyRound { round_height: 130, members: vec![[7; 32], [8; 32]], checked_in: vec![[8; 32]] }]);
        let mut named = v.clone();
        named["standby_key"] = serde_json::json!("02".repeat(32));
        named["standby_stale"] = serde_json::json!(true);
        named["waiting_key"] = serde_json::json!("03".repeat(32));
        let named = parse_view(&named).unwrap();
        assert_eq!((named.standby_key, named.standby_stale, named.waiting_key), (Some([2; 32]), true, Some([3; 32])));
        assert!(parse_view(&serde_json::json!({ "height": 1 })).is_none(), "no window");
    }

    #[test]
    fn an_epoch_committees_standby_steps_aside_when_stale_or_replaced() {
        let records = vec![rec(1, 4, 0, 480, 10), rec(5, 5, 0, 600, 50), rec(6, 6, 0, 720, 60)];
        let named = StandbyView { standby_key: Some([6; 32]), ..view() };
        let stale = StandbyView { standby_stale: true, ..named.clone() };
        assert!(standby_set_retired(&named, &records, &[6; 32], 720, 0).is_none(), "working");
        assert!(standby_set_retired(&stale, &records, &[6; 32], 720, 0).unwrap().contains("not proved"));
        assert!(standby_set_retired(&named, &records, &[5; 32], 600, 0).unwrap().contains("newer standby"));
        // A newer key does not step aside for an older named one, nor with none named.
        assert!(standby_set_retired(&StandbyView { standby_key: Some([5; 32]), ..view() }, &records, &[6; 32], 720, 0).is_none());
        assert!(standby_set_retired(&view(), &records, &[6; 32], 720, 0).is_none());
        // Nor does the owner's set.
        assert!(standby_set_retired(&stale, &records, &[1; 32], 480, 0).is_none());
    }

    #[test]
    fn a_rounds_set_steps_aside_once_it_has_lost() {
        let records = vec![rec(1, 4, 0, 480, 10), rec(5, 5, 610, 610, 620), rec(6, 5, 620, 620, 630)];
        let ours = |v: &StandbyView, vk: u8, round: u64| standby_set_retired(v, &records, &[vk; 32], round, round);

        // Still in the running: waiting, named, or collecting within its window.
        let waiting = StandbyView { waiting_key: Some([5; 32]), height: 640, ..view() };
        assert!(ours(&waiting, 5, 610).is_none());
        assert!(ours(&StandbyView { standby_key: Some([5; 32]), ..view() }, 5, 610).is_none());
        assert!(ours(&StandbyView { height: 650, ..view() }, 9, 650).is_none());
        assert!(ours(&StandbyView { height: 660, ..view() }, 9, 650).is_none(), "the window's last block");

        // Lost: another key is waiting, or named; never attested in time; left too long.
        assert!(ours(&waiting, 6, 620).unwrap().contains("no longer the one waiting"));
        assert!(ours(&StandbyView { standby_key: Some([5; 32]), ..view() }, 6, 620).unwrap().contains("another key is named"));
        assert!(ours(&StandbyView { height: 661, ..view() }, 9, 650).unwrap().contains("closed without attesting"));
        assert!(ours(&view(), 5, 610).unwrap().contains("no longer the one waiting"));

        // A stale named standby's holders go; another round's holders may be next, so stay put
        // while their key is the waiting one.
        let stale = StandbyView { standby_key: Some([6; 32]), standby_stale: true, waiting_key: Some([5; 32]), ..view() };
        assert!(ours(&stale, 6, 620).unwrap().contains("not proved"));
        assert!(ours(&stale, 5, 610).is_none());

        // Without an attested owner consensus has nothing waiting: not a loss. Nor is the owner's.
        assert!(ours(&StandbyView { owner_epoch: None, ..view() }, 5, 610).is_none());
        assert!(ours(&StandbyView { owner_key: Some([5; 32]), ..view() }, 5, 610).is_none());
    }

    #[test]
    fn a_stale_standby_proves_nothing_more_unless_its_takeover_runs() {
        // A slot is open and not yet proved: prove.
        assert!(standby_should_prove(120, Some(0), false, false));
        assert!(standby_should_prove(120, None, false, false));
        // Already proved for this slot, or no slot open: nothing to do.
        assert!(!standby_should_prove(120, Some(120), false, false));
        assert!(!standby_should_prove(0, None, false, false));
        // Stale: the key is being replaced, so returning holders do not revive it.
        assert!(!standby_should_prove(120, Some(0), true, false));
        // ...unless its own takeover runs: only its holders can complete that.
        assert!(standby_should_prove(120, Some(0), true, true));
    }
}
