//! Session message wire format + dispatch (plan §C.4 transport glue).
//!
//! The [`session`](crate::session) engine is a pure state machine driven by
//! event methods. This module is the layer that carries those events between the
//! committee's signers: a compact, std-only codec for a session message, and a
//! [`apply`] dispatcher that routes a decoded message into the right session
//! (enforcing **S14** per-leg isolation and dropping stale/duplicate messages,
//! as an async mesh requires). The actual bytes are moved by a
//! [`Transport`](crate::transport::Transport) — [`LoopbackTransport`] in tests,
//! the OMQ backend in production.
//!
//! Wire layout (fixed 48-byte header + variable body), little-endian:
//! ```text
//!   [0]      leg          (0 = Pevm, 1 = Pgw)          — S14 tag
//!   [1..9]   epoch        u64
//!   [9..41]  payload_hash [32]                          — session identity
//!   [41..45] attempt      u32                           — retry generation
//!   [45..47] from         u16                           — sender committee index
//!   [47]     type         (0 Propose,1 Ack,2 Nack,3 Round,4 Signature,5 DistAck)
//!   [48..]   body         (type-dependent)
//! ```

use crate::session::{NackReason, Session, SessionError};
use crate::transport::Leg;

/// The body of a session message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMsg {
    /// Leader → members: the exact payload to sign (S4 root; members verify it
    /// against their own independently-rebuilt payload before ACKing).
    Propose(Vec<u8>),
    /// Member → all: I accept the proposal.
    Ack,
    /// Member → all: I reject the proposal (with a reason for the transcript).
    Nack(NackReason),
    /// Member → all: my scheme-round contribution (opaque; CGGMP21 / FROST).
    Round(Vec<u8>),
    /// Aggregator → all: the combined signature.
    Signature(Vec<u8>),
    /// Member → all: I have the distributed signature.
    DistributeAck,
    /// Member → all: my ed25519 signature over an observed wBDX rotation (H.6.3).
    ///
    /// Not part of a signing session: each member observes the rotation on its own RPC
    /// and signs the same objective fact, and the threshold evidence is assembled by
    /// merging. It rides the session mesh because `payload_hash` already groups messages
    /// by exactly the right key — the hash of the canonical ack bytes — so signatures for
    /// two different rotations can never be pooled, and every frame is already
    /// authenticated under the sender's committee key.
    ///
    /// Body: `committee_index(u16 LE) ‖ signature(64)`.
    RotationAckSig(Vec<u8>),
}

/// A full, routable session message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireMsg {
    pub leg: Leg,
    pub epoch: u64,
    pub payload_hash: [u8; 32],
    pub attempt: u32,
    pub from: u16,
    pub body: SessionMsg,
}

/// Codec / dispatch failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Buffer too short / truncated body.
    Truncated,
    /// Unknown leg / message-type / nack-reason byte.
    BadTag,
}

const HEADER_LEN: usize = 48;

const T_PROPOSE: u8 = 0;
const T_ACK: u8 = 1;
const T_NACK: u8 = 2;
const T_ROUND: u8 = 3;
const T_SIGNATURE: u8 = 4;
const T_DIST_ACK: u8 = 5;
const T_ROTATION_ACK_SIG: u8 = 6;

fn leg_to_u8(l: Leg) -> u8 {
    match l {
        Leg::Pevm => 0,
        Leg::Pgw => 1,
    }
}
fn leg_from_u8(b: u8) -> Option<Leg> {
    match b {
        0 => Some(Leg::Pevm),
        1 => Some(Leg::Pgw),
        _ => None,
    }
}

impl WireMsg {
    /// Serialize to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 8);
        out.push(leg_to_u8(self.leg));
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.attempt.to_le_bytes());
        out.extend_from_slice(&self.from.to_le_bytes());
        match &self.body {
            SessionMsg::Propose(p) => {
                out.push(T_PROPOSE);
                push_bytes(&mut out, p);
            }
            SessionMsg::Ack => out.push(T_ACK),
            SessionMsg::Nack(r) => {
                out.push(T_NACK);
                out.push(r.to_u8());
            }
            SessionMsg::Round(b) => {
                out.push(T_ROUND);
                push_bytes(&mut out, b);
            }
            SessionMsg::Signature(b) => {
                out.push(T_SIGNATURE);
                push_bytes(&mut out, b);
            }
            SessionMsg::DistributeAck => out.push(T_DIST_ACK),
            SessionMsg::RotationAckSig(b) => {
                out.push(T_ROTATION_ACK_SIG);
                push_bytes(&mut out, b);
            }
        }
        out
    }

    /// Parse from bytes.
    pub fn decode(buf: &[u8]) -> Result<WireMsg, WireError> {
        if buf.len() < HEADER_LEN {
            return Err(WireError::Truncated);
        }
        let leg = leg_from_u8(buf[0]).ok_or(WireError::BadTag)?;
        let epoch = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&buf[9..41]);
        let attempt = u32::from_le_bytes(buf[41..45].try_into().unwrap());
        let from = u16::from_le_bytes(buf[45..47].try_into().unwrap());
        let ty = buf[47];
        let rest = &buf[HEADER_LEN..];

        let body = match ty {
            T_PROPOSE => SessionMsg::Propose(take_bytes(rest)?),
            T_ACK => SessionMsg::Ack,
            T_NACK => {
                let b = *rest.first().ok_or(WireError::Truncated)?;
                SessionMsg::Nack(NackReason::from_u8(b).ok_or(WireError::BadTag)?)
            }
            T_ROUND => SessionMsg::Round(take_bytes(rest)?),
            T_SIGNATURE => SessionMsg::Signature(take_bytes(rest)?),
            T_DIST_ACK => SessionMsg::DistributeAck,
            T_ROTATION_ACK_SIG => SessionMsg::RotationAckSig(take_bytes(rest)?),
            _ => return Err(WireError::BadTag),
        };
        Ok(WireMsg { leg, epoch, payload_hash, attempt, from, body })
    }
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn take_bytes(rest: &[u8]) -> Result<Vec<u8>, WireError> {
    if rest.len() < 4 {
        return Err(WireError::Truncated);
    }
    let n = u32::from_le_bytes(rest[0..4].try_into().unwrap()) as usize;
    let body = rest.get(4..4 + n).ok_or(WireError::Truncated)?;
    Ok(body.to_vec())
}

/// Dispatch failures distinct from benign drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// A message for the other key was routed here (S14 violation).
    WrongLeg,
    /// The message is for a different session (epoch / payload).
    NotForThisSession,
    /// A hard protocol violation from the engine (e.g. unknown member).
    Session(SessionError),
}

/// Route a decoded [`WireMsg`] into `session`, upholding S14 and treating
/// stale/duplicate/out-of-stage messages as benign drops (an async mesh delivers
/// those routinely). Hard violations (unknown member, wrong leg, wrong session)
/// are surfaced.
pub fn apply(session: &mut Session, wire: &WireMsg) -> Result<(), DispatchError> {
    // Snapshot the session identity (all Copy) so no immutable borrow is held
    // across the mutable engine calls below.
    let (sid_epoch, sid_ph, sid_attempt) = {
        let id = session.id();
        (id.epoch, id.payload_hash, id.attempt)
    };
    // S14: never accept a message tagged for the other leg.
    if !session.accepts_leg(wire.leg) {
        return Err(DispatchError::WrongLeg);
    }
    if wire.epoch != sid_epoch || wire.payload_hash != sid_ph {
        return Err(DispatchError::NotForThisSession);
    }
    // A message from a superseded attempt is stale — drop it silently.
    if wire.attempt != sid_attempt {
        return Ok(());
    }

    let from = wire.from as usize;
    let r = match &wire.body {
        // Informational: each member self-roots its own session with the payload
        // its watcher produced; a Propose is used by higher-level logic to decide
        // ACK vs NACK, so the raw dispatcher treats it as a no-op.
        SessionMsg::Propose(_) => Ok(()),
        SessionMsg::Ack => session.on_ack(from),
        SessionMsg::Nack(reason) => session.on_nack(from, *reason),
        SessionMsg::Round(bytes) => session.on_round_message(from, bytes.clone()),
        // Mesh authentication names the sender, not a valid aggregate. Only the
        // coordinator, after checking the bytes under the group key, may advance the
        // engine with `signature_ready`.
        SessionMsg::Signature(_) => Ok(()),
        SessionMsg::DistributeAck => session.on_distribute_ack(from),
        // Not a session message. It rides the same mesh for authentication and for the
        // grouping `payload_hash` gives, but it belongs to the rotation-ack collector,
        // which handles it before dispatch. Reaching here means no collector was
        // listening; ignore it rather than failing a live signing session.
        SessionMsg::RotationAckSig(_) => Ok(()),
    };

    match r {
        Ok(()) => Ok(()),
        // Late / duplicate / out-of-stage / post-terminal messages are normal in
        // an asynchronous mesh — drop them rather than erroring.
        Err(SessionError::WrongStage(_)) | Err(SessionError::Terminal(_)) => Ok(()),
        Err(e) => Err(DispatchError::Session(e)),
    }
}

/// Transport errors surfaced by a [`SessionTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshError {
    /// The peer index is not known to this transport.
    UnknownPeer(u16),
    /// A message could not be decoded off the wire.
    Decode(WireError),
    /// An inbound frame failed message authentication (S4): a forged `from`, a
    /// tampered body, an unknown sender, or a truncated frame. Dropped, never
    /// delivered to a session. Stringified to keep this enum std-only.
    Auth(String),
    /// Backend I/O failure (socket error, etc.), stringified so this stays free
    /// of any transport-crate types in the std-only interface.
    Io(String),
    /// The frame was not handed to these peers' connections, each with the reason (its
    /// queue is full, it is not connected, a socket error). Every other recipient got it.
    /// Retryable: re-sending to just these peers cannot duplicate a delivery.
    Undelivered(Vec<(u16, String)>),
}

impl MeshError {
    /// The peers a retry should go to, if this failure is one a retry can fix.
    pub fn undelivered_peers(&self) -> Option<Vec<u16>> {
        match self {
            MeshError::Undelivered(f) => Some(f.iter().map(|(p, _)| *p).collect()),
            _ => None,
        }
    }
}

impl std::fmt::Display for MeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeshError::UnknownPeer(p) => write!(f, "peer {p} is not in this mesh"),
            MeshError::Decode(e) => write!(f, "undecodable frame: {e:?}"),
            MeshError::Auth(e) => write!(f, "frame failed authentication: {e}"),
            MeshError::Io(e) => write!(f, "{e}"),
            MeshError::Undelivered(peers) => {
                write!(f, "not delivered to ")?;
                for (i, (p, why)) in peers.iter().enumerate() {
                    write!(f, "{}peer {p} ({why})", if i == 0 { "" } else { ", " })?;
                }
                Ok(())
            }
        }
    }
}

/// Moves [`WireMsg`]s between the committee's signers. Implemented by the
/// curve-authenticated OMQ mesh in production (`omq_mesh`), and by in-memory
/// doubles in tests. The session driver is written against this trait so it is
/// transport-agnostic.
pub trait SessionTransport {
    /// Send `msg` to every peer (not including self).
    fn broadcast(&mut self, msg: &WireMsg) -> Result<(), MeshError>;
    /// Send `msg` to a single peer by committee index.
    fn send_to(&mut self, peer_index: u16, msg: &WireMsg) -> Result<(), MeshError>;
    /// Non-blocking receive of the next inbound message, if any is ready.
    fn poll(&mut self) -> Result<Option<WireMsg>, MeshError>;
}

/// Report a failed send of a message that is sent again on a schedule anyway.
///
/// Only for those: a barrier HELLO (re-broadcast until every peer answers), a leader's
/// `Propose` (re-broadcast every tick), a rotation-ack signature (re-sent every sweep). A
/// lost copy is replaced by the next one, so logging it is the whole of the handling. A
/// message sent once must go through [`deliver`] (or the coordinator's re-send queue),
/// which retries the peers that missed it and reports the ones it could not reach.
pub fn note_send_failure(what: &str, r: Result<(), MeshError>) {
    if let Err(e) = r {
        eprintln!("  mesh send failed ({what}, sent again on schedule): {e}");
    }
}

/// What a connection barrier could not send, kept for its timeout error.
///
/// A barrier re-broadcasts its HELLO every ~150ms until every peer answers, so a peer
/// that is down would otherwise log hundreds of identical lines. Instead the latest
/// reason per peer is kept, and if the barrier gives up its error names both the peers
/// that never answered and the ones this node could not even send to.
#[derive(Debug, Default)]
pub struct BarrierSendFailures {
    last: std::collections::BTreeMap<u16, String>,
    /// The latest failure that named no peer (the frame could not be signed, say).
    other: Option<String>,
    count: u64,
}

impl BarrierSendFailures {
    /// `; HELLO not delivered to peer 3 (…) [12 failed sends]`, or empty.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = self.last.iter().map(|(p, why)| format!("peer {p} ({why})")).collect();
        parts.extend(self.other.iter().map(|why| format!("anyone ({why})")));
        if parts.is_empty() {
            return String::new();
        }
        format!("; HELLO not delivered to {} [{} failed sends]", parts.join(", "), self.count)
    }
}

/// Record a barrier HELLO send's outcome in `f` (see [`BarrierSendFailures`]).
pub fn note_barrier_send(f: &mut BarrierSendFailures, r: Result<(), MeshError>) {
    match r {
        Ok(()) => {}
        Err(MeshError::Undelivered(peers)) => {
            f.count += 1;
            f.last.extend(peers);
        }
        Err(e) => {
            f.count += 1;
            f.other = Some(e.to_string());
        }
    }
}

/// How long [`deliver`] keeps re-sending to peers that missed a frame. A peer that cannot
/// take a frame for this long is treated as gone: the run stops and names it, instead of
/// waiting out its whole protocol timeout for a message that never left.
pub const SEND_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// Where a frame goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dest {
    /// Every peer.
    All,
    /// One peer, by committee index.
    One(u16),
}

/// Send a frame that is sent only once, making sure every recipient gets it.
///
/// Protocol rounds (cggmp21, FROST) are sent exactly once and never repeated: a frame
/// that does not leave means the run can only time out, with nothing saying why. So a
/// send that misses some peers is retried to just those peers, with backoff, for up to
/// `within`. A peer still unreachable after that is returned as
/// [`MeshError::Undelivered`], and the caller abandons the run with that cause. A
/// failure a retry cannot fix (an unknown peer, a frame that could not be signed) is
/// returned at once.
pub fn deliver<T: SessionTransport + ?Sized>(
    transport: &mut T,
    dest: Dest,
    msg: &WireMsg,
    within: std::time::Duration,
) -> Result<(), MeshError> {
    let deadline = std::time::Instant::now() + within;
    let mut backoff = std::time::Duration::from_millis(10);
    let mut result = match dest {
        Dest::All => transport.broadcast(msg),
        Dest::One(peer) => transport.send_to(peer, msg),
    };
    loop {
        let Some(peers) = result.as_ref().err().and_then(MeshError::undelivered_peers) else {
            return result; // delivered, or not retryable
        };
        if std::time::Instant::now() >= deadline {
            return result;
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(std::time::Duration::from_millis(250));
        let mut still: Vec<(u16, String)> = Vec::new();
        for peer in peers {
            match transport.send_to(peer, msg) {
                Ok(()) => {}
                Err(MeshError::Undelivered(f)) => still.extend(f),
                Err(e) => return Err(e),
            }
        }
        result = if still.is_empty() { Ok(()) } else { Err(MeshError::Undelivered(still)) };
    }
}

#[cfg(test)]
mod rotation_ack_wire_tests {
    use super::*;

    /// A rotation-ack signature must survive the wire unchanged, and must carry the
    /// acknowledged fact's own hash as `payload_hash` — that is what keeps signatures for
    /// two different rotations from ever being pooled.
    #[test]
    fn an_ack_signature_round_trips_with_its_fact_hash() {
        let body = {
            let mut v = Vec::new();
            v.extend_from_slice(&7u16.to_le_bytes());
            v.extend_from_slice(&[0xAB; 64]);
            v
        };
        let msg = WireMsg {
            leg: crate::transport::Leg::Pgw,
            epoch: 12,
            payload_hash: [0x5A; 32], // the fact's hash, not a session's
            attempt: 0,
            from: 7,
            body: SessionMsg::RotationAckSig(body.clone()),
        };
        let decoded = WireMsg::decode(&msg.encode()).expect("round trip");
        assert_eq!(decoded, msg);
        match decoded.body {
            SessionMsg::RotationAckSig(b) => assert_eq!(b, body),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// It must not collide with the session message types that share the wire.
    #[test]
    fn its_tag_is_distinct_from_session_messages() {
        let hdr = |b: SessionMsg| {
            WireMsg {
                leg: crate::transport::Leg::Pgw,
                epoch: 1,
                payload_hash: [0; 32],
                attempt: 0,
                from: 0,
                body: b,
            }
            .encode()[HEADER_LEN - 1]
        };
        let ack_sig = hdr(SessionMsg::RotationAckSig(vec![0; 66]));
        for other in [
            hdr(SessionMsg::Ack),
            hdr(SessionMsg::DistributeAck),
            hdr(SessionMsg::Round(vec![1])),
            hdr(SessionMsg::Signature(vec![1])),
            hdr(SessionMsg::Propose(vec![1])),
        ] {
            assert_ne!(ack_sig, other, "tag must be unique");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::CommitteeView;
    use crate::session::Stage;

    fn wire(from: u16, body: SessionMsg, attempt: u32) -> WireMsg {
        WireMsg { leg: Leg::Pgw, epoch: 2, payload_hash: [7u8; 32], attempt, from, body }
    }

    #[test]
    fn codec_round_trips_every_type() {
        let cases = [
            SessionMsg::Propose(b"the-tx".to_vec()),
            SessionMsg::Ack,
            SessionMsg::Nack(NackReason::PayloadMismatch),
            SessionMsg::Nack(NackReason::WrongEpoch),
            SessionMsg::Round(vec![1, 2, 3, 4, 5]),
            SessionMsg::Signature(vec![0xaa; 64]),
            SessionMsg::DistributeAck,
        ];
        for (i, body) in cases.into_iter().enumerate() {
            let m = wire(i as u16, body, 3);
            let bytes = m.encode();
            let back = WireMsg::decode(&bytes).expect("decode");
            assert_eq!(m, back);
        }
    }

    #[test]
    fn decode_rejects_truncated_and_bad_tags() {
        assert_eq!(WireMsg::decode(&[0u8; 10]), Err(WireError::Truncated));
        let mut m = wire(0, SessionMsg::Ack, 0).encode();
        m[0] = 9; // bad leg tag
        assert_eq!(WireMsg::decode(&m), Err(WireError::BadTag));
        // Round with a length that overruns the buffer.
        let mut r = wire(0, SessionMsg::Round(vec![1, 2, 3]), 0).encode();
        let n = r.len();
        r[48..52].copy_from_slice(&(9999u32).to_le_bytes());
        r.truncate(n); // keep the bogus length but not the bytes
        assert_eq!(WireMsg::decode(&r), Err(WireError::Truncated));
    }

    fn committee(n: usize, t: usize) -> CommitteeView {
        CommitteeView {
            epoch: 2,
            height: 240,
            members: (0..n).map(|i| [i as u8; 32]).collect(),
            signer_keys: Vec::new(),
            member_ips: Vec::new(),
            member_x25519: Vec::new(),
            daemon_self_index: None,
            threshold: t,
        }
    }

    fn new_session(n: usize, t: usize, self_index: usize) -> Session {
        Session::start(&committee(n, t), Leg::Pgw, b"release".to_vec(), [7u8; 32], self_index)
            .unwrap()
    }

    #[test]
    fn apply_rejects_wrong_leg_s14() {
        let mut s = new_session(6, 4, 0);
        let mut m = wire(1, SessionMsg::Ack, 0);
        m.leg = Leg::Pevm; // foreign leg
        assert_eq!(apply(&mut s, &m), Err(DispatchError::WrongLeg));
    }

    #[test]
    fn apply_drops_stale_attempt() {
        let mut s = new_session(6, 4, 0);
        // A message tagged for attempt 5 while the session is on attempt 0: dropped.
        let m = wire(1, SessionMsg::Ack, 5);
        assert_eq!(apply(&mut s, &m), Ok(()));
        assert_eq!(s.ack_count(), 0);
    }

    #[test]
    fn apply_drops_wrong_session() {
        let mut s = new_session(6, 4, 0);
        let mut m = wire(1, SessionMsg::Ack, 0);
        m.payload_hash = [9u8; 32]; // different session
        assert_eq!(apply(&mut s, &m), Err(DispatchError::NotForThisSession));
    }

    // ---- multi-party in-process simulation ---------------------------------

    /// A bus of `n` member sessions; broadcasting a message applies it to every
    /// member's local session (each member independently runs the state machine).
    struct Bus {
        sessions: Vec<Session>,
    }
    impl Bus {
        fn new(n: usize, t: usize) -> Bus {
            Bus { sessions: (0..n).map(|i| new_session(n, t, i)).collect() }
        }
        fn broadcast(&mut self, from: u16, body: SessionMsg, attempt: u32) {
            let m = wire(from, body, attempt);
            for s in &mut self.sessions {
                apply(s, &m).expect("apply");
            }
        }
        fn all_at(&self, stage: Stage) -> bool {
            self.sessions.iter().all(|s| s.stage() == stage)
        }
    }

    #[test]
    fn full_session_runs_across_six_parties() {
        let (n, t) = (6, 4);
        let mut bus = Bus::new(n, t);
        assert!(bus.all_at(Stage::Consensus));

        // Every member ACKs (broadcast). Once each local session sees t+1 ACKs it
        // advances to Sign.
        for f in 0..n as u16 {
            bus.broadcast(f, SessionMsg::Ack, 0);
        }
        assert!(bus.all_at(Stage::Sign), "all should reach Sign after n ACKs");

        // Every member contributes a round message.
        for f in 0..n as u16 {
            bus.broadcast(f, SessionMsg::Round(vec![f as u8]), 0);
        }
        assert!(bus.sessions.iter().all(|s| s.has_threshold_round_messages()));

        // A raw Signature frame never advances the engine, even from the leader: that
        // takes the coordinator's group-key check, which then calls `signature_ready`.
        let leader = bus.sessions[0].leader() as u16;
        bus.broadcast(leader, SessionMsg::Signature(vec![]), 0);
        bus.broadcast(leader, SessionMsg::Signature(vec![0xab; 64]), 0);
        assert!(bus.all_at(Stage::Sign));
        for s in &mut bus.sessions {
            s.signature_ready(vec![0xab; 64]).unwrap();
        }
        assert!(bus.all_at(Stage::Distribute));

        // Every member acknowledges receipt -> Finalize, then finalizes locally.
        for f in 0..n as u16 {
            bus.broadcast(f, SessionMsg::DistributeAck, 0);
        }
        assert!(bus.all_at(Stage::Finalize));
        for s in &mut bus.sessions {
            s.finalize().unwrap();
        }
        assert!(bus.all_at(Stage::Finalized));
    }

    #[test]
    fn all_parties_agree_on_retry_and_new_leader() {
        let (n, t) = (6, 4);
        let mut bus = Bus::new(n, t);
        let leader0 = bus.sessions[0].leader();

        // Three members NACK -> every local session independently determines the
        // attempt failed and retries. Because leader selection is deterministic,
        // all parties must land on the *same* new leader and attempt (S4/agreement).
        for f in 0..3u16 {
            bus.broadcast(f, SessionMsg::Nack(NackReason::PayloadMismatch), 0);
        }
        assert!(bus.sessions.iter().all(|s| s.attempt() == 1));
        assert!(bus.all_at(Stage::Consensus));
        let new_leaders: Vec<_> = bus.sessions.iter().map(|s| s.leader()).collect();
        assert!(new_leaders.iter().all(|&l| l == new_leaders[0]));
        assert_ne!(new_leaders[0], leader0);
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    /// Peers 1..=3. Each peer refuses its next `refuse[peer]` frames; `u32::MAX` = never
    /// takes one. Records every frame that was taken, per peer.
    #[derive(Default)]
    struct Flaky {
        refuse: BTreeMap<u16, u32>,
        got: BTreeMap<u16, u32>,
        sends: u32,
        fail_hard: bool,
    }
    impl Flaky {
        fn take(&mut self, peer: u16) -> Result<(), (u16, String)> {
            self.sends += 1;
            match self.refuse.get_mut(&peer) {
                Some(n) if *n > 0 => {
                    *n = n.saturating_sub(if *n == u32::MAX { 0 } else { 1 });
                    Err((peer, "queue full".into()))
                }
                _ => {
                    *self.got.entry(peer).or_default() += 1;
                    Ok(())
                }
            }
        }
    }
    impl SessionTransport for Flaky {
        fn broadcast(&mut self, _msg: &WireMsg) -> Result<(), MeshError> {
            if self.fail_hard {
                return Err(MeshError::Io("sign: no key".into()));
            }
            let failed: Vec<_> = (1..=3).filter_map(|p| self.take(p).err()).collect();
            if failed.is_empty() { Ok(()) } else { Err(MeshError::Undelivered(failed)) }
        }
        fn send_to(&mut self, peer: u16, _msg: &WireMsg) -> Result<(), MeshError> {
            self.take(peer).map_err(|f| MeshError::Undelivered(vec![f]))
        }
        fn poll(&mut self) -> Result<Option<WireMsg>, MeshError> {
            Ok(None)
        }
    }

    fn frame() -> WireMsg {
        WireMsg { leg: crate::transport::Leg::Pevm, epoch: 2, payload_hash: [7; 32], attempt: 0, from: 0, body: SessionMsg::Round(vec![1]) }
    }

    #[test]
    fn a_peer_that_missed_a_frame_gets_it_on_retry_and_nobody_gets_it_twice() {
        let mut t = Flaky { refuse: BTreeMap::from([(2, 3)]), ..Default::default() };
        deliver(&mut t, Dest::All, &frame(), Duration::from_secs(5)).unwrap();
        assert_eq!(t.got, BTreeMap::from([(1, 1), (2, 1), (3, 1)]), "each peer exactly once");
    }

    #[test]
    fn a_peer_that_stays_unreachable_is_named_once_the_window_closes() {
        let mut t = Flaky { refuse: BTreeMap::from([(3, u32::MAX)]), ..Default::default() };
        let started = Instant::now();
        let e = deliver(&mut t, Dest::All, &frame(), Duration::from_millis(300)).unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(300) && started.elapsed() < Duration::from_secs(2));
        assert_eq!(e.undelivered_peers(), Some(vec![3]));
        assert_eq!(e.to_string(), "not delivered to peer 3 (queue full)");
        assert_eq!(t.got, BTreeMap::from([(1, 1), (2, 1)]), "the reachable peers still got it, once");
    }

    #[test]
    fn a_failure_a_retry_cannot_fix_is_returned_at_once() {
        let mut t = Flaky { fail_hard: true, ..Default::default() };
        let started = Instant::now();
        assert_eq!(
            deliver(&mut t, Dest::All, &frame(), Duration::from_secs(5)),
            Err(MeshError::Io("sign: no key".into()))
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        let mut t = Flaky::default();
        deliver(&mut t, Dest::One(2), &frame(), Duration::from_secs(5)).unwrap();
        assert_eq!(t.got, BTreeMap::from([(2, 1)]));
    }

    #[test]
    fn a_barrier_keeps_the_reason_instead_of_logging_every_hello() {
        let mut f = BarrierSendFailures::default();
        assert_eq!(f.describe(), "");
        for _ in 0..40 {
            note_barrier_send(&mut f, Err(MeshError::Undelivered(vec![(4, "queue full".into())])));
            note_barrier_send(&mut f, Ok(()));
        }
        assert_eq!(f.describe(), "; HELLO not delivered to peer 4 (queue full) [40 failed sends]");
        note_barrier_send(&mut f, Err(MeshError::Io("sign: no key".into())));
        assert_eq!(
            f.describe(),
            "; HELLO not delivered to peer 4 (queue full), anyone (sign: no key) [41 failed sends]"
        );
    }
}
