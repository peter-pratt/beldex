//! Direct peer-to-peer session transport over curve-authenticated OMQ/ZMQ
//! (plan §2.3, C.4). Chosen architecture: each signer binds its own listener and
//! dials every peer directly, keyed by the masternodes' curve identities — no
//! relay through `beldexd`, which only supplies the peer address book.
//!
//! Wire model (deliberately simple, since both ends are our own signer process —
//! we do **not** need beldexd's category/REPLY command protocol here):
//!   * **inbound:** one `PULL` socket bound at `listen_endpoint`, `curve_server`,
//!     holding this node's curve secret. Every peer's `PUSH` connects to it.
//!   * **outbound:** one `PUSH` per peer, connected to that peer's endpoint with
//!     `curve_serverkey = peer_pubkey` (server-key pinning ⇒ you reach the
//!     intended peer, and the channel is encrypted + integrity-protected).
//!
//! A [`WireMsg`] is sent as a single ZMQ frame (its `encode()`); `poll` decodes
//! one frame if ready. Sends are non-blocking, so a slow or absent peer never wedges
//! the sender. A frame a peer's connection would not take (its queue is full, or a
//! socket error) is reported as [`MeshError::Undelivered`] naming that peer, never
//! passed off as sent: a broadcast still goes to every other peer, and the caller
//! re-sends to the ones that missed it ([`crate::wire::deliver`]).
//!
//! **Security (S4 hardening — now enforced):** curve gives confidentiality +
//! peer-key pinning on dial, but the `from` index inside a `WireMsg` is
//! self-declared, so on its own the mesh cannot stop a connected peer from
//! stamping another member's index on a message. This transport therefore signs
//! every outbound frame with this node's bridge-signer ed25519 key and verifies
//! every inbound frame against the sender's on-chain transport key
//! (see [`crate::wire_auth`]): a frame whose signature does not authenticate its
//! `from` is dropped **before** it reaches the session engine, so a forged `from`
//! cannot enter the transcript. Signing also makes the transcript transferable
//! evidence for Phase F slashing. Curve auth and per-message signing are
//! complementary: curve authenticates the *channel*, the signature authenticates
//! the *content and author*.
//!
//! Set a [`MeshAuth`] via [`OmqPeerTransport::with_auth`] to enable it; the
//! plain path (no auth) remains only for the curve-less plumbing test.
//!
//! Built under `--features omq-mesh` (needs libzmq).

use crate::wire::{MeshError, SessionTransport, WireMsg};
use crate::wire_auth::{AuthKeyBook, Ed25519, MsgSigner};
use std::collections::BTreeMap;

/// A peer's address book entry, as read from `beldexd`'s masternode list /
/// `bridge_get_seats`.
#[derive(Debug, Clone)]
pub struct PeerAddr {
    /// The peer's committee index (matches `WireMsg.from` / `self_index`).
    pub index: u16,
    /// ZMQ endpoint, e.g. `tcp://10.0.0.7:5580`.
    pub endpoint: String,
    /// The peer's 32-byte curve (x25519) public key (channel authentication).
    pub curve_pubkey: [u8; 32],
    /// The peer's 32-byte bridge-signer ed25519 public key (`signer_ed25519` from
    /// its on-chain `bridge_registration`) — used to authenticate the `from` on
    /// every message this peer sends (S4, [`crate::wire_auth`]).
    pub signer_ed25519: [u8; 32],
}

/// Message-authentication context for the mesh (S4): this node's signer plus the
/// key book that authenticates every peer's `from`. Uses boxed trait objects so
/// production injects the libsodium verifier/signer and tests inject a double,
/// without making the transport itself generic.
pub struct MeshAuth {
    /// Signs this node's outbound frames with its bridge-signer ed25519 key.
    pub signer: Box<dyn MsgSigner>,
    /// Verifies inbound frames against each member's transport key.
    pub book: AuthKeyBook<Box<dyn Ed25519>>,
}

impl MeshAuth {
    /// Build a mesh-auth context from this node's signer and a set of
    /// `(index, signer_ed25519)` transport keys (self + peers). `verifier` is the
    /// [`Ed25519`] backend (libsodium in production).
    pub fn new(
        signer: Box<dyn MsgSigner>,
        verifier: Box<dyn Ed25519>,
        members: impl IntoIterator<Item = (u16, [u8; 32])>,
    ) -> MeshAuth {
        MeshAuth { signer, book: AuthKeyBook::from_members(verifier, members) }
    }

    /// Build the mesh-auth context directly from a consensus committee view: the
    /// key book is keyed by each member's `signer_ed25519` as reported on
    /// `bridge.committee` (`CommitteeView::auth_members`). This is the intended
    /// wiring — the transport keys come from consensus, never from a peer.
    /// Returns `None` if the committee did not carry per-member signer keys (an
    /// older daemon, or a reply without `signer_keys`): the caller must treat that
    /// as a hard startup error rather than run an un-authenticated mesh.
    pub fn from_committee(
        signer: Box<dyn MsgSigner>,
        verifier: Box<dyn Ed25519>,
        committee: &crate::committee::CommitteeView,
    ) -> Option<MeshAuth> {
        if !committee.has_signer_keys() {
            return None;
        }
        Some(MeshAuth::new(signer, verifier, committee.auth_members()))
    }
}

/// Configuration for this node's mesh transport.
pub struct OmqMeshConfig {
    /// This node's committee index.
    pub self_index: u16,
    /// Where this node binds its inbound listener, e.g. `tcp://0.0.0.0:5580`.
    pub listen_endpoint: String,
    /// Enable CURVE authentication + encryption. **Production must set this true.**
    /// Requires a libzmq built with libsodium/tweetnacl; when false the transport
    /// runs plain (used only to test the plumbing where curve is unavailable).
    pub use_curve: bool,
    /// This node's 32-byte curve secret key (used iff `use_curve`).
    pub self_curve_secret: [u8; 32],
    /// This node's 32-byte curve public key (used iff `use_curve`).
    pub self_curve_public: [u8; 32],
    /// The other committee members' address book (excluding self).
    pub peers: Vec<PeerAddr>,
}

/// A curve-authenticated peer-to-peer session transport.
pub struct OmqPeerTransport {
    _ctx: zmq::Context,
    listener: zmq::Socket,
    /// Outbound PUSH sockets keyed by peer committee index.
    peers: BTreeMap<u16, zmq::Socket>,
    /// Message-authentication context (S4). `None` only on the curve-less
    /// plumbing test path; **production must set it** via [`Self::with_auth`].
    auth: Option<MeshAuth>,
}

impl OmqPeerTransport {
    /// Attach the S4 message-authentication context: outbound frames are signed
    /// and inbound frames are verified against each member's transport key. A
    /// frame that fails authentication is dropped in [`Self::poll`], never
    /// delivered to a session.
    pub fn with_auth(mut self, auth: MeshAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Whether message authentication is enabled (production requires it).
    pub fn has_auth(&self) -> bool {
        self.auth.is_some()
    }

    /// Bind the inbound listener and dial every peer.
    pub fn bind(cfg: &OmqMeshConfig) -> Result<OmqPeerTransport, MeshError> {
        let ctx = zmq::Context::new();

        // Inbound: PULL, curve server (if enabled), holding our secret. Peers PUSH to it.
        let listener = ctx
            .socket(zmq::PULL)
            .map_err(|e| MeshError::Io(format!("pull socket: {e}")))?;
        if cfg.use_curve {
            listener
                .set_curve_server(true)
                .map_err(|e| MeshError::Io(format!("curve_server: {e}")))?;
            listener
                .set_curve_secretkey(&cfg.self_curve_secret)
                .map_err(|e| MeshError::Io(format!("curve_secretkey: {e}")))?;
        }
        listener
            .set_rcvtimeo(0) // non-blocking recv (poll semantics)
            .map_err(|e| MeshError::Io(format!("rcvtimeo: {e}")))?;
        listener
            .bind(&cfg.listen_endpoint)
            .map_err(|e| MeshError::Io(format!("bind {}: {e}", cfg.listen_endpoint)))?;

        // Outbound: one PUSH per peer, curve client with the peer's key pinned.
        let mut peers = BTreeMap::new();
        for p in &cfg.peers {
            let sock = ctx
                .socket(zmq::PUSH)
                .map_err(|e| MeshError::Io(format!("push socket: {e}")))?;
            if cfg.use_curve {
                sock.set_curve_serverkey(&p.curve_pubkey)
                    .map_err(|e| MeshError::Io(format!("curve_serverkey: {e}")))?;
                sock.set_curve_publickey(&cfg.self_curve_public)
                    .map_err(|e| MeshError::Io(format!("curve_publickey: {e}")))?;
                sock.set_curve_secretkey(&cfg.self_curve_secret)
                    .map_err(|e| MeshError::Io(format!("curve_secretkey: {e}")))?;
            }
            // Don't block a broadcast on a slow/absent peer; drop instead.
            sock.set_sndtimeo(0)
                .map_err(|e| MeshError::Io(format!("sndtimeo: {e}")))?;
            sock.set_linger(0)
                .map_err(|e| MeshError::Io(format!("linger: {e}")))?;
            sock.connect(&p.endpoint)
                .map_err(|e| MeshError::Io(format!("connect {}: {e}", p.endpoint)))?;
            peers.insert(p.index, sock);
        }

        Ok(OmqPeerTransport { _ctx: ctx, listener, peers, auth: None })
    }

    /// Serialize a message for the wire: signed frame (`canonical ‖ sig`) when
    /// authentication is enabled, plain `encode()` otherwise (test path only).
    fn frame_out(&self, msg: &WireMsg) -> Result<Vec<u8>, MeshError> {
        match &self.auth {
            Some(a) => crate::wire_auth::sign_wire(a.signer.as_ref(), msg)
                .map_err(|e| MeshError::Io(format!("sign: {e}"))),
            None => Ok(msg.encode()),
        }
    }

    /// Decode-and-authenticate an inbound frame. With auth enabled, a frame that
    /// fails authentication is a [`MeshError::Auth`] (the caller drops it); with
    /// auth disabled it is a plain decode.
    fn frame_in(&self, bytes: &[u8]) -> Result<WireMsg, MeshError> {
        match &self.auth {
            Some(a) => a
                .book
                .authenticate(bytes)
                .map_err(|e| MeshError::Auth(format!("{e:?}"))),
            None => WireMsg::decode(bytes).map_err(MeshError::Decode),
        }
    }

    /// Hand one frame to a peer's connection without blocking. `Err` carries the reason
    /// the frame did not leave. EAGAIN — the peer's queue is full, because it has been
    /// unreachable or slow for a while — is such a reason: the frame is gone, and calling
    /// it sent is what left rounds to fail as unexplained timeouts.
    fn send_frame(sock: &zmq::Socket, bytes: &[u8]) -> Result<(), String> {
        match sock.send(bytes, zmq::DONTWAIT) {
            Ok(()) => Ok(()),
            Err(zmq::Error::EAGAIN) => Err("its send queue is full: unreachable or not reading".into()),
            Err(e) => Err(format!("send: {e}")),
        }
    }
}

impl SessionTransport for OmqPeerTransport {
    /// Every peer is tried, whatever happens to the others: one peer that cannot take the
    /// frame must not keep it from the peers after it in the map.
    fn broadcast(&mut self, msg: &WireMsg) -> Result<(), MeshError> {
        let bytes = self.frame_out(msg)?;
        let failed: Vec<(u16, String)> = self
            .peers
            .iter()
            .filter_map(|(idx, sock)| Self::send_frame(sock, &bytes).err().map(|why| (*idx, why)))
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(MeshError::Undelivered(failed))
        }
    }

    fn send_to(&mut self, peer_index: u16, msg: &WireMsg) -> Result<(), MeshError> {
        let bytes = self.frame_out(msg)?;
        let sock = self.peers.get(&peer_index).ok_or(MeshError::UnknownPeer(peer_index))?;
        Self::send_frame(sock, &bytes).map_err(|why| MeshError::Undelivered(vec![(peer_index, why)]))
    }

    fn poll(&mut self) -> Result<Option<WireMsg>, MeshError> {
        match self.listener.recv_bytes(zmq::DONTWAIT) {
            // Authenticate before delivering (S4): a frame with a forged `from`,
            // a tampered body, or an unknown sender surfaces as MeshError::Auth
            // and the caller drops it — it never reaches a session.
            Ok(bytes) => self.frame_in(&bytes).map(Some),
            Err(zmq::Error::EAGAIN) => Ok(None), // nothing ready
            Err(e) => Err(MeshError::Io(format!("recv: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::NackReason;
    use crate::transport::Leg;
    use crate::wire::SessionMsg;

    fn wire(from: u16, body: SessionMsg) -> WireMsg {
        WireMsg { leg: Leg::Pgw, epoch: 2, payload_hash: [7u8; 32], attempt: 0, from, body }
    }

    /// Build a bidirectional 2-node pair on the given ports, curve on/off.
    fn pair(port_a: u16, port_b: u16, use_curve: bool) -> (OmqPeerTransport, OmqPeerTransport) {
        let (a_pk, a_sk, b_pk, b_sk) = if use_curve {
            let a = zmq::CurveKeyPair::new().expect("curve keypair (libzmq needs libsodium)");
            let b = zmq::CurveKeyPair::new().expect("curve keypair");
            (a.public_key, a.secret_key, b.public_key, b.secret_key)
        } else {
            ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32])
        };
        let ep = |p: u16| format!("tcp://127.0.0.1:{p}");
        let cfg_a = OmqMeshConfig {
            self_index: 0,
            listen_endpoint: ep(port_a),
            use_curve,
            self_curve_secret: a_sk,
            self_curve_public: a_pk,
            peers: vec![PeerAddr {
                index: 1,
                endpoint: ep(port_b),
                curve_pubkey: b_pk,
                signer_ed25519: [0u8; 32],
            }],
        };
        let cfg_b = OmqMeshConfig {
            self_index: 1,
            listen_endpoint: ep(port_b),
            use_curve,
            self_curve_secret: b_sk,
            self_curve_public: b_pk,
            peers: vec![PeerAddr {
                index: 0,
                endpoint: ep(port_a),
                curve_pubkey: a_pk,
                signer_ed25519: [0u8; 32],
            }],
        };
        (
            OmqPeerTransport::bind(&cfg_a).expect("bind a"),
            OmqPeerTransport::bind(&cfg_b).expect("bind b"),
        )
    }

    fn exchange(ta: &mut OmqPeerTransport, tb: &mut OmqPeerTransport) {
        std::thread::sleep(std::time::Duration::from_millis(300)); // let connects settle
        ta.broadcast(&wire(0, SessionMsg::Ack)).unwrap();
        tb.broadcast(&wire(1, SessionMsg::Nack(NackReason::PayloadMismatch)))
            .unwrap();
        assert_eq!(poll_until(tb), Some(wire(0, SessionMsg::Ack)));
        assert_eq!(
            poll_until(ta),
            Some(wire(1, SessionMsg::Nack(NackReason::PayloadMismatch)))
        );
    }

    // Plain (no curve) — verifies the transport plumbing (encode/send/poll/decode)
    // even where libzmq lacks CURVE. Run:
    //   cargo test -p beldex-bridge-signer --features omq-mesh -- --ignored two_node_plain
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost"]
    fn two_node_plain_roundtrip() {
        let (mut ta, mut tb) = pair(55810, 55811, false);
        exchange(&mut ta, &mut tb);
    }

    /// A peer that is down must not cost the others their frames, and must not be passed
    /// off as delivered. Peer 1 has no listener, so once its queue is full (the ZMQ
    /// high-water mark, 1000 frames) every frame to it is refused; peer 2 is up. Before,
    /// a refused frame was reported as sent (EAGAIN -> Ok), and any other send error
    /// returned from the broadcast before it reached the peers after it.
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost"]
    fn a_down_peer_is_reported_and_does_not_cost_the_others_their_frames() {
        let ep = |p: u16| format!("tcp://127.0.0.1:{p}");
        let peer = |index: u16, port: u16| PeerAddr { index, endpoint: ep(port), curve_pubkey: [0; 32], signer_ed25519: [0; 32] };
        let mut a = OmqPeerTransport::bind(&OmqMeshConfig {
            self_index: 0,
            listen_endpoint: ep(55830),
            use_curve: false,
            self_curve_secret: [0; 32],
            self_curve_public: [0; 32],
            peers: vec![peer(1, 55831), peer(2, 55832)], // nothing listens on 55831
        })
        .expect("bind a");
        let mut b = OmqPeerTransport::bind(&OmqMeshConfig {
            self_index: 2,
            listen_endpoint: ep(55832),
            use_curve: false,
            self_curve_secret: [0; 32],
            self_curve_public: [0; 32],
            peers: vec![peer(0, 55830)],
        })
        .expect("bind b");
        std::thread::sleep(std::time::Duration::from_millis(300));

        let frames = 1200;
        let mut refused = 0;
        let mut got = 0;
        for _ in 0..frames {
            // Peer 2 reads as it goes, as a live signer does; peer 1 never will.
            while let Ok(Some(_)) = b.poll() {
                got += 1;
            }
            match a.broadcast(&wire(0, SessionMsg::Ack)) {
                Ok(()) => {}
                Err(MeshError::Undelivered(f)) => {
                    assert_eq!(f.iter().map(|(p, _)| *p).collect::<Vec<_>>(), vec![1], "only the down peer");
                    refused += 1;
                }
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        assert!(refused > 0, "frames the down peer's full queue refused are reported");
        while poll_until(&mut b).is_some() {
            got += 1;
        }
        assert_eq!(got, frames, "the live peer got every frame");
    }

    // Curve-authenticated — the production path. Skips (does not fail) if the
    // linked libzmq was built without CURVE support.
    //   cargo test -p beldex-bridge-signer --features omq-mesh -- --ignored two_node_curve
    #[test]
    #[ignore = "binds real ZMQ sockets on localhost; needs libzmq+libsodium"]
    fn two_node_curve_roundtrip() {
        if zmq::CurveKeyPair::new().is_err() {
            eprintln!("SKIP: linked libzmq has no CURVE support (rebuild libzmq with libsodium)");
            return;
        }
        let (mut ta, mut tb) = pair(55820, 55821, true);
        exchange(&mut ta, &mut tb);
    }

    fn poll_until(t: &mut OmqPeerTransport) -> Option<WireMsg> {
        for _ in 0..50 {
            if let Some(m) = t.poll().unwrap() {
                return Some(m);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        None
    }
}
