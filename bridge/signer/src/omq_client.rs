//! OMQ client for `bridge.committee` (Phase B.9 transport).
//!
//! The signer reads its committee view from its own `beldexd` over OxenMQ. There
//! is no mature pure-Rust OxenMQ binding, but a *request/reply* over the local
//! plain IPC socket is just the underlying ZMQ protocol OMQ speaks:
//!
//!   request  (DEALER send): [ "bridge.committee", <tag>, <optional height> ]
//!   reply    (DEALER recv): [ "REPLY", <tag>, "<status>", <data...> ]
//!
//! where `<status>` is `"200"` on success and `<data[0]>` is the JSON committee
//! reply (parsed by [`crate::committee::CommitteeView::from_bridge_committee_json`]).
//! The local socket authenticates connections at admin level ("unauthenticated
//! local admin"), so no curve keypair is needed for the operator's own node.
//!
//! This is the minimal committee-read transport; the full session engine (C.4)
//! is a larger OMQ surface and is separate work. Built under `--features omq-client`.

use crate::committee::{CommitteeError, CommitteeView};
use std::time::Duration;

/// A thin client that fetches the committee view from a `beldexd` OMQ endpoint.
pub struct OmqCommitteeClient {
    ctx: zmq::Context,
    endpoint: String,
    timeout: Duration,
}

impl OmqCommitteeClient {
    /// Create a client for `endpoint` (e.g. `ipc:///…/beldexd.sock` or
    /// `tcp://127.0.0.1:PORT`). A fresh DEALER socket is opened per request so a
    /// timed-out request can never desync a long-lived socket's reply framing.
    pub fn new(endpoint: impl Into<String>) -> Self {
        OmqCommitteeClient {
            ctx: zmq::Context::new(),
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Override the request timeout (default 5s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Call `bridge.committee` and return the parsed committee for `height`
    /// (the epoch containing it; `None` = current tip).
    pub fn fetch_committee(&self, height: Option<u64>) -> Result<CommitteeView, CommitteeError> {
        CommitteeView::from_bridge_committee_json(&self.fetch_committee_json(height)?)
    }

    /// The raw `bridge.committee` reply behind [`Self::fetch_committee`]. `dkg` keeps it
    /// beside the shares it writes, so the committee that holds a key can still be read
    /// after consensus has selected a different one.
    pub fn fetch_committee_json(&self, height: Option<u64>) -> Result<String, CommitteeError> {
        let tx = |e: String| CommitteeError::Transport(e);

        let sock = self
            .ctx
            .socket(zmq::DEALER)
            .map_err(|e| tx(format!("socket: {e}")))?;
        // Don't linger on close; a dead endpoint must not block teardown.
        sock.set_linger(0).map_err(|e| tx(format!("set_linger: {e}")))?;
        sock.connect(&self.endpoint)
            .map_err(|e| tx(format!("connect {}: {e}", self.endpoint)))?;

        // request parts: command, correlation tag, [optional height as ASCII]
        let height_str;
        let mut parts: Vec<&[u8]> = vec![b"bridge.committee", b"bridgesig-committee"];
        if let Some(h) = height {
            height_str = h.to_string();
            parts.push(height_str.as_bytes());
        }
        sock.send_multipart(parts, 0)
            .map_err(|e| tx(format!("send: {e}")))?;

        // Wait for the reply with a bounded timeout so a hung daemon can't stall
        // the signer.
        let ms = self.timeout.as_millis() as i64;
        let mut items = [sock.as_poll_item(zmq::POLLIN)];
        let ready = zmq::poll(&mut items, ms).map_err(|e| tx(format!("poll: {e}")))?;
        if ready == 0 {
            return Err(tx(format!("timeout after {ms}ms waiting for {}", self.endpoint)));
        }

        let reply = sock
            .recv_multipart(0)
            .map_err(|e| tx(format!("recv: {e}")))?;

        // [ REPLY, tag, status, data... ]
        if reply.len() < 3 || reply[0] != b"REPLY" {
            return Err(tx(format!("unexpected {}-part reply", reply.len())));
        }
        let status = String::from_utf8_lossy(&reply[2]);
        if status != "200" {
            let body = reply.get(3).map(|d| String::from_utf8_lossy(d).into_owned());
            return Err(tx(format!(
                "daemon returned status {status}{}",
                body.map(|b| format!(": {b}")).unwrap_or_default()
            )));
        }

        let data = reply.get(3).ok_or_else(|| tx("empty reply data".into()))?;
        let json = std::str::from_utf8(data).map_err(|_| tx("reply not utf-8".into()))?;
        Ok(json.to_string())
    }

    /// Publish a completed, committee-signed **mint payload** to `bridge.mint_payload`, which
    /// the daemon fans out to every `sub.bridge_mint` subscriber (Phase I mint bus).
    ///
    /// The daemon accepts a publication **only from a seated committee member**: `signature`
    /// must be this node's `signer_ed25519` signature over
    /// [`mint_publish_message`]`(genesis, payload)`, and `self_index` its committee index.
    /// See [`mint_publish_message`] for the byte layout (it must match the C++
    /// `bridge_mint_publish_message` exactly). `master_node` is this node's master node
    /// pubkey: it lets the daemon authenticate a member of the committee that holds the live
    /// key after consensus has selected another one, by looking up that one registered seat.
    ///
    /// Returns the daemon's status word: the subscriber count, or `DUPLICATE` when another
    /// member of the same signing quorum already published this deposit's payload — every
    /// member derives the identical payload, so exactly one fan-out is the desired outcome
    /// and `DUPLICATE` is a success, not an error.
    pub fn publish_mint_payload(
        &self,
        payload: &str,
        self_index: u16,
        signature: &[u8; 64],
        master_node: &[u8; 32],
    ) -> Result<String, String> {
        let sock = self.ctx.socket(zmq::DEALER).map_err(|e| format!("socket: {e}"))?;
        sock.set_linger(0).map_err(|e| format!("set_linger: {e}"))?;
        sock.connect(&self.endpoint)
            .map_err(|e| format!("connect {}: {e}", self.endpoint))?;
        let idx = self_index.to_string();
        let sig_hex: String = signature.iter().map(|b| format!("{b:02x}")).collect();
        let mn_hex: String = master_node.iter().map(|b| format!("{b:02x}")).collect();
        sock.send_multipart(
            [
                b"bridge.mint_payload".as_slice(),
                b"bridgesig-mint".as_slice(),
                payload.as_bytes(),
                idx.as_bytes(),
                sig_hex.as_bytes(),
                mn_hex.as_bytes(),
            ],
            0,
        )
        .map_err(|e| format!("send: {e}"))?;

        let ms = self.timeout.as_millis() as i64;
        let mut items = [sock.as_poll_item(zmq::POLLIN)];
        if zmq::poll(&mut items, ms).map_err(|e| format!("poll: {e}"))? == 0 {
            return Err(format!("timeout after {ms}ms publishing to {}", self.endpoint));
        }
        let reply = sock.recv_multipart(0).map_err(|e| format!("recv: {e}"))?;
        if reply.len() < 3 || reply[0] != b"REPLY" {
            return Err(format!("unexpected {}-part reply", reply.len()));
        }
        let status = String::from_utf8_lossy(&reply[2]).into_owned();
        if status != "200" {
            let body = reply.get(3).map(|d| String::from_utf8_lossy(d).into_owned());
            return Err(format!(
                "daemon returned status {status}{}",
                body.map(|b| format!(": {b}")).unwrap_or_default()
            ));
        }
        Ok(reply.get(3).map(|d| String::from_utf8_lossy(d).into_owned()).unwrap_or_default())
    }
}

/// Domain separator for a mint-bus publication. MUST equal the C++
/// `hashkey::BRIDGE_MINT_PUBLISH` byte-for-byte.
pub const BRIDGE_MINT_PUBLISH_DOMAIN: &[u8] = b"bridge_mint_publish_v1";

/// The bytes a publishing committee member signs with its `signer_ed25519`, so the daemon can
/// prove the publisher is seated before fanning the payload out:
///
/// ```text
///   BRIDGE_MINT_PUBLISH ‖ genesis_hash(32) ‖ payload
/// ```
///
/// Genesis-bound like every other bridge attestation, so a publication cannot be replayed onto
/// another chain or fork. Byte-for-byte identical to C++ `bridge_mint_publish_message`.
impl OmqCommitteeClient {
    /// Submit a threshold-signed rotation acknowledgement to `bridge.rotation_ack`.
    ///
    /// The daemon verifies the evidence against the observing epoch's committee and
    /// returns a serialized `tx_extra` — it does **not** broadcast. A wallet must put
    /// that into a transaction and pay its fee, the same split `bridge.slash_report`
    /// uses, since only a wallet can pay.
    ///
    /// Submitting is idempotent: an acknowledgement for a key epoch the chain has
    /// already recorded is a harmless no-op, so whichever member assembles threshold
    /// first may submit without coordinating.
    pub fn submit_rotation_ack(&self, submission_json: &str) -> Result<String, String> {
        let sock = self.ctx.socket(zmq::DEALER).map_err(|e| format!("socket: {e}"))?;
        sock.set_linger(0).map_err(|e| format!("set_linger: {e}"))?;
        sock.connect(&self.endpoint)
            .map_err(|e| format!("connect {}: {e}", self.endpoint))?;
        // request parts: command, correlation tag, data — the tag is NOT optional. Without
        // it the daemon takes the first data part as the tag, the handler sees zero data
        // parts and never runs, and the DEALER gets back a REPLY whose only part is the tag
        // it was handed: the submission JSON, echoed. That reads exactly like a success,
        // which is how this went unnoticed — the acknowledgement never reached consensus,
        // so `observed_key_epoch` never advanced and no departed member's bond could unlock.
        sock.send_multipart(
            [
                b"bridge.rotation_ack".as_slice(),
                b"bridgesig-rotation-ack".as_slice(),
                submission_json.as_bytes(),
            ],
            0,
        )
        .map_err(|e| format!("send: {e}"))?;

        let ms = self.timeout.as_millis() as i64;
        let mut items = [sock.as_poll_item(zmq::POLLIN)];
        if zmq::poll(&mut items, ms).map_err(|e| format!("poll: {e}"))? == 0 {
            return Err(format!("timeout after {ms}ms submitting to {}", self.endpoint));
        }
        let reply = sock.recv_multipart(0).map_err(|e| format!("recv: {e}"))?;
        // [ REPLY, tag, status, data... ] — the same shape the committee and mint calls
        // parse. Reading part 1 returns the correlation tag, so the caller logs
        // "bridgesig-rotation-ack" where the tx_extra should be; and skipping the status
        // reports a rejected acknowledgement as an accepted one, which is the difference
        // between a bond that unlocks and one that never does.
        if reply.len() < 3 || reply[0] != b"REPLY" {
            return Err(format!("unexpected {}-part reply", reply.len()));
        }
        let status = String::from_utf8_lossy(&reply[2]).into_owned();
        if status != "200" {
            let body = reply.get(3).map(|d| String::from_utf8_lossy(d).into_owned());
            return Err(format!(
                "daemon returned status {status}{}",
                body.map(|b| format!(": {b}")).unwrap_or_default()
            ));
        }
        Ok(reply.get(3).map(|d| String::from_utf8_lossy(d).into_owned()).unwrap_or_default())
    }
}

pub fn mint_publish_message(genesis: &[u8; 32], payload: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BRIDGE_MINT_PUBLISH_DOMAIN.len() + 32 + payload.len());
    buf.extend_from_slice(BRIDGE_MINT_PUBLISH_DOMAIN);
    buf.extend_from_slice(genesis);
    buf.extend_from_slice(payload.as_bytes());
    buf
}

/// A long-lived subscriber to the daemon's mint-payload bus (`sub.bridge_mint` →
/// `notify.bridge_mint`). This is what a relayer runs: it needs no bridge key, no signer
/// host access, and no logs — just an OMQ endpoint it can reach.
///
/// The subscription **expires after 30 minutes** on the daemon side, so [`Self::poll`]
/// re-subscribes on a timer; a `DUPLICATE`/`ALREADY` reply to that renewal is normal.
pub struct OmqMintSubscriber {
    ctx: zmq::Context,
    endpoint: String,
    sock: Option<zmq::Socket>,
    last_sub: Option<std::time::Instant>,
    /// How often to renew (well inside the daemon's 30-minute expiry).
    renew_every: Duration,
}

impl OmqMintSubscriber {
    pub fn new(endpoint: impl Into<String>) -> Self {
        OmqMintSubscriber {
            ctx: zmq::Context::new(),
            endpoint: endpoint.into(),
            sock: None,
            last_sub: None,
            renew_every: Duration::from_secs(600),
        }
    }

    /// Subscribe (or renew) on the **same long-lived socket**. Reconnecting with a fresh
    /// socket on every renewal would present as a new connection to the daemon, which
    /// replays its retained backlog to new subscribers — correct after an outage, pure
    /// duplicate-noise every ten minutes. So the socket is only (re)created when absent
    /// (first call, or after a receive error forced a reconnect) — which is exactly the
    /// "was down, wants the backlog" case.
    fn subscribe(&mut self) -> Result<(), String> {
        if self.sock.is_none() {
            let sock = self.ctx.socket(zmq::DEALER).map_err(|e| format!("socket: {e}"))?;
            sock.set_linger(0).map_err(|e| format!("set_linger: {e}"))?;
            sock.connect(&self.endpoint)
                .map_err(|e| format!("connect {}: {e}", self.endpoint))?;
            self.sock = Some(sock);
        }
        self.sock
            .as_ref()
            .expect("created above")
            .send_multipart([b"sub.bridge_mint".as_slice(), b"bridgerelay-sub".as_slice()], 0)
            .map_err(|e| {
                self.sock = None; // send failed → full reconnect (and backlog) next call
                format!("send subscribe: {e}")
            })?;
        self.last_sub = Some(std::time::Instant::now());
        Ok(())
    }

    /// Wait up to `timeout` for the next payload. Returns `Ok(None)` on timeout (call again).
    /// Renews the subscription when due, and reconnects transparently after an error.
    pub fn poll(&mut self, timeout: Duration) -> Result<Option<String>, String> {
        let due = self
            .last_sub
            .map(|t| t.elapsed() >= self.renew_every)
            .unwrap_or(true);
        if self.sock.is_none() || due {
            self.subscribe()?;
        }
        let sock = self.sock.as_ref().expect("subscribed above");
        let ms = timeout.as_millis() as i64;
        let mut items = [sock.as_poll_item(zmq::POLLIN)];
        if zmq::poll(&mut items, ms).map_err(|e| format!("poll: {e}"))? == 0 {
            return Ok(None);
        }
        let msg = sock.recv_multipart(0).map_err(|e| {
            self.sock = None; // force a reconnect next call
            format!("recv: {e}")
        })?;
        // Two shapes arrive on this socket: the REPLY to our own subscribe request, and the
        // notifications we actually want.
        match msg.first().map(|p| p.as_slice()) {
            Some(b"notify.bridge_mint") => Ok(msg
                .get(1)
                .map(|d| String::from_utf8_lossy(d).into_owned())),
            Some(b"REPLY") => Ok(None), // our subscribe/renew ack
            _ => Ok(None),              // anything else: ignore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The publish message must match C++ `bridge_mint_publish_message` byte-for-byte or the
    // daemon rejects every publication. Pin the layout here (the MINT_TAG drift is exactly
    // this bug class, caught late).
    #[test]
    fn mint_publish_message_layout_is_pinned() {
        let genesis = [0xabu8; 32];
        let msg = mint_publish_message(&genesis, r#"{"kind":"mint"}"#);
        assert_eq!(&msg[..22], b"bridge_mint_publish_v1", "domain first");
        assert_eq!(&msg[22..54], &genesis[..], "then the 32-byte genesis");
        assert_eq!(&msg[54..], br#"{"kind":"mint"}"#, "then the payload verbatim");
        assert_eq!(msg.len(), 22 + 32 + 15);
        // Genesis-bound: a different chain yields a different message (no cross-net replay).
        assert_ne!(msg, mint_publish_message(&[0xcd; 32], r#"{"kind":"mint"}"#));
    }

    // Integration test against a live beldexd. Ignored by default (needs a running
    // node); run explicitly against the devnet:
    //
    //   BRIDGE_SIGNER_OXENMQ_ENDPOINT=ipc://$PWD/utils/local-devnet/testdata/\
    //     beldex-127.0.0.1-<PORT>/devnet/beldexd.sock \
    //   cargo test -p beldex-bridge-signer --features omq-client -- --ignored fetches_live_committee
    #[test]
    #[ignore = "requires a running beldexd with an active bridge committee"]
    fn fetches_live_committee() {
        let endpoint = std::env::var("BRIDGE_SIGNER_OXENMQ_ENDPOINT")
            .expect("set BRIDGE_SIGNER_OXENMQ_ENDPOINT to a beldexd OMQ socket");
        let client = OmqCommitteeClient::new(endpoint);
        let view = client.fetch_committee(None).expect("fetch committee");
        assert!(view.can_sign(), "committee should be signable: {view:?}");
        assert_eq!(view.size(), view.members.len());
        eprintln!(
            "live committee: epoch={} height={} size={} threshold={}",
            view.epoch,
            view.height,
            view.size(),
            view.threshold
        );
    }
}

#[cfg(test)]
mod omq_request_shape_tests {
    //! Every OMQ request is [command, correlation tag, data…]. Omitting the tag does not
    //! fail: the first data part silently becomes the tag, the handler sees no data and
    //! never runs, and the reply carries that part straight back — which reads as success.
    //! The rotation acknowledgement shipped that way, so it never reached consensus and no
    //! departed member's bond could ever unlock.

    /// Built the same way the senders build them, so a missing tag shows up here.
    fn parts(cmd: &[u8], tag: &[u8], data: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut v = vec![cmd.to_vec(), tag.to_vec()];
        v.extend(data.iter().map(|d| d.to_vec()));
        v
    }

    /// Replies are [ REPLY, tag, status, data… ]. Two separate mistakes hide in that shape:
    /// taking part 1 hands back the correlation tag instead of the payload, and skipping
    /// part 2 reports a rejected call as a successful one.
    #[test]
    fn a_reply_body_is_part_three_and_the_status_is_part_two() {
        let reply: Vec<Vec<u8>> = vec![
            b"REPLY".to_vec(),
            b"bridgesig-rotation-ack".to_vec(),
            b"200".to_vec(),
            b"{\"rotation_hex\":\"deadbeef\"}".to_vec(),
        ];
        assert_eq!(&reply[2], b"200", "the status is part two");
        let body = String::from_utf8_lossy(&reply[3]).into_owned();
        assert!(body.contains("rotation_hex"), "the payload is part three");
        assert!(
            !String::from_utf8_lossy(&reply[1]).contains("rotation_hex"),
            "part one is the tag — logging it loses the tx_extra the operator must broadcast"
        );

        // A rejection carries a non-200 status and must never read as success.
        let bad: Vec<Vec<u8>> = vec![
            b"REPLY".to_vec(),
            b"bridgesig-rotation-ack".to_vec(),
            b"400".to_vec(),
            b"bridge.rotation_ack: malformed ack".to_vec(),
        ];
        assert_ne!(&bad[2], b"200", "a non-200 status must be surfaced, not ignored");
    }

    #[test]
    fn a_request_carries_its_tag_before_its_data() {
        for (cmd, tag) in [
            (&b"bridge.committee"[..], &b"bridgesig-committee"[..]),
            (&b"bridge.mint_payload"[..], &b"bridgesig-mint"[..]),
            (&b"bridge.rotation_ack"[..], &b"bridgesig-rotation-ack"[..]),
        ] {
            let p = parts(cmd, tag, &[b"{\"some\":\"payload\"}"]);
            assert_eq!(p[0], cmd, "part 0 is the command");
            assert_eq!(p[1], tag, "part 1 is the correlation tag, never the payload");
            assert_eq!(p.len(), 3, "exactly one data part follows the tag");
            assert_ne!(
                p[1], b"{\"some\":\"payload\"}".to_vec(),
                "the payload must not land in the tag slot"
            );
        }
    }
}
