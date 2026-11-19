//! `beldex-bridge-signer` entry point (Phase C scaffold).
//!
//! At this stage the binary only loads and validates configuration and reports
//! the modules that are wired. The service loop (connect to `beldexd` OMQ, fetch
//! the committee, run DKG/refresh, serve signing sessions) is added as C.2–C.5
//! integrate the audited TSS crates — see `DUE_DILIGENCE.md`.

use std::collections::HashMap;
use std::process::ExitCode;

use beldex_bridge_signer::config::{self, Config};
use beldex_bridge_signer::SIGNER_VERSION;

const PREFIX: &str = "BRIDGE_SIGNER_";

/// Build the config map from (1) an optional `.env` file, then (2) real process
/// environment variables which override it. In both, keys are `BRIDGE_SIGNER_<KEY>`
/// and are lower-cased without the prefix (e.g. `BRIDGE_SIGNER_GATEWAY_ID` ->
/// `gateway_id`). The `.env` path defaults to `./.env` and can be overridden with
/// `BRIDGE_SIGNER_DOTENV` (or disabled by pointing it at a missing file).
fn config_map() -> HashMap<String, String> {
    let mut map = HashMap::new();

    // (1) .env file (lower priority).
    let dotenv_path = std::env::var(format!("{PREFIX}DOTENV")).unwrap_or_else(|_| ".env".to_string());
    match std::fs::read_to_string(&dotenv_path) {
        Ok(contents) => {
            for (k, v) in config::parse_dotenv(&contents) {
                if let Some(rest) = k.strip_prefix(PREFIX) {
                    map.insert(rest.to_ascii_lowercase(), v);
                }
            }
            eprintln!("(loaded config from {dotenv_path})");
        }
        Err(_) => eprintln!("(no {dotenv_path} file; using environment only)"),
    }

    // (2) real env vars (higher priority) override the .env.
    for (k, v) in std::env::vars() {
        if let Some(rest) = k.strip_prefix(PREFIX) {
            map.insert(rest.to_ascii_lowercase(), v);
        }
    }
    map
}

fn print_status(cfg: &Config) {
    let [a, b, c] = SIGNER_VERSION;
    println!("beldex-bridge-signer v{a}.{b}.{c}");
    println!("  beldexd RPC : {}", cfg.beldexd_rpc_url);
    println!("  OxenMQ      : {}", cfg.oxenmq_endpoint);
    println!("  gateway     : {}", hex(&cfg.gateway_id));
    println!("  self MN     : {}", hex(&cfg.self_mn_pubkey));
    println!("  epoch blocks: {}", cfg.bridge_epoch_blocks);
    println!("  threshold   : {}", cfg.committee_threshold);
    println!("  share store : {:?}", cfg.share_store);
    println!("  pool cap L  : {}", cfg.max_pool);
    if cfg!(feature = "live-dkg") {
        println!("subcommands:");
        println!("  dkg  — run the dual DKG over the mesh (persists Pgw share if SHARE_DIR set)");
        println!("  sign — run the Pgw FROST signing over the mesh (loads the persisted share)");
        println!("  new-share-key <path> — create the key that seals shares (keep it outside the share dir)");
        println!("  protect-shares [dir] — seal an existing share dir under the configured share key");
    } else {
        println!("(build with --features live-dkg for the `dkg` / `sign` subcommands)");
    }
    if cfg!(feature = "evm-watcher-http") {
        println!("  watch-evm — poll EVM chains for finalized wBDX burns (BRIDGE_SIGNER_EVM_CHAINS)");
    } else {
        println!("(build with --features evm-watcher-http for the `watch-evm` subcommand)");
    }
    if cfg!(feature = "autonomy") {
        println!("  serve — autonomous watcher pipeline: detect + dedup deposit/burn duties (dry-run backend)");
        println!("          with --features serve-live + BRIDGE_SIGNER_SERVE_LIVE=1: coordinated live signing");
    } else {
        println!("(build with --features autonomy for the `serve` subcommand)");
    }
    if cfg!(feature = "omq-client") {
        println!("  relay-watch — subscribe to the daemon's mint bus and broadcast each payload");
        println!("                (no bridge key needed; this is the relayer-operator command)");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The test-network-only settings this process is using (see `network_policy`): each is
/// refused unless the daemon confirms a devnet.
#[cfg(feature = "live-dkg")]
fn test_network_settings() -> Vec<String> {
    use beldex_bridge_signer::share_file;
    let mut v = Vec::new();
    if std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE").is_ok_and(|x| x == "false" || x == "0") {
        v.push("mesh CURVE disabled (BRIDGE_SIGNER_MESH_USE_CURVE)".to_string());
    }
    if share_file::plaintext_allowed() {
        v.push("plaintext shares allowed (BRIDGE_SIGNER_ALLOW_PLAINTEXT_SHARES)".to_string());
    }
    if share_file::key_comes_from_env() {
        v.push("share key read from the environment (BRIDGE_SIGNER_SHARE_KEY)".to_string());
    }
    v
}

/// Refuse `settings` unless this node's daemon says it is on a devnet or fakechain. Asks
/// only when there is something to refuse.
#[cfg(feature = "live-dkg")]
fn enforce_network_policy(cfg: &Config, settings: &[String]) -> Result<(), String> {
    use beldex_bridge_signer::network_policy;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    if settings.is_empty() {
        return Ok(());
    }
    let reply = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone())
        .fetch_committee_json(None)
        .map_err(|e| format!("asking the daemon which network this is: {e}"))?;
    let network = network_policy::network_of_committee_reply(&reply);
    network_policy::enforce(network, settings)?;
    println!("  test-network settings, allowed on {network:?}: {}", settings.join("; "));
    Ok(())
}

/// The parts of one DKG run that `dkg-auto` chooses per attempt; `dkg` reads them from the
/// environment.
#[cfg(feature = "live-dkg")]
struct DkgRun {
    key_generation: u32,
    share_dir: Option<String>,
    port_base: Option<u16>,
    timeout: std::time::Duration,
    /// Refuse to run unless the committee is still this epoch's.
    epoch: Option<u64>,
    /// The standby round whose committee makes this key, instead of the current epoch's.
    standby_round: Option<u64>,
}

/// `dkg` subcommand: fetch the live committee and run the `Pgw` FROST DKG across
/// the authenticated mesh (C.2). Only built with `--features live-dkg`.
#[cfg(feature = "live-dkg")]
fn run_dkg(cfg: &Config) -> Result<(), String> {
    let key_generation: u32 = std::env::var("BRIDGE_SIGNER_DKG_KEYGEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    run_dkg_into(cfg, std::env::var("BRIDGE_SIGNER_SHARE_DIR").ok().as_deref(), key_generation, None)
}

/// The DKG itself: shares written to `share_dir` (none kept without one), execution ids
/// derived from the committee and `key_generation`. By the current epoch's committee, or with
/// `standby_round` by that standby round's.
#[cfg(feature = "live-dkg")]
fn run_dkg_into(cfg: &Config, share_dir: Option<&str>, key_generation: u32, standby_round: Option<u64>) -> Result<(), String> {
    let run = DkgRun {
        key_generation,
        share_dir: share_dir.map(str::to_string),
        port_base: std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
            .ok()
            .and_then(|s| s.parse().ok()),
        timeout: std::time::Duration::from_secs(
            std::env::var("BRIDGE_SIGNER_DKG_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900),
        ),
        epoch: None,
        standby_round,
    };
    run_dkg_with(cfg, &run)
}

#[cfg(feature = "live-dkg")]
fn run_dkg_with(cfg: &Config, run: &DkgRun) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::live::{run_live_capture, MeshIdentity, PeerTransportAddr};
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use std::time::Duration;
    enforce_network_policy(cfg, &test_network_settings())?;

    let env = |k: &str| std::env::var(k).map_err(|_| format!("missing env {k}"));
    let h32 = |s: &str, k: &str| config::parse_hex32(s).ok_or(format!("{k} must be 32-byte hex"));
    let h64 = |s: &str, k: &str| config::parse_hex64(s).ok_or(format!("{k} must be 64-byte hex"));

    // 1) Read the live committee (now carrying signer_keys, S4). Prefer the index
    //    the daemon reports for itself (OMQ `self_index`) so no per-node pubkey
    //    config is needed; fall back to matching the configured MN pubkey.
    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    let committee_json = match run.standby_round {
        Some(round) => client.fetch_standby_round_json(round),
        None => client.fetch_committee_json(None),
    }
    .map_err(|e| e.to_string())?;
    let committee = beldex_bridge_signer::committee::CommitteeView::from_bridge_committee_json(&committee_json)
        .map_err(|e| e.to_string())?;
    if let Some(e) = run.epoch.filter(|e| *e != committee.epoch) {
        return Err(format!("the committee moved on to epoch {} (this run was for epoch {e})", committee.epoch));
    }
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node is not on the current bridge committee")? as u16;
    if !committee.has_signer_keys() {
        return Err("bridge.committee returned no signer_keys — update beldexd (mesh auth needs them)".into());
    }
    println!(
        "committee epoch {} height {} size {} threshold {}; self_index {}",
        committee.epoch, committee.height, committee.size(), committee.threshold, self_index
    );

    // A single-host deployment (local devnet) sets a port base: every node shares
    // the committee's IP but listens on `port_base + index`. **Dual DKG** (both
    // legs) requires this mode so each leg gets a distinct port range.
    let port_base: Option<u16> = run.port_base;

    // 2) This node's mesh keys (x25519 channel + ed25519 message-auth), derived
    //    once. Turnkey path: read the masternode ed25519 key file
    //    (`<data-dir>/key_ed25519`, 64 bytes) and derive both — exactly as beldexd
    //    does. Fallback: explicit MESH_* env vars. The per-leg listen port is
    //    applied when building each leg's identity.
    let (curve_secret, curve_public, ed25519_secret) =
        if let Ok(key_path) = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE") {
            let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
            if sk_bytes.len() != 64 {
                return Err(format!("MN key {key_path} is {} bytes, expected 64 (key_ed25519)", sk_bytes.len()));
            }
            let mut ed25519_secret = [0u8; 64];
            ed25519_secret.copy_from_slice(&sk_bytes);
            let mut ed_pub = [0u8; 32];
            ed_pub.copy_from_slice(&ed25519_secret[32..64]); // libsodium sk = seed‖pub
            let cs = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
            let cp = ffi::ed25519_pk_to_x25519(&ed_pub)?;
            println!("mesh identity: derived from MN key {key_path}");
            (cs, cp, ed25519_secret)
        } else {
            (
                h32(&env("BRIDGE_SIGNER_MESH_CURVE_SK")?, "MESH_CURVE_SK")?,
                h32(&env("BRIDGE_SIGNER_MESH_CURVE_PK")?, "MESH_CURVE_PK")?,
                h64(&env("BRIDGE_SIGNER_MESH_ED25519_SK")?, "MESH_ED25519_SK")?,
            )
        };

    // Safety self-check: our derived x25519 must match what the committee advertises
    // (else peers dial the wrong key and every CURVE handshake fails).
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("this node's derived x25519 does not match its bridge.committee entry (wrong MN key file / curve key?)".into());
        }
    }

    let to_addr = |(index, endpoint, curve_pubkey): (u16, String, [u8; 32])| PeerTransportAddr {
        index,
        endpoint,
        curve_pubkey,
    };
    let make_identity = move |listen: String| MeshIdentity {
        listen_endpoint: listen,
        curve_secret,
        curve_public,
        ed25519_secret,
    };

    let key_generation: u32 = run.key_generation;
    let timeout: Duration = run.timeout;
    // Channel encryption. Production: CURVE (needs libzmq built with CURVE). Set
    // BRIDGE_SIGNER_MESH_USE_CURVE=false for a libzmq without CURVE — plain sockets,
    // but per-message ed25519 auth (S4) stays on.
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !use_curve {
        println!("WARNING: mesh CURVE disabled (plain channel); message auth (S4) still enforced");
    }

    // 3) Which key(s) to generate: pgw | pevm | both (default `both` — the dual DKG).
    let leg_sel = std::env::var("BRIDGE_SIGNER_DKG_LEG").unwrap_or_else(|_| "both".into());
    let run_pgw = leg_sel == "both" || leg_sel == "pgw";
    let run_pevm = leg_sel == "both" || leg_sel == "pevm";
    if !run_pgw && !run_pevm {
        return Err(format!("BRIDGE_SIGNER_DKG_LEG must be pgw|pevm|both (got '{leg_sel}')"));
    }
    if run_pevm && port_base.is_none() {
        return Err("the Pevm leg / dual DKG needs BRIDGE_SIGNER_MESH_PORT_BASE (distinct port ranges per leg)".into());
    }

    // Reserve every execution this run will start before any of them sends a message. The
    // ids are derived from the committee and key generation, so a retry with the same
    // generation derives them again; the ledger refuses that. Default location: beside the
    // share tree, so `shares` and `shares-next` share one ledger.
    let ledger_dir = match std::env::var("BRIDGE_SIGNER_EXECUTION_LEDGER")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            let share = run.share_dir.clone().ok_or_else(|| {
                "set BRIDGE_SIGNER_SHARE_DIR or BRIDGE_SIGNER_EXECUTION_LEDGER: a DKG must \
                 record its execution ids so a retry cannot reuse them"
                    .to_string()
            })?;
            let share = std::path::Path::new(&share);
            share.parent().unwrap_or(std::path::Path::new(".")).join("dkg-executions")
        }
    };
    // The shares this run produces must be sealable before the ceremony starts: finding
    // out at the end would mean a finished DKG whose output cannot be saved.
    if let Some(share) = &run.share_dir {
        beldex_bridge_signer::share_file::require_key(Some(std::path::Path::new(share)))?;
    }
    {
        use beldex_bridge_signer::execution_ledger::reserve;
        if run_pgw {
            let id = beldex_bridge_signer::committee::execution_id(
                b"beldex-pgw-dkg-v1",
                &[&committee.identity_bytes(), &key_generation.to_le_bytes()],
            );
            reserve(&ledger_dir, "pgw-dkg", &id)?;
        }
        #[cfg(feature = "live-pevm-dkg")]
        if run_pevm {
            let keygen = beldex_bridge_signer::cggmp21_driver::keygen_execution_id(&committee, key_generation);
            let aux = beldex_bridge_signer::cggmp21_aux_driver::aux_execution_id(&committee, key_generation);
            reserve(&ledger_dir, "pevm-keygen", &keygen)?;
            reserve(&ledger_dir, "pevm-aux", &aux)?;
        }
        println!("execution ids for key generation {key_generation} reserved in {}", ledger_dir.display());
    }

    // Pevm ports live PEVM_PORT_OFFSET above the Pgw ports, so the two legs never
    // collide when run back-to-back on one host. Kept small (100, not 1000) so the
    // Pevm range stays near the Pgw base and away from ports the host may already
    // use — e.g. macOS's AirPlay Receiver on :7000, which a base of 6000 + 1000
    // would hit for self_index 0. Overridable via BRIDGE_SIGNER_MESH_PEVM_OFFSET.
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let check_size = |peers: &[PeerTransportAddr]| -> Result<(), String> {
        if peers.len() + 1 != committee.size() {
            return Err(format!(
                "peer book has {} peers; committee size is {} (need {} peers + self)",
                peers.len(), committee.size(), committee.size() - 1
            ));
        }
        Ok(())
    };

    // --- Pgw (ed25519 / FROST) ------------------------------------------------
    let mut pgw_vk = None;
    if run_pgw {
        let (identity, peers) = match port_base {
            Some(base) => {
                println!("Pgw peer book: bridge.committee, single-host ports {base}+index");
                let peers: Vec<PeerTransportAddr> = committee
                    .peer_transport_indexed(self_index as usize, base)
                    .into_iter()
                    .map(to_addr)
                    .collect();
                (make_identity(format!("tcp://0.0.0.0:{}", base + self_index)), peers)
            }
            None => {
                // Single-leg legacy resolution: explicit listen + (peers file or the
                // committee's shared mesh port).
                let listen = std::env::var("BRIDGE_SIGNER_MESH_LISTEN")
                    .map_err(|_| "set BRIDGE_SIGNER_MESH_PORT_BASE (or MESH_LISTEN + a peer source)".to_string())?;
                let peers: Vec<PeerTransportAddr> =
                    if let Ok(peers_path) = std::env::var("BRIDGE_SIGNER_PEERS_FILE") {
                        println!("Pgw peer book: peers file {peers_path}");
                        let text = std::fs::read_to_string(&peers_path)
                            .map_err(|e| format!("read peers file {peers_path}: {e}"))?;
                        let mut peers = Vec::new();
                        for (lineno, raw) in text.lines().enumerate() {
                            let line = raw.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() != 3 {
                                return Err(format!("peers file line {}: expected `index endpoint curve_hex`", lineno + 1));
                            }
                            let index: u16 = parts[0].parse().map_err(|_| format!("peers line {}: bad index", lineno + 1))?;
                            if index == self_index {
                                continue;
                            }
                            peers.push(PeerTransportAddr {
                                index,
                                endpoint: parts[1].to_string(),
                                curve_pubkey: h32(parts[2], "peer curve key")?,
                            });
                        }
                        peers
                    } else if committee.has_network_info() {
                        let mesh_port: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT")
                            .ok().and_then(|s| s.parse().ok()).unwrap_or(5580);
                        println!("Pgw peer book: bridge.committee shared port {mesh_port}");
                        committee.peer_transport(self_index as usize, mesh_port).into_iter().map(to_addr).collect()
                    } else {
                        return Err("no peer source: set BRIDGE_SIGNER_MESH_PORT_BASE or BRIDGE_SIGNER_PEERS_FILE".into());
                    };
                (make_identity(listen), peers)
            }
        };
        check_size(&peers)?;

        let mut rng = rand::rngs::OsRng;
        println!("running Pgw FROST DKG over the mesh (key generation {key_generation})…");
        let (group_vk, kp_blob, pk_blob) = run_live_capture(
            &committee, self_index, key_generation, &identity, &peers, use_curve, &mut rng, timeout,
        )
        .map_err(|e| format!("Pgw dkg failed: {e:?}"))?;
        println!("Pgw DKG complete — group ed25519 key (gateway owner_key): {}", hex(&group_vk));
        // Persist the share material so a later `sign` invocation can load it. This
        // is a dev file store; production custody (Vault/enclave) is D.1.
        if let Some(dir) = &run.share_dir {
            persist_pgw_material(&dir, self_index, &kp_blob, &pk_blob, &group_vk)?;
            println!("Pgw share material written to {dir}/pgw-{self_index}.{{keypackage,pubkeypackage,groupvk}}");
        }
        pgw_vk = Some(group_vk);
    }

    // --- Pevm (secp256k1 / CGGMP21) -------------------------------------------
    if run_pevm {
        let base = port_base.expect("checked above") + pevm_offset;
        #[cfg(feature = "live-pevm-dkg")]
        {
            use beldex_bridge_signer::cggmp21_aux_driver::{
                complete_key_share_blob, run_cggmp21_aux_over_transport,
            };
            use beldex_bridge_signer::cggmp21_driver::run_cggmp21_keygen_over_transport;
            use beldex_bridge_signer::dkg_driver::live::assemble_mesh;
            println!("Pevm peer book: bridge.committee, single-host ports {base}+index");
            let peers: Vec<PeerTransportAddr> = committee
                .peer_transport_indexed(self_index as usize, base)
                .into_iter()
                .map(to_addr)
                .collect();
            check_size(&peers)?;
            let identity = make_identity(format!("tcp://0.0.0.0:{}", base + self_index));

            // One mesh for both Pevm phases (keygen then aux) — avoids a port
            // rebind race between them and reuses the established links.
            let mut transport = assemble_mesh(&committee, self_index, &identity, &peers, use_curve)
                .map_err(|e| format!("Pevm mesh assembly failed: {e:?}"))?;

            println!("running Pevm cggmp21 keygen over the mesh (key generation {key_generation})…");
            let (x33, incomplete_blob) = run_cggmp21_keygen_over_transport(
                &committee, self_index, key_generation, &mut transport, timeout,
            )
            .map_err(|e| format!("Pevm keygen failed: {e:?}"))?;

            // Derive the EVM signer address the wBDX contract checks (ecrecover):
            // decompress the group key, keccak256 the uncompressed point, take the
            // last 20 bytes.
            use k256::ecdsa::VerifyingKey;
            use sha3::{Digest, Keccak256};
            let addr = VerifyingKey::from_sec1_bytes(&x33)
                .map(|vk| {
                    let enc = vk.to_encoded_point(false);
                    let h = Keccak256::digest(&enc.as_bytes()[1..]);
                    let mut a = [0u8; 20];
                    a.copy_from_slice(&h[12..]);
                    a
                })
                .map_err(|e| format!("Pevm group key is not a valid secp256k1 point: {e}"))?;
            println!(
                "Pevm keygen complete — wBDX signer address 0x{} (group key {})",
                hex(&addr),
                hex(&x33)
            );

            // Aux-info over the same mesh, then combine into the complete share the
            // signing driver needs. This is the slow safe-prime phase.
            println!("running Pevm aux-info generation over the mesh…");
            let aux_blob = run_cggmp21_aux_over_transport(
                &committee, self_index, key_generation, &mut transport, timeout,
            )
            .map_err(|e| format!("Pevm aux-info failed: {e:?}"))?;
            let complete_blob = complete_key_share_blob(&incomplete_blob, &aux_blob)
                .map_err(|e| format!("Pevm share completion failed: {e:?}"))?;
            println!("Pevm complete share ready (keygen + aux-info)");

            if let Some(dir) = &run.share_dir {
                persist_pevm_material(&dir, self_index, &complete_blob, &x33)?;
                println!("Pevm share material written to {dir}/pevm-{self_index}.{{keyshare,groupkey}}");
            }

            // Both legs done here does not mean done everywhere: keep the key only once
            // every member says, signed, that it finished with the same two
            // (dkg_driver::confirm_key). The signatures are the key's certificate.
            if let Some(vk) = &pgw_vk {
                let pevm: [u8; 33] = x33[..].try_into().map_err(|_| "Pevm group key is not 33 bytes".to_string())?;
                let signer = beldex_bridge_signer::wire_auth::LibsodiumSigner { sk64: ed25519_secret };
                let cert = beldex_bridge_signer::dkg_driver::confirm_key(
                    &committee, self_index, key_generation, vk, &pevm, &signer,
                    &beldex_bridge_signer::wire_auth::LibsodiumEd25519, &mut transport, timeout,
                )
                .map_err(|e| format!("key confirmation failed: {e:?}"))?;
                println!("all {} members confirmed they hold this key", committee.size());
                if let Some(dir) = &run.share_dir {
                    std::fs::write(format!("{dir}/{KEY_CERT_FILE}"), cert.to_text())
                        .map_err(|e| format!("write {dir}/{KEY_CERT_FILE}: {e}"))?;
                    println!("key certificate ({} signatures) written to {dir}/{KEY_CERT_FILE}", cert.sigs.len());
                }
            }
        }
        #[cfg(not(feature = "live-pevm-dkg"))]
        {
            let _ = (base, pgw_vk);
            return Err("the Pevm leg needs a build with --features live-pevm-dkg".into());
        }
    }

    // The committee these shares belong to. A share's index is its position in THIS list,
    // and this list — not whichever committee consensus selects later — is who can sign
    // with the key until it is replaced on chain.
    if let Some(dir) = &run.share_dir {
        std::fs::write(format!("{dir}/{KEY_COMMITTEE_FILE}"), &committee_json)
            .map_err(|e| format!("write {dir}/{KEY_COMMITTEE_FILE}: {e}"))?;
        println!("key committee (epoch {}) written to {dir}/{KEY_COMMITTEE_FILE}", committee.epoch);
    }

    println!("(shares in the scaffold in-memory store; production custody = Vault/enclave)");
    Ok(())
}

/// Beside each share tree: the `bridge.committee` reply `dkg` ran against.
#[cfg(feature = "live-dkg")]
const KEY_COMMITTEE_FILE: &str = "committee.json";

/// Beside each share tree: every member's signature on the key ([`beldex_bridge_signer::dkg_driver::KeyCertificate`]).
#[cfg(feature = "live-dkg")]
const KEY_CERT_FILE: &str = "keycert";

#[cfg(feature = "live-dkg")]
fn run_verify_keycert(path: Option<String>) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::KeyCertificate;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;

    let path = path.ok_or("usage: verify-keycert <keycert file>")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let cert = KeyCertificate::from_text(&text).map_err(|e| format!("{path}: {e}"))?;
    let endpoint = std::env::var("BRIDGE_SIGNER_OXENMQ_ENDPOINT")
        .map_err(|_| "set BRIDGE_SIGNER_OXENMQ_ENDPOINT (beldexd's OMQ socket)".to_string())?;
    let committee = OmqCommitteeClient::new(endpoint)
        .fetch_committee(Some(cert.height))
        .map_err(|e| format!("bridge.committee at height {}: {e}", cert.height))?;
    cert.verify(&committee, &beldex_bridge_signer::wire_auth::LibsodiumEd25519)?;
    println!(
        "OK: the key of the epoch {} committee ({} members, all signed)\n  Pgw  {}\n  Pevm {}",
        cert.epoch,
        committee.size(),
        hex(&cert.pgw),
        hex(&cert.pevm)
    );
    Ok(())
}

#[cfg(not(feature = "live-dkg"))]
fn run_verify_keycert(_path: Option<String>) -> Result<(), String> {
    Err("verify-keycert requires a build with `--features live-dkg`".into())
}

/// The committee that holds the key in `dir`, and this node's index in it.
///
/// That is the committee `dkg` saved beside the shares — not the current one. Consensus
/// selects a new committee every epoch, but the key it held stays live, and stays signable
/// only by its own holders, until the rotation replacing it lands; the outgoing committee
/// has to sign that very rotation. A tree written before `dkg` saved its committee falls
/// back to the current one, which is what it was built against.
#[cfg(feature = "live-dkg")]
fn load_key_committee(
    cfg: &Config,
    dir: &str,
) -> Result<(beldex_bridge_signer::committee::CommitteeView, u16), String> {
    use beldex_bridge_signer::committee::CommitteeView;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;

    let path = format!("{dir}/{KEY_COMMITTEE_FILE}");
    let committee = match std::fs::read_to_string(&path) {
        Ok(json) => {
            let c = CommitteeView::from_bridge_committee_json(&json).map_err(|e| format!("{path}: {e}"))?;
            println!("key committee from {path} (epoch {}, size {})", c.epoch, c.size());
            c
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone())
            .fetch_committee(None)
            .map_err(|e| e.to_string())?,
        Err(e) => return Err(format!("read {path}: {e}")),
    };
    // `self_index` in a saved reply is this node's own daemon's answer at DKG time — the
    // index its share files carry.
    let self_index = committee
        .daemon_self_index
        .or_else(|| committee.self_index(&cfg.self_mn_pubkey))
        .ok_or("this node does not hold a share of this committee's key")? as u16;
    if !committee.has_signer_keys() {
        return Err("bridge.committee returned no signer_keys — update beldexd".into());
    }
    Ok((committee, self_index))
}

#[cfg(not(feature = "live-dkg"))]
fn run_dkg(_cfg: &Config) -> Result<(), String> {
    Err("the `dkg` subcommand requires a build with `--features live-dkg`".into())
}

/// The epoch whose complete key a share tree holds for this node, if any: its saved
/// committee, both legs' files under the index that committee gave this node, and the
/// key's certificate.
#[cfg(feature = "live-dkg")]
fn tree_key_epoch(dir: &std::path::Path) -> Option<u64> {
    let json = std::fs::read_to_string(dir.join(KEY_COMMITTEE_FILE)).ok()?;
    let c = beldex_bridge_signer::committee::CommitteeView::from_bridge_committee_json(&json).ok()?;
    let i = c.daemon_self_index?;
    let files = [
        format!("pgw-{i}.keypackage"),
        format!("pgw-{i}.groupvk"),
        format!("pevm-{i}.keyshare"),
        format!("pevm-{i}.groupkey"),
        KEY_CERT_FILE.to_string(),
    ];
    files.iter().all(|f| dir.join(f).is_file()).then_some(c.epoch)
}

/// Whether the key in `dir` is one a hand-off is under way to (the contract's pending signer)
/// or has reached (its current signer) on any chain in `BRIDGE_SIGNER_EVM_CHAINS`. Such a tree
/// is never moved aside for a newer committee's key: its members still have to sign with it,
/// or install it. False when nothing can be read: the lock is then the only guard.
#[cfg(feature = "serve-live")]
fn key_in_use(dir: &std::path::Path) -> bool {
    use beldex_bridge_signer::evm_watcher::{parse_evm_chains, HttpJsonRpc, JsonRpcClient};
    let Some(cert) = std::fs::read_to_string(dir.join(KEY_CERT_FILE))
        .ok()
        .and_then(|t| beldex_bridge_signer::dkg_driver::KeyCertificate::from_text(&t).ok())
    else {
        return false;
    };
    let Ok(vk) = k256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.pevm) else { return false };
    let signer = hex(&beldex_bridge_signer::aggregate_signature::eth_address(&vk));
    let chains = std::env::var("BRIDGE_SIGNER_EVM_CHAINS").ok().and_then(|j| parse_evm_chains(&j).ok()).unwrap_or_default();
    chains.iter().any(|c| {
        let client = HttpJsonRpc::new(c.rpc_url.clone());
        // currentSigner(), pendingSigner()
        ["0x4cd615e7", "0x14d90c45"].iter().any(|sel| {
            client
                .call("eth_call", serde_json::json!([{ "to": format!("0x{}", hex(&c.contract)), "data": sel }, "latest"]))
                .ok()
                .and_then(|w| w.as_str().and_then(|w| w.get(26..)).map(str::to_ascii_lowercase))
                .is_some_and(|a| a == signer)
        })
    })
}

#[cfg(all(feature = "live-dkg", not(feature = "serve-live")))]
fn key_in_use(_dir: &std::path::Path) -> bool {
    false
}

/// `root/base`, or `root/base.<n>` for the first free `n`: a tree moved aside never lands on
/// another one.
#[cfg(feature = "live-dkg")]
fn free_name(root: &std::path::Path, base: &str) -> std::path::PathBuf {
    let mut p = root.join(base);
    let mut n = 1;
    while p.exists() {
        p = root.join(format!("{base}.{n}"));
        n += 1;
    }
    p
}

/// `dkg-auto`: run beside `beldexd` and make this node's share of each epoch's key as soon
/// as its committee is selected, retrying within the epoch on the schedule every member
/// derives from the chain ([`beldex_bridge_signer::dkg::AttemptSchedule`]).
///
/// Every key goes into the `shares-next` beside `BRIDGE_SIGNER_SHARE_DIR`, on every member
/// alike: which tree a key lands in must not depend on what one node happens to hold, or
/// a member new to the bridge would treat the next key as the live one. Installing it in
/// the live tree is a separate step (the rotation's promotion; at launch, the first key's
/// setup). Each attempt writes into a fresh directory and only a complete key is moved into
/// place, so a failed attempt leaves no part of a key behind. Whether an epoch already has
/// its key is read from this node's own trees; the key announcement on Beldex is meant to
/// replace that.
#[cfg(feature = "live-dkg")]
fn run_dkg_auto(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::dkg::AttemptSchedule;
    use beldex_bridge_signer::omq_client::OmqCommitteeClient;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    let num = |k: &str, default: u64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(default);
    let live = PathBuf::from(
        std::env::var("BRIDGE_SIGNER_SHARE_DIR").map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR (the live share tree)".to_string())?,
    );
    let root = live.parent().unwrap_or(Path::new(".")).to_path_buf();
    let next = root.join("shares-next");
    let epoch_blocks = cfg.bridge_epoch_blocks;
    // By default an attempt an hour on a 2880-block day, the last one a full interval
    // before the next committee is selected.
    let retry = num("BRIDGE_SIGNER_DKG_RETRY_BLOCKS", (epoch_blocks / 24).max(60));
    let schedule = AttemptSchedule {
        settle: num("BRIDGE_SIGNER_DKG_SETTLE_BLOCKS", 2),
        retry,
        join: num("BRIDGE_SIGNER_DKG_JOIN_BLOCKS", 3),
        cutoff: num("BRIDGE_SIGNER_DKG_CUTOFF_BLOCKS", retry),
    };
    // Its own ports: a member of both the outgoing committee (serving) and the incoming one
    // (generating) runs both meshes at once.
    let port_base: Option<u16> = std::env::var("BRIDGE_SIGNER_DKG_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
                .map(|b| b + 1000)
        });
    // The Pevm aux-info phase alone takes minutes.
    let timeout = Duration::from_secs(num("BRIDGE_SIGNER_DKG_TIMEOUT_SECS", 1800));
    let poll = Duration::from_secs(num("BRIDGE_SIGNER_DKG_POLL_SECS", 5).max(1));
    println!(
        "dkg-auto: live tree {}, new keys into {}; an attempt every {} blocks from block {} of an epoch, \
         {} block(s) to join, none in its last {}; mesh port base {:?}, timeout {}s",
        live.display(), next.display(), schedule.retry, schedule.settle, schedule.join, schedule.cutoff,
        port_base, timeout.as_secs()
    );

    // Work directories of a run this process did not finish (it was stopped mid-attempt).
    // They never hold a key: one is only ever moved into place complete.
    if let Ok(it) = std::fs::read_dir(&root) {
        for e in it.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let parts: Vec<&str> = name.strip_prefix(".dkg-").unwrap_or("").split('-').collect();
            if parts.len() == 2 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
                let _ = std::fs::remove_dir_all(e.path());
                println!("dkg-auto: removed the unfinished attempt {}", e.path().display());
            }
        }
    }
    // A rotation that is installing the key in `shares-next` holds this; that key is then
    // never replaced, even by a newer committee's.
    let lock = root.join("shares-next.lock");

    let client = OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone());
    // The last attempt started. An attempt is never started twice: its execution ids are
    // spent once it begins.
    let mut tried: Option<(u64, u32)> = None;
    // The activation (sign_activation) is tried once per slot of ACTIVATION_SLOT blocks,
    // started only in a slot's first few blocks: the signers derive the slot, and with it
    // the session's attempt number, from the chain, so they start the same session.
    const ACTIVATION_SLOT: u64 = 10;
    let mut activation_tried: Option<(u64, u64)> = None;
    // The key attestation (attest_tree_key): the epoch it is done for, and when to look again.
    let mut attest_done: Option<u64> = None;
    let mut attest_next = std::time::Instant::now();
    let mut said = String::new();
    let mut say = |msg: String| {
        if msg != said {
            println!("{msg}");
            said = msg;
        }
    };
    #[cfg(feature = "serve-live")]
    let status = StatusBoard::start("dkg-auto");
    // The status endpoint's calls; they compile away in a build without it.
    macro_rules! status {
        ($($call:tt)*) => {{
            #[cfg(feature = "serve-live")]
            status.$($call)*;
        }};
    }
    let mut absence = Absence::new(cfg);
    loop {
        std::thread::sleep(poll);
        let (committee, tip) = match (client.fetch_committee(None), client.fetch_height()) {
            (Ok(c), Ok(h)) => (c, h),
            (Err(e), _) | (_, Err(e)) => {
                say(format!("dkg-auto: no answer from beldexd: {e}"));
                status!(problem("beldexd", Some(e.to_string())));
                continue;
            }
        };
        absence.tick(&committee, tip);
        let epoch = committee.epoch;
        status!(beat(poll * 6));
        status!(problem("beldexd", None));
        status!(set("epoch", epoch));
        status!(set("height", tip));
        status!(set("live_key_epoch", tree_key_epoch(&live).map_or(serde_json::Value::Null, |e| e.into())));
        status!(set("next_key_epoch", tree_key_epoch(&next).map_or(serde_json::Value::Null, |e| e.into())));
        if committee.members.is_empty() {
            say(format!("epoch {epoch}: no bridge committee (bridge dormant)"));
            continue;
        }
        let Some(self_index) = committee.daemon_self_index else {
            say(format!("epoch {epoch}: this node is not on the committee"));
            status!(set("member", "not on the committee"));
            status!(problem("dkg", None));
            continue;
        };
        status!(set("member", self_index));
        if tree_key_epoch(&live) == Some(epoch) || tree_key_epoch(&next) == Some(epoch) {
            say(format!("epoch {epoch}: this node holds its share of the epoch's key"));
            status!(problem("dkg", None));
            // Every member attests the key on chain: the outgoing committee hands over only to an
            // attested one. After sending, the chain gets time to count it before another try.
            if attest_done != Some(epoch) && std::time::Instant::now() >= attest_next {
                let tree = if tree_key_epoch(&next) == Some(epoch) { &next } else { &live };
                match attest_tree_key(cfg, tree, epoch, self_index as u16) {
                    Ok((done, m)) => {
                        if done {
                            attest_done = Some(epoch);
                        }
                        attest_next = std::time::Instant::now() + Duration::from_secs(600);
                        status!(set("attestation", m.clone()));
                        status!(problem("attestation", None));
                        say(format!("epoch {epoch}: {m}"));
                    }
                    Err(e) => {
                        attest_next = std::time::Instant::now() + Duration::from_secs(60);
                        status!(problem("attestation", Some(e.clone())));
                        eprintln!("epoch {epoch}: key attestation: {e}");
                    }
                }
            }
            let slot = tip / ACTIVATION_SLOT;
            if let Some(base) = port_base.filter(|_| tree_key_epoch(&next) == Some(epoch)) {
                // At once the first time (the signers all finish the DKG together, so they are
                // in the same slot), then at the start of each later slot until it is signed.
                let first = activation_tried.map_or(true, |(e, _)| e != epoch);
                if (first || tip % ACTIVATION_SLOT < schedule.join.max(1)) && activation_tried != Some((epoch, slot)) {
                    activation_tried = Some((epoch, slot));
                    // Ports 200 above the DKG's: clear of its two legs' meshes.
                    match sign_activation(cfg, &next, base + 200, slot as u32) {
                        Ok(m) => {
                            status!(set("activation", m.clone()));
                            status!(problem("activation", None));
                            say(format!("epoch {epoch}: {m}"))
                        }
                        Err(e) => {
                            status!(problem("activation", Some(e.clone())));
                            eprintln!("epoch {epoch}: activation not signed yet: {e}")
                        }
                    }
                }
            }
            continue;
        }
        // This epoch's key, finished while a rotation held the lock: once the rotation is
        // done it is the newest key, so it goes where an uninstalled key belongs.
        let parked = root.join(format!("shares-next.unplaced-at-{epoch}"));
        if !lock.exists() && tree_key_epoch(&parked) == Some(epoch) && !key_in_use(&next) {
            if next.exists() {
                let aside = free_name(&root, &format!("shares-next.superseded-at-{epoch}"));
                std::fs::rename(&next, &aside).map_err(|e| format!("move {} aside: {e}", next.display()))?;
                println!("epoch {epoch}: the uninstalled key moved to {}", aside.display());
            }
            std::fs::rename(&parked, &next).map_err(|e| format!("move the key into {}: {e}", next.display()))?;
            println!("epoch {epoch}: key kept aside during the rotation now in {}", next.display());
            continue;
        }
        let Some(k) = schedule.attempt_at(committee.height, epoch_blocks, tip) else {
            say(format!("epoch {epoch}: member {self_index}, waiting for the next attempt to open"));
            continue;
        };
        if tried >= Some((epoch, k)) {
            continue;
        }
        if lock.exists() {
            say(format!("epoch {epoch}: a rotation holds {}; not making a new key", lock.display()));
            continue;
        }
        tried = Some((epoch, k));

        let target = next.clone();
        let work = root.join(format!(".dkg-{epoch}-{k}"));
        let _ = std::fs::remove_dir_all(&work);
        println!(
            "epoch {epoch}: attempt {k} at height {tip}, member {self_index} of {} → {}",
            committee.size(),
            target.display()
        );
        let run = DkgRun {
            key_generation: k,
            share_dir: Some(work.to_string_lossy().into_owned()),
            port_base,
            timeout,
            epoch: Some(epoch),
            standby_round: None,
        };
        // A DKG holds this loop for up to its timeout: say so, and that it is not stuck.
        status!(set("dkg_running", format!("epoch {epoch} attempt {k} since height {tip}")));
        status!(beat(timeout + Duration::from_secs(120)));
        let result = run_dkg_with(cfg, &run);
        status!(set("dkg_running", serde_json::Value::Null));
        if let Err(e) = result {
            eprintln!("epoch {epoch}: attempt {k} failed: {e}");
            absence.attempt_failed(&committee, self_index as u16, &e);
            status!(set("last_attempt", format!("epoch {epoch} attempt {k}: failed: {e}")));
            status!(problem("dkg", Some(format!("epoch {epoch} attempt {k} failed: {e}"))));
            let _ = std::fs::remove_dir_all(&work);
            continue;
        }
        status!(set("last_attempt", format!("epoch {epoch} attempt {k}: key made")));
        status!(problem("dkg", None));
        absence.attempt_succeeded();
        if lock.exists() || key_in_use(&next) {
            // A rotation took the old key while this one was being made, or a hand-off is
            // under way to it on chain: leave it in place.
            let parked = root.join(format!("shares-next.unplaced-at-{epoch}"));
            std::fs::rename(&work, &parked).map_err(|e| format!("park the key in {}: {e}", parked.display()))?;
            eprintln!("epoch {epoch}: {} is in use by a hand-off; the new key was kept in {}", next.display(), parked.display());
            continue;
        }
        if next.exists() {
            // A key that was never installed: the newest committee's replaces it. Kept rather
            // than deleted, like every retired tree.
            let aside = free_name(&root, &format!("shares-next.superseded-at-{epoch}"));
            std::fs::rename(&next, &aside).map_err(|e| format!("move {} aside: {e}", next.display()))?;
            println!("epoch {epoch}: the uninstalled key moved to {}", aside.display());
        }
        std::fs::rename(&work, &target).map_err(|e| format!("move the key into {}: {e}", target.display()))?;
        println!("epoch {epoch}: key ready in {} (generation {k})", target.display());
    }
}

/// dkg-auto's part in pausing absent seats (key_attestation::absence): after two failed
/// attempts in a row that never heard from the same members, this member signs a report naming
/// them and publishes its signature on the bus; members pool the signatures, and once the
/// epoch's threshold have signed, the lowest-indexed signer (or, two minutes on, any of them)
/// puts the report on chain from its fee wallet. And for this node's own seat: if it was paused
/// before this process started (it was restarted since, as fixing a stopped signer does), it
/// sends its resume, once, so it is drawn again.
#[cfg(feature = "serve-live")]
struct Absence {
    genesis: Option<[u8; 32]>,
    sk: Option<[u8; 64]>,
    daemon: beldex_bridge_signer::evm_watcher::HttpJsonRpc,
    wallet: Option<beldex_bridge_signer::evm_watcher::HttpJsonRpc>,
    bus: Vec<String>,
    subs: Vec<beldex_bridge_signer::omq_client::OmqMintSubscriber>,
    /// This node's own daemon (its OMQ socket): who this seat is.
    own: beldex_bridge_signer::omq_client::OmqCommitteeClient,
    tracker: beldex_bridge_signer::key_attestation::absence::Tracker,
    collector: beldex_bridge_signer::key_attestation::absence::Collector,
    /// Reports this member signed, and when it first saw the threshold of signatures on one.
    mine: std::collections::BTreeMap<(u64, Vec<u16>), Option<std::time::Instant>>,
    submitted: std::collections::BTreeSet<(u64, Vec<u16>)>,
    started_height: Option<u64>,
    resumed: std::collections::BTreeSet<u64>,
    resume_checked: Option<std::time::Instant>,
}

#[cfg(feature = "serve-live")]
impl Absence {
    fn new(cfg: &Config) -> Absence {
        use beldex_bridge_signer::evm_watcher::HttpJsonRpc;
        let nonempty = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let wallet = nonempty("BRIDGE_SIGNER_ACK_WALLET_RPC").map(|url| {
            match nonempty("BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE")
                .and_then(|f| beldex_bridge_signer::rpc_login::read_login_file(std::path::Path::new(f.trim())).ok())
            {
                Some(login) => HttpJsonRpc::new(url).with_basic_auth(&login),
                None => HttpJsonRpc::new(url),
            }
        });
        let bus = bus_endpoints(&nonempty("BRIDGE_SIGNER_MINT_BUS_ENDPOINT").unwrap_or_else(|| cfg.oxenmq_endpoint.clone()));
        Absence {
            genesis: nonempty("BRIDGE_SIGNER_GENESIS_HASH").and_then(|h| config::parse_hex32(&h)).filter(|g| *g != [0; 32]),
            sk: nonempty("BRIDGE_SIGNER_MN_KEY_FILE").and_then(|f| std::fs::read(f.trim()).ok()).and_then(|b| b.try_into().ok()),
            daemon: HttpJsonRpc::new(format!("{}/json_rpc", cfg.beldexd_rpc_url.trim_end_matches('/'))),
            wallet,
            subs: bus.iter().cloned().map(beldex_bridge_signer::omq_client::OmqMintSubscriber::new).collect(),
            own: beldex_bridge_signer::omq_client::OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone()),
            bus,
            tracker: Default::default(),
            collector: Default::default(),
            mine: Default::default(),
            submitted: Default::default(),
            started_height: None,
            resumed: Default::default(),
            resume_checked: None,
        }
    }

    /// A DKG attempt of `committee`'s epoch failed with `error`.
    fn attempt_failed(&mut self, committee: &beldex_bridge_signer::committee::CommitteeView, self_index: u16, error: &str) {
        use beldex_bridge_signer::key_attestation::absence;
        let Some(absent) = self.tracker.failed(committee.epoch, absence::missing_peers(error)) else { return };
        let (Some(genesis), Some(sk)) = (self.genesis, self.sk) else {
            eprintln!("epoch {}: members {absent:?} absent twice, but no genesis / MN key to report them with", committee.epoch);
            return;
        };
        // More absent than the committee can do without: no threshold of present members exists.
        if absent.contains(&self_index) || absent.len() > committee.size().saturating_sub(committee.threshold) {
            return;
        }
        let msg = absence::message(&genesis, committee.epoch, &absent);
        let Ok(sig) = beldex_bridge_signer::ffi::ed25519_sign_detached(&sk, &msg) else { return };
        self.collector.add(committee.epoch, &absent, self_index, sig);
        self.mine.entry((committee.epoch, absent.clone())).or_insert(None);
        let payload = format!(
            r#"{{"kind":"absence","epoch":{},"absent":{:?},"voter_index":{self_index},"sig":"{}"}}"#,
            committee.epoch,
            absent,
            hex(&sig)
        );
        println!("epoch {}: members {absent:?} absent from two attempts in a row: reporting them", committee.epoch);
        self.publish(committee, self_index, &sk, &genesis, &payload);
    }

    fn publish(
        &self,
        committee: &beldex_bridge_signer::committee::CommitteeView,
        self_index: u16,
        sk: &[u8; 64],
        genesis: &[u8; 32],
        payload: &str,
    ) {
        use beldex_bridge_signer::omq_client::{mint_publish_message, OmqCommitteeClient};
        let Ok(pub_sig) = beldex_bridge_signer::ffi::ed25519_sign_detached(sk, &mint_publish_message(genesis, payload)) else { return };
        let member = committee.members[self_index as usize];
        for e in &self.bus {
            if let Err(err) = OmqCommitteeClient::new(e.clone()).publish_mint_payload(payload, self_index, &pub_sig, &member) {
                eprintln!("  absence signature not published to {e}: {err}");
            }
        }
    }

    /// Every pass of the loop: pool peers' signatures, put a complete report on chain, and
    /// resume this node's seat if it was paused before this process started.
    fn tick(&mut self, committee: &beldex_bridge_signer::committee::CommitteeView, tip: u64) {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        use beldex_bridge_signer::key_attestation::absence;
        let started = *self.started_height.get_or_insert(tip);
        self.collector.prune(committee.epoch);
        self.mine.retain(|(e, _), _| *e >= committee.epoch);

        // Peers' signatures off the bus, each checked against the committee's signer key.
        let mut arrived = Vec::new();
        for sub in self.subs.iter_mut() {
            while let Ok(Some(p)) = sub.poll(std::time::Duration::from_millis(20)) {
                arrived.push(p);
            }
        }
        if let Some(genesis) = self.genesis {
            for p in arrived {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&p) else { continue };
                if v.get("kind").and_then(|k| k.as_str()) != Some("absence")
                    || v.get("epoch").and_then(|e| e.as_u64()) != Some(committee.epoch)
                {
                    continue;
                }
                let absent: Option<Vec<u16>> = v.get("absent").and_then(|a| a.as_array()).and_then(|a| {
                    a.iter().map(|x| x.as_u64().and_then(|x| u16::try_from(x).ok())).collect()
                });
                let voter = v.get("voter_index").and_then(|x| x.as_u64()).and_then(|x| u16::try_from(x).ok());
                let sig: Option<[u8; 64]> = v
                    .get("sig")
                    .and_then(|s| s.as_str())
                    .and_then(|h| (0..h.len()).step_by(2).map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect::<Option<Vec<u8>>>())
                    .and_then(|b| b.try_into().ok());
                let (Some(absent), Some(voter), Some(sig)) = (absent, voter, sig) else { continue };
                let Some(key) = committee.signer_key(voter as usize) else { continue };
                if beldex_bridge_signer::ffi::ed25519_verify_consensus(&sig, &absence::message(&genesis, committee.epoch, &absent), &key) {
                    self.collector.add(committee.epoch, &absent, voter, sig);
                }
            }
        }

        // A report this member signed that has the threshold: the lowest-indexed signer sends it
        // at once, the others two minutes on if it has not landed.
        let self_index = committee.daemon_self_index.map(|i| i as u16);
        let keys: Vec<(u64, Vec<u16>)> = self.mine.keys().cloned().collect();
        for key in keys {
            if self.submitted.contains(&key) {
                continue;
            }
            let sigs = self.collector.signatures(key.0, &key.1);
            if sigs.len() < committee.threshold {
                continue;
            }
            let since = *self.mine.get_mut(&key).expect("listed").get_or_insert_with(std::time::Instant::now);
            let first = sigs.first().map(|(v, _)| *v) == self_index;
            if !first && since.elapsed() < std::time::Duration::from_secs(120) {
                continue;
            }
            // Stepping in for the first signer: not if its report already landed (every member
            // named is paused in this epoch). Another copy would only cost another fee.
            if !first {
                // The report is this committee's: its epoch starts at the committee's height.
                let epoch_start = committee.height;
                let paused_now = self.daemon.call("bridge_get_seats", serde_json::json!({})).ok().is_some_and(|seats| {
                    let rows = seats.get("seats").and_then(|s| s.as_array()).cloned().unwrap_or_default();
                    key.1.iter().all(|i| {
                        let Some(pk) = committee.members.get(*i as usize).map(|m| hex(m)) else { return false };
                        rows.iter().any(|r| {
                            r.get("master_node_pubkey").and_then(|k| k.as_str()).is_some_and(|k| k.eq_ignore_ascii_case(&pk))
                                && r.get("paused_height").and_then(|h| h.as_u64()).is_some_and(|h| h >= epoch_start)
                        })
                    })
                });
                if paused_now {
                    println!("epoch {}: absence report for {:?} already on chain", key.0, key.1);
                    self.submitted.insert(key);
                    continue;
                }
            }
            let Some(wallet) = &self.wallet else {
                eprintln!("epoch {}: absence report for {:?} is complete, but there is no fee wallet to send it", key.0, key.1);
                self.submitted.insert(key);
                continue;
            };
            let reporters: Vec<serde_json::Value> =
                sigs.iter().map(|(v, s)| serde_json::json!({ "voter_index": v, "signature": hex(s) })).collect();
            match wallet.call("bridge_absence_report", serde_json::json!({ "epoch": key.0, "absent": key.1, "reporters": reporters })) {
                Ok(r) => println!(
                    "epoch {}: absence report for {:?} sent ({} reporters): tx {}",
                    key.0,
                    key.1,
                    sigs.len(),
                    r.get("tx_hash").and_then(|t| t.as_str()).unwrap_or("?")
                ),
                // Another member's landed first (or is in the pool): nothing left to do.
                Err(e) => println!("epoch {}: absence report for {:?} not sent ({e:?}); another member's may have landed", key.0, key.1),
            }
            self.submitted.insert(key);
        }

        // This node's own seat: paused before this process started? Then it was restarted since,
        // and says it is back, once per pause.
        if self.resume_checked.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(60)) {
            return;
        }
        self.resume_checked = Some(std::time::Instant::now());
        let (Some(genesis), Some(sk), Some(wallet)) = (self.genesis, self.sk, &self.wallet) else { return };
        let Ok(me) = self.own.fetch_master_node_pubkey() else { return };
        let Some(seats) = self.daemon.call("bridge_get_seats", serde_json::json!({})).ok() else { return };
        let paused = seats.get("seats").and_then(|s| s.as_array()).and_then(|s| {
            s.iter()
                .find(|x| x.get("master_node_pubkey").and_then(|k| k.as_str()).is_some_and(|k| k.eq_ignore_ascii_case(&me)))
                .and_then(|x| x.get("paused_height").and_then(|h| h.as_u64()))
        });
        let Some(paused_height) = paused else { return };
        if paused_height >= started || self.resumed.contains(&paused_height) {
            return;
        }
        let Some(mn) = config::parse_hex32(&me) else { return };
        let Ok(sig) = beldex_bridge_signer::ffi::ed25519_sign_detached(&sk, &absence::resume_message(&genesis, &mn, paused_height)) else {
            return;
        };
        match wallet.call(
            "bridge_resume",
            serde_json::json!({ "master_node_pubkey": me, "paused_height": paused_height, "signature": hex(&sig) }),
        ) {
            Ok(r) => {
                println!(
                    "this seat was paused at height {paused_height} and this signer has restarted since: resume sent, tx {}",
                    r.get("tx_hash").and_then(|t| t.as_str()).unwrap_or("?")
                );
                self.resumed.insert(paused_height);
            }
            Err(e) => eprintln!("  resume not sent ({e:?}); will try again"),
        }
    }

    fn attempt_succeeded(&mut self) {
        self.tracker.succeeded();
    }
}

#[cfg(not(feature = "serve-live"))]
struct Absence;

#[cfg(not(feature = "serve-live"))]
impl Absence {
    fn new(_cfg: &Config) -> Absence {
        Absence
    }
    fn attempt_failed(&mut self, _c: &beldex_bridge_signer::committee::CommitteeView, _i: u16, _e: &str) {}
    fn tick(&mut self, _c: &beldex_bridge_signer::committee::CommitteeView, _tip: u64) {}
    fn attempt_succeeded(&mut self) {}
}

/// The epoch of the committee consensus counts as holding the key (`pgw`, `pevm`), from this
/// node's own daemon (`bridge_get_standby`): the first epoch committee whose members attested it
/// (key_attestation). `None` while it is not attested, or if only a standby round attested it.
#[cfg(feature = "serve-live")]
fn attested_epoch_of(
    daemon: &beldex_bridge_signer::evm_watcher::HttpJsonRpc,
    pgw: &[u8; 32],
    pevm: &[u8; 20],
) -> Result<Option<u64>, String> {
    use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
    use beldex_bridge_signer::key_attestation as ka;
    let v = daemon.call("bridge_get_standby", serde_json::json!({})).map_err(|e| format!("bridge_get_standby: {e:?}"))?;
    let records = ka::parse_records(&v).ok_or("bridge_get_standby: no attestations in the reply")?;
    Ok(ka::holder(&records, pgw).filter(|r| r.round_height == 0 && r.pevm_address == *pevm).map(|r| r.epoch))
}

/// This member's key attestation for the key in `tree` (key_attestation): once every member
/// has confirmed the key (its certificate), each says on chain, from its own fee wallet
/// (`BRIDGE_SIGNER_ACK_WALLET_RPC`, logged in to with `BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE`),
/// that its committee generated it. The outgoing committee hands over only to a key consensus
/// counts as attested, so this comes before any hand-off. `Ok((true, _))` once the chain
/// counts this member or the key; `Ok((false, _))` after sending one (or printing it, with no
/// wallet), to be looked at again later.
#[cfg(feature = "serve-live")]
fn attest_tree_key(cfg: &Config, tree: &std::path::Path, epoch: u64, self_index: u16) -> Result<(bool, String), String> {
    use beldex_bridge_signer::aggregate_signature::eth_address;
    use beldex_bridge_signer::dkg_driver::KeyCertificate;
    use beldex_bridge_signer::evm_watcher::{HttpJsonRpc, JsonRpcClient as _};
    use beldex_bridge_signer::key_attestation as ka;

    let cert = KeyCertificate::from_text(
        &std::fs::read_to_string(tree.join(KEY_CERT_FILE)).map_err(|e| format!("{}/{KEY_CERT_FILE}: {e}", tree.display()))?,
    )?;
    if cert.epoch != epoch {
        return Err(format!("{} holds epoch {}'s key, not epoch {epoch}'s", tree.display(), cert.epoch));
    }
    let pevm = eth_address(&k256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.pevm).map_err(|e| format!("Pevm group key: {e}"))?);
    let daemon = HttpJsonRpc::new(format!("{}/json_rpc", cfg.beldexd_rpc_url.trim_end_matches('/')));
    let v = daemon.call("bridge_get_standby", serde_json::json!({})).map_err(|e| format!("bridge_get_standby: {e:?}"))?;
    let records = ka::parse_records(&v).ok_or("bridge_get_standby: no attestations in the reply")?;
    match ka::status(&records, epoch, 0, &cert.pgw, &pevm, self_index) {
        ka::Status::Attested => return Ok((true, format!("key attested: committee epoch {epoch} holds gateway key {}", hex(&cert.pgw)))),
        ka::Status::Counted => return Ok((true, format!("key attestation counted (member {self_index}); the others are still to come"))),
        ka::Status::Missing => {}
    }
    let key_file = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE").map_err(|_| "set BRIDGE_SIGNER_MN_KEY_FILE (this node's signer key)".to_string())?;
    let sk: [u8; 64] = std::fs::read(&key_file)
        .map_err(|e| format!("read {key_file}: {e}"))?
        .try_into()
        .map_err(|_| format!("{key_file} is not a 64-byte key_ed25519"))?;
    let genesis = std::env::var("BRIDGE_SIGNER_GENESIS_HASH")
        .ok()
        .and_then(|h| config::parse_hex32(&h))
        .filter(|g| *g != [0; 32])
        .ok_or("set BRIDGE_SIGNER_GENESIS_HASH: the attestation is bound to the chain")?;
    let sig = ka::sign(&sk, &genesis, epoch, 0, &cert.pgw, &pevm)?;
    let wallet = match std::env::var("BRIDGE_SIGNER_ACK_WALLET_RPC").ok().filter(|v| !v.trim().is_empty()) {
        None => {
            println!(
                "KEY-ATTESTATION epoch={epoch} round_height=0 pgw_vk={} pevm_address={} voter_index={self_index} signature={} \
                 (no wallet RPC: submit with the wallet RPC bridge_key_attestation)",
                hex(&cert.pgw),
                hex(&pevm),
                hex(&sig)
            );
            return Ok((false, "key attestation signed; no wallet RPC to send it (BRIDGE_SIGNER_ACK_WALLET_RPC)".into()));
        }
        Some(url) => match std::env::var("BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE").ok().filter(|v| !v.trim().is_empty()) {
            Some(f) => HttpJsonRpc::new(url).with_basic_auth(&beldex_bridge_signer::rpc_login::read_login_file(std::path::Path::new(f.trim()))?),
            None => HttpJsonRpc::new(url),
        },
    };
    let r = wallet
        .call(
            "bridge_key_attestation",
            serde_json::json!({
                "epoch": epoch,
                "round_height": 0,
                "pgw_vk": hex(&cert.pgw),
                "pevm_address": hex(&pevm),
                "voter_index": self_index,
                "signature": hex(&sig),
            }),
        )
        .map_err(|e| format!("key attestation not submitted: {e:?}"))?;
    Ok((
        false,
        format!(
            "key attestation (committee epoch {epoch}, member {self_index}) submitted: tx {}",
            r.get("tx_hash").and_then(serde_json::Value::as_str).unwrap_or("?")
        ),
    ))
}

#[cfg(not(feature = "serve-live"))]
fn attest_tree_key(_cfg: &Config, _tree: &std::path::Path, _epoch: u64, _self_index: u16) -> Result<(bool, String), String> {
    Ok((true, "key attestation needs a build with `--features serve-live`".into()))
}

/// `dkg-auto`'s part of the hand-off: the incoming committee signs `activateRotation` with the
/// key it has just made (in `next`), and publishes it on the bus with the key's certificate.
///
/// The contract takes it only after the outgoing committee's `rotateSigner` and the challenge
/// window, but it is signed now, while every member is still on line from the DKG. It is the
/// first signature the new key makes, so it doubles as the proof that the key signs. The
/// outgoing committee checks the certificate and this signature before it signs the hand-off
/// to this key, and a relayer holds the payload until the contract takes it.
///
/// Per chain in `BRIDGE_SIGNER_EVM_CHAINS`; the payload is kept as `next/activation-<chain>`
/// and published again on every call (the daemon's retained copy does not survive a restart),
/// and signed again if the contract's key epoch has moved since. A member outside the signer
/// set has nothing to sign.
#[cfg(feature = "serve-live")]
fn sign_activation(cfg: &Config, next: &std::path::Path, port_base: u16, attempt: u32) -> Result<String, String> {
    use beldex_bridge_signer::aggregate_signature::{eth_address, pevm_signer};
    use beldex_bridge_signer::dkg_driver::KeyCertificate;
    use beldex_bridge_signer::evm_watcher::{parse_evm_chains, HttpJsonRpc, JsonRpcClient};
    use beldex_bridge_signer::omq_client::{mint_publish_message, OmqCommitteeClient};

    let chains = match std::env::var("BRIDGE_SIGNER_EVM_CHAINS") {
        Ok(j) if !j.trim().is_empty() => parse_evm_chains(&j)?,
        _ => return Ok("no BRIDGE_SIGNER_EVM_CHAINS: activation not signed".into()),
    };
    let dir = next.to_string_lossy().into_owned();
    let cert_text = std::fs::read_to_string(next.join(KEY_CERT_FILE)).map_err(|e| format!("{dir}/{KEY_CERT_FILE}: {e}"))?;
    let cert = KeyCertificate::from_text(&cert_text)?;
    let signer = eth_address(
        &k256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.pevm).map_err(|e| format!("Pevm group key: {e}"))?,
    );
    let live = match build_live_signers_for(cfg, &dir, port_base) {
        Ok(l) => l,
        Err(e) if e.contains("not in the signer set") => return Ok("not in the activation's signer set".into()),
        Err(e) => return Err(e),
    };
    let genesis: Option<[u8; 32]> =
        std::env::var("BRIDGE_SIGNER_GENESIS_HASH").ok().and_then(|h| config::parse_hex32(&h)).filter(|g| *g != [0; 32]);
    let bus_endpoint = std::env::var("BRIDGE_SIGNER_MINT_BUS_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| cfg.oxenmq_endpoint.clone());
    let mut done = Vec::new();
    for c in &chains {
        // The epoch it activates: the one after the contract's current key.
        let reply = HttpJsonRpc::new(c.rpc_url.clone())
            .call("eth_call", serde_json::json!([{ "to": format!("0x{}", hex(&c.contract)), "data": "0x6fdf657e" }, "latest"]))
            .map_err(|e| format!("chain {}: keyEpoch(): {e:?}", c.chain_id))?;
        let key_epoch = reply
            .as_str()
            .and_then(|w| w.strip_prefix("0x"))
            .filter(|w| w.len() == 64 && w[..48].bytes().all(|b| b == b'0'))
            .and_then(|w| u64::from_str_radix(&w[48..], 16).ok())
            .ok_or_else(|| format!("chain {}: keyEpoch() returned {reply}", c.chain_id))?;
        // Activated already (by a relayer that carried this payload): nothing left to sign
        // or publish. Without this the epoch moving on would look like a stale activation and
        // get one for the next epoch, to a key that is already live.
        let current = HttpJsonRpc::new(c.rpc_url.clone())
            .call("eth_call", serde_json::json!([{ "to": format!("0x{}", hex(&c.contract)), "data": "0x4cd615e7" }, "latest"]))
            .map_err(|e| format!("chain {}: currentSigner(): {e:?}", c.chain_id))?;
        if current.as_str().and_then(|w| w.get(26..)).is_some_and(|a| a.eq_ignore_ascii_case(&hex(&signer))) {
            done.push(format!("chain {}: 0x{} is the live key, nothing to activate", c.chain_id, hex(&signer)));
            continue;
        }
        let pending_key_epoch = key_epoch + 1;
        let preimage =
            beldex_bridge_signer::release_policy::activate_preimage(c.chain_id, c.contract, pending_key_epoch, signer);
        let file = next.join(format!("activation-{}", c.chain_id));
        let kept = std::fs::read_to_string(&file)
            .ok()
            .filter(|p| p.contains(&format!(r#""pending_key_epoch":{pending_key_epoch},"#)));
        let payload = match kept {
            Some(p) => p,
            None => {
                let sig = live.pevm_sign(&preimage, &live.signers, attempt)?;
                if pevm_signer(&preimage, &sig) != Some(signer) {
                    return Err(format!(
                        "chain {}: the activation does not recover to the new key 0x{}",
                        c.chain_id,
                        hex(&signer)
                    ));
                }
                let payload = format!(
                    r#"{{"kind":"activate","contract":"{}","chain_id":{},"pending_signer":"{}","pending_key_epoch":{},"sig":"{}","keycert":"{}"}}"#,
                    hex(&c.contract),
                    c.chain_id,
                    hex(&signer),
                    pending_key_epoch,
                    hex(&sig),
                    cert_text.replace('\n', "\\n"),
                );
                std::fs::write(&file, &payload).map_err(|e| format!("write {}: {e}", file.display()))?;
                payload
            }
        };
        let published = match genesis {
            Some(g) => {
                let pub_sig = beldex_bridge_signer::ffi::ed25519_sign_detached(&live.ed25519_secret, &mint_publish_message(&g, &payload))?;
                let member = live.committee.members[live.self_index as usize];
                bus_endpoints(&bus_endpoint)
                    .into_iter()
                    .map(|e| match OmqCommitteeClient::new(e.clone()).publish_mint_payload(&payload, live.self_index, &pub_sig, &member) {
                        Ok(r) => format!("published to {e} ({r})"),
                        Err(err) => format!("NOT published to {e} ({err}); kept in {}", file.display()),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            }
            None => format!("not published (BRIDGE_SIGNER_GENESIS_HASH unset); kept in {}", file.display()),
        };
        done.push(format!("chain {} key epoch {pending_key_epoch} → 0x{}: {published}", c.chain_id, hex(&signer)));
    }
    Ok(format!("activation signed: {}", done.join("; ")))
}

#[cfg(all(feature = "live-dkg", not(feature = "serve-live")))]
fn sign_activation(_cfg: &Config, _next: &std::path::Path, _port_base: u16, _attempt: u32) -> Result<String, String> {
    Ok("activation not signed: needs a build with --features serve-live".into())
}

#[cfg(not(feature = "live-dkg"))]
fn run_dkg_auto(_cfg: &Config) -> Result<(), String> {
    Err("the `dkg-auto` subcommand requires a build with `--features live-dkg`".into())
}

/// What a long-running job (`serve`, `dkg-auto`, `handover-submit`) is doing, for monitoring:
/// with `BRIDGE_SIGNER_STATUS_LISTEN` set (e.g. `127.0.0.1:9100`) a thread answers
/// `GET /status` (all of it, as JSON) and `GET /health` (200 `ok`, or 503 and the problems), so
/// any monitoring tool can poll it. The job records facts and problems; it also beats a
/// heartbeat, and one missing for longer than the job said it may is a problem by itself —
/// the HTTP thread answers even while the job is busy, so a stuck job still shows up.
#[cfg(feature = "serve-live")]
#[derive(Clone)]
struct StatusBoard(std::sync::Arc<std::sync::Mutex<StatusState>>);

#[cfg(feature = "serve-live")]
struct StatusState {
    facts: serde_json::Map<String, serde_json::Value>,
    problems: std::collections::BTreeMap<String, String>,
    beat: std::time::Instant,
    stale_after: std::time::Duration,
}

#[cfg(feature = "serve-live")]
impl StatusBoard {
    fn start(role: &str) -> StatusBoard {
        let board = StatusBoard(std::sync::Arc::new(std::sync::Mutex::new(StatusState {
            facts: [("role".to_string(), serde_json::json!(role))].into_iter().collect(),
            problems: Default::default(),
            beat: std::time::Instant::now(),
            stale_after: std::time::Duration::from_secs(300),
        })));
        if let Some(listen) = std::env::var("BRIDGE_SIGNER_STATUS_LISTEN").ok().filter(|v| !v.trim().is_empty()) {
            match tiny_http::Server::http(&listen) {
                Ok(server) => {
                    println!("  status: http://{listen}/status and /health");
                    let b = board.clone();
                    std::thread::spawn(move || {
                        for req in server.incoming_requests() {
                            let (code, body) = b.answer(req.url());
                            let _ = req.respond(tiny_http::Response::from_string(body).with_status_code(code));
                        }
                    });
                }
                Err(e) => eprintln!("  status endpoint not started ({listen}: {e})"),
            }
        }
        board
    }

    fn set(&self, key: &str, value: impl Into<serde_json::Value>) {
        if let Ok(mut s) = self.0.lock() {
            s.facts.insert(key.to_string(), value.into());
        }
    }

    /// Record (`Some`) or clear (`None`) a named problem.
    fn problem(&self, name: &str, what: Option<String>) {
        if let Ok(mut s) = self.0.lock() {
            match what {
                Some(w) => s.problems.insert(name.to_string(), w),
                None => s.problems.remove(name),
            };
        }
    }

    /// The job is alive, and will be again within `next`.
    fn beat(&self, next: std::time::Duration) {
        if let Ok(mut s) = self.0.lock() {
            s.beat = std::time::Instant::now();
            s.stale_after = next;
        }
    }

    fn answer(&self, url: &str) -> (u16, String) {
        let Ok(s) = self.0.lock() else { return (500, "status unavailable".into()) };
        let mut problems = s.problems.clone();
        let quiet = s.beat.elapsed();
        if quiet > s.stale_after {
            problems.insert("stalled".into(), format!("no progress for {}s", quiet.as_secs()));
        }
        if url.starts_with("/health") {
            return if problems.is_empty() {
                (200, "ok\n".into())
            } else {
                (503, problems.iter().map(|(k, v)| format!("{k}: {v}\n")).collect())
            };
        }
        let mut all = s.facts.clone();
        all.insert("seconds_since_progress".into(), serde_json::json!(quiet.as_secs()));
        all.insert("problems".into(), serde_json::json!(problems));
        (200, serde_json::Value::Object(all).to_string())
    }
}

/// Read a secret share file: it must be sealed under the share key (see
/// [`beldex_bridge_signer::share_file`]); plaintext only on a test network that allows it.
#[cfg(any(feature = "live-dkg", feature = "live-pevm-dkg"))]
fn read_secret_file(path: &str) -> Result<Vec<u8>, String> {
    beldex_bridge_signer::share_file::read_secret(std::path::Path::new(path))
}

/// Read public group-key material written beside the shares.
#[cfg(feature = "live-dkg")]
fn read_public_file(path: &str) -> Result<Vec<u8>, String> {
    beldex_bridge_signer::share_file::read_public(std::path::Path::new(path))
}

/// Create a directory for secret material, owner-only.
#[cfg(any(feature = "live-dkg", feature = "live-pevm-dkg"))]
fn create_secret_dir(dir: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create share dir {dir}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best effort: an existing directory may be owned by someone else.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Write a secret share file, sealed under the share key and bound to its name. Refused
/// when no key is configured, unless a test network allows plaintext.
#[cfg(any(feature = "live-dkg", feature = "live-pevm-dkg"))]
fn write_secret_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    beldex_bridge_signer::share_file::write_secret(std::path::Path::new(path), bytes)
}

/// Write public group-key material: readable (scripts compare it), owner-only, atomic.
/// Members never trust it on its own; they check it against their sealed share.
#[cfg(any(feature = "live-dkg", feature = "live-pevm-dkg"))]
fn write_public_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    beldex_bridge_signer::share_file::write_public(std::path::Path::new(path), bytes)
}

/// Write this node's `Pgw` DKG material to `<dir>/pgw-<index>.{keypackage,
/// pubkeypackage,groupvk}` for a later `sign` invocation. Dev file store only.
#[cfg(feature = "live-dkg")]
fn persist_pgw_material(
    dir: &str,
    self_index: u16,
    kp: &[u8],
    pk: &[u8],
    vk: &[u8; 32],
) -> Result<(), String> {
    create_secret_dir(dir)?;
    let path = |suffix: &str| format!("{dir}/pgw-{self_index}.{suffix}");
    write_secret_file(&path("keypackage"), kp)?;
    write_public_file(&path("pubkeypackage"), pk)?;
    write_public_file(&path("groupvk"), vk)?;
    Ok(())
}

/// Write this node's complete `Pevm` share to `<dir>/pevm-<index>.{keyshare,
/// groupkey}` for a later `sign` invocation. Dev file store only.
#[cfg(feature = "live-pevm-dkg")]
fn persist_pevm_material(
    dir: &str,
    self_index: u16,
    keyshare: &[u8],
    x33: &[u8; 33],
) -> Result<(), String> {
    create_secret_dir(dir)?;
    write_secret_file(&format!("{dir}/pevm-{self_index}.keyshare"), keyshare)?;
    write_public_file(&format!("{dir}/pevm-{self_index}.groupkey"), x33)?;
    Ok(())
}

/// `sign` subcommand: load this node's persisted share material and run the signing
/// driver for the selected leg across the authenticated mesh. `BRIDGE_SIGNER_SIGN_LEG`
/// = `pgw` (FROST → libsodium-verified ed25519 release; default) or `pevm` (cggmp21
/// → ecrecover'd wBDX mint). Only built with `--features live-dkg`; the `pevm` leg
/// additionally needs `live-pevm-dkg`. Run `dkg` first with `BRIDGE_SIGNER_SHARE_DIR`.
#[cfg(feature = "live-dkg")]
fn run_sign(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::live::{MeshIdentity, PeerTransportAddr};
    use beldex_bridge_signer::ffi;
    use std::time::Duration;
    enforce_network_policy(cfg, &test_network_settings())?;

    // 1) Committee + self_index: the committee that holds the key in the share dir.
    let dir = std::env::var("BRIDGE_SIGNER_SHARE_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR (where `dkg` wrote the shares)".to_string())?;
    let (committee, self_index) = load_key_committee(cfg, &dir)?;

    // 2) Leg + signer set (default: the first `threshold` committee members).
    let leg = std::env::var("BRIDGE_SIGNER_SIGN_LEG").unwrap_or_else(|_| "pgw".into());
    let signers: Vec<u16> = match std::env::var("BRIDGE_SIGNER_SIGN_SIGNERS") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => (0..committee.threshold as u16).collect(),
    };
    println!(
        "committee epoch {} size {} threshold {}; self_index {}; leg {}; signer set {:?}",
        committee.epoch, committee.size(), committee.threshold, self_index, leg, signers
    );
    if !signers.contains(&self_index) {
        println!("this node ({self_index}) is not in the signer set — nothing to do");
        return Ok(());
    }

    // 3) Shared config + mesh identity material (from the MN key).
    let port_base: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("set BRIDGE_SIGNER_MESH_PORT_BASE (single-host devnet)")?;
    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let key_path = std::env::var("BRIDGE_SIGNER_MN_KEY_FILE")
        .map_err(|_| "set BRIDGE_SIGNER_MN_KEY_FILE".to_string())?;
    let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
    if sk_bytes.len() != 64 {
        return Err(format!("MN key {key_path} is {} bytes, expected 64", sk_bytes.len()));
    }
    let mut ed25519_secret = [0u8; 64];
    ed25519_secret.copy_from_slice(&sk_bytes);
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&ed25519_secret[32..64]);
    let curve_secret = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
    let curve_public = ffi::ed25519_pk_to_x25519(&ed_pub)?;
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("derived x25519 does not match this node's bridge.committee entry".into());
        }
    }
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !use_curve {
        println!("WARNING: mesh CURVE disabled (plain channel); message auth (S4) still enforced");
    }
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_SIGN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );

    // Build this node's identity + peer book for a given single-host port base.
    let build_mesh = |base: u16| -> (MeshIdentity, Vec<PeerTransportAddr>) {
        let identity = MeshIdentity {
            listen_endpoint: format!("tcp://0.0.0.0:{}", base + self_index),
            curve_secret,
            curve_public,
            ed25519_secret,
        };
        let peers = committee
            .peer_transport_indexed(self_index as usize, base)
            .into_iter()
            .map(|(index, endpoint, curve_pubkey)| PeerTransportAddr { index, endpoint, curve_pubkey })
            .collect();
        (identity, peers)
    };

    match leg.as_str() {
        "pgw" => {
            let (identity, peers) = build_mesh(port_base);
            sign_pgw(&committee, self_index, &signers, &dir, &identity, &peers, use_curve, timeout)
        }
        "pevm" => {
            let (identity, peers) = build_mesh(port_base + pevm_offset);
            sign_pevm(&committee, self_index, &signers, &dir, &identity, &peers, use_curve, timeout)
        }
        other => Err(format!("BRIDGE_SIGNER_SIGN_LEG must be pgw|pevm (got '{other}')")),
    }
}

/// `Pgw` leg of `sign`: FROST threshold-sign a 32-byte digest over the mesh and
/// verify the aggregate under libsodium (the consensus check).
#[cfg(feature = "live-dkg")]
#[allow(clippy::too_many_arguments)]
fn sign_pgw(
    committee: &beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: &[u16],
    dir: &str,
    identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    use_curve: bool,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use beldex_bridge_signer::ffi;
    use beldex_bridge_signer::frost_sign_driver::live::run_live_sign;

    let message: [u8; 32] = match std::env::var("BRIDGE_SIGNER_SIGN_DIGEST") {
        Ok(h) => config::parse_hex32(&h).ok_or("BRIDGE_SIGNER_SIGN_DIGEST must be 32-byte hex")?,
        Err(_) => {
            println!("WARNING: no BRIDGE_SIGNER_SIGN_DIGEST set — signing a fixed demo digest");
            [0x5au8; 32]
        }
    };
    let (key_package, pubkey_package) = load_pgw_material(&dir, self_index)?;
    let group_vk: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("cannot serialize group verifying key")?;

    let mut rng = rand::rngs::OsRng;
    println!("running Pgw FROST signing over the mesh…");
    let sig = run_live_sign(
        committee, self_index, signers, key_package, pubkey_package, message, 0, identity, peers,
        use_curve, &mut rng, timeout,
    )
    .map_err(|e| format!("Pgw sign failed: {e:?}"))?;

    let ok = ffi::ed25519_verify_consensus(&sig, &message, &group_vk);
    println!("Pgw signature : {}", hex(&sig));
    println!("  over digest : {}", hex(&message));
    println!("  owner_key   : {}", hex(&group_vk));
    println!("  libsodium   : {}", if ok { "VERIFIED (consensus would accept)" } else { "REJECTED" });
    if !ok {
        return Err("the aggregated signature failed libsodium verification".into());
    }
    Ok(())
}

/// `Pevm` leg of `sign`: cggmp21 threshold-sign a mint preimage over the mesh and
/// `ecrecover` the aggregate to the wBDX signer address (the on-chain check).
#[cfg(feature = "live-pevm-dkg")]
#[allow(clippy::too_many_arguments)]
fn sign_pevm(
    committee: &beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: &[u16],
    dir: &str,
    identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    use_curve: bool,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use beldex_bridge_signer::cggmp21_sign_driver::live::run_live_pevm_sign;
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
    use sha3::{Digest, Keccak256};

    // The mint preimage the contract keccaks + ecrecovers. Demo default; in
    // production this is the ABI-encoded mint tuple.
    let preimage: Vec<u8> = match std::env::var("BRIDGE_SIGNER_SIGN_PREIMAGE") {
        Ok(h) => hex_to_bytes(&h).ok_or("BRIDGE_SIGNER_SIGN_PREIMAGE must be hex")?,
        Err(_) => {
            println!("WARNING: no BRIDGE_SIGNER_SIGN_PREIMAGE set — signing a fixed demo mint preimage");
            b"BELDEX_BRIDGE_MINT_V1 || chainid || wBDX || to || amount || beldexTxid".to_vec()
        }
    };
    let key_share = read_secret_file(&format!("{dir}/pevm-{self_index}.keyshare"))
        .map_err(|e| format!("pevm: {e} (run `dkg` first with SHARE_DIR set)"))?;

    println!("running Pevm cggmp21 signing over the mesh…");
    let (rs, x33) = run_live_pevm_sign(
        committee, self_index, signers, &key_share, &preimage, /*attempt=*/ 0, identity, peers,
        use_curve, timeout,
    )
    .map_err(|e| format!("Pevm sign failed: {e:?}"))?;

    // Derive the expected wBDX address from the group key, then ecrecover.
    let expected = VerifyingKey::from_sec1_bytes(&x33)
        .map(|vk| {
            let enc = vk.to_encoded_point(false);
            let h = Keccak256::digest(&enc.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&h[12..]);
            a
        })
        .map_err(|e| format!("Pevm group key invalid: {e}"))?;
    let digest32: [u8; 32] = Keccak256::digest(&preimage).into();
    let k_sig = K256Sig::from_slice(&rs).map_err(|e| format!("bad signature bytes: {e}"))?;
    let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
    let mut recovered = None;
    for rec in [0u8, 1u8] {
        if let Ok(vk) = VerifyingKey::recover_from_prehash(
            &digest32,
            &k_sig,
            RecoveryId::from_byte(rec).unwrap(),
        ) {
            let enc = vk.to_encoded_point(false);
            let h = Keccak256::digest(&enc.as_bytes()[1..]);
            if h[12..] == expected {
                recovered = Some(rec);
                break;
            }
        }
    }
    println!("Pevm signature: {}{}", hex(&rs[..32]), hex(&rs[32..]));
    println!("  over digest : {}", hex(&digest32));
    println!("  wBDX signer : 0x{}", hex(&expected));
    match recovered {
        Some(rec) => {
            println!("  ecrecover   : VERIFIED (v={})", 27 + rec);
            // The 65 bytes a contract takes: the low-s form `rec` was found for (the raw s
            // above may be the high one, which recovers another key with this v) and v.
            println!("  eth signature: 0x{}{:02x}", hex(&k_sig.to_bytes()), 27 + rec);
        }
        None => {
            println!("  ecrecover   : FAILED");
            return Err("the aggregated signature did not ecrecover to the wBDX signer".into());
        }
    }
    Ok(())
}

#[cfg(all(feature = "live-dkg", not(feature = "live-pevm-dkg")))]
#[allow(clippy::too_many_arguments)]
fn sign_pevm(
    _committee: &beldex_bridge_signer::committee::CommitteeView,
    _self_index: u16,
    _signers: &[u16],
    _dir: &str,
    _identity: &beldex_bridge_signer::dkg_driver::live::MeshIdentity,
    _peers: &[beldex_bridge_signer::dkg_driver::live::PeerTransportAddr],
    _use_curve: bool,
    _timeout: std::time::Duration,
) -> Result<(), String> {
    Err("the Pevm sign leg needs a build with --features live-pevm-dkg".into())
}

/// Parse an even-length hex string to bytes (for `BRIDGE_SIGNER_SIGN_PREIMAGE`).
#[cfg(feature = "live-pevm-dkg")]
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(not(feature = "live-dkg"))]
fn run_sign(_cfg: &Config) -> Result<(), String> {
    Err("the `sign` subcommand requires a build with `--features live-dkg`".into())
}

/// `watch-evm` subcommand: build one EVM watcher per chain from
/// `BRIDGE_SIGNER_EVM_CHAINS` and poll for finalized wBDX burns (E.2). Prints each
/// finalized `ReleaseEvent` and its canonical id (what members agree on). Only built
/// with `--features evm-watcher-http`.
/// `protect-shares [dir]` (default `BRIDGE_SIGNER_SHARE_DIR`): bring a share directory to
/// the current at-rest form under the configured share key — seal plaintext shares,
/// re-seal older sealed ones with their file name bound, and make public group-key files
/// readable. Run it once on every node whose shares predate this.
#[cfg(feature = "live-dkg")]
fn run_protect_shares(dir: Option<String>) -> Result<(), String> {
    use beldex_bridge_signer::share_file;
    let dir = dir
        .or_else(|| std::env::var("BRIDGE_SIGNER_SHARE_DIR").ok())
        .ok_or("usage: protect-shares <share dir> (or set BRIDGE_SIGNER_SHARE_DIR)")?;
    let dir = std::path::Path::new(&dir);
    let key = share_file::configured_key(Some(dir))?.ok_or(
        "no share key configured: set BRIDGE_SIGNER_SHARE_KEY_FILE (see `new-share-key`)",
    )?;
    let r = share_file::protect_dir(dir, &key)?;
    println!("{}:", dir.display());
    println!("  sealed from plaintext : {:?}", r.sealed);
    println!("  re-sealed (name bound): {:?}", r.upgraded);
    println!("  already current       : {:?}", r.current);
    println!("  public files unsealed : {:?}", r.unsealed_public);
    if !r.sealed.is_empty() {
        println!(
            "  NOTE: copies of these shares made before now (backups, snapshots) still hold \
             them in plaintext. Treat those as exposed: delete them, and rotate the keys if a \
             copy may have left your control."
        );
    }
    Ok(())
}

/// `new-share-key <path>`: create a fresh random share key file, owner-only, refusing to
/// overwrite one (losing a key loses the shares sealed under it).
#[cfg(feature = "live-dkg")]
fn run_new_share_key(path: Option<String>) -> Result<(), String> {
    use std::io::Write;
    let path = path.ok_or("usage: new-share-key <path> (keep it outside the share directory)")?;
    let mut key = [0u8; 32];
    beldex_bridge_signer::ffi::random_bytes(&mut key).map_err(|e| e.to_string())?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).map_err(|e| format!("create {path}: {e} (an existing key is never overwritten)"))?;
    f.write_all(format!("{}\n", hex(&key)).as_bytes()).map_err(|e| format!("write {path}: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync {path}: {e}"))?;
    println!("share key written to {path}. Back it up separately from the shares: without it they cannot be opened.");
    Ok(())
}

#[cfg(not(feature = "live-dkg"))]
fn run_protect_shares(_dir: Option<String>) -> Result<(), String> {
    Err("`protect-shares` requires a build with `--features live-dkg`".into())
}

#[cfg(not(feature = "live-dkg"))]
fn run_new_share_key(_path: Option<String>) -> Result<(), String> {
    Err("`new-share-key` requires a build with `--features live-dkg`".into())
}

/// Build a chain's watcher the way every live path needs it: holding the endpoint to the
/// finality it has reported before (`BRIDGE_SIGNER_EVM_FINALITY_DIR`, default
/// `evm-finality`), and refusing at startup an endpoint that cannot say what is final.
/// A chain configured `depth_only_finality` skips that check and says so loudly.
#[cfg(feature = "evm-watcher-http")]
fn live_evm_watcher(
    c: &beldex_bridge_signer::evm_watcher::EvmChainConfig,
) -> Result<beldex_bridge_signer::evm_watcher::EvmWatcher<beldex_bridge_signer::evm_watcher::HttpJsonRpc>, String> {
    let dir = std::env::var("BRIDGE_SIGNER_EVM_FINALITY_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "evm-finality".to_string());
    let w = c.build_watcher().with_finality_record(std::path::Path::new(&dir))?;
    if w.is_depth_only() {
        println!(
            "  WARNING: chain {} settles burns on {} confirmations alone (depth_only_finality). \
             A deeper reorg reverses a burn after its BDX was released. Test networks only.",
            c.chain_id, c.confirmations
        );
    } else {
        w.check_finality_source()?;
    }
    if let Some(why) = w.halted() {
        eprintln!(
            "!! chain {} is HALTED after a finality violation: {why}\n   Nothing on it will be \
             released. Investigate the endpoint, then remove {dir}/{}.halted to resume.",
            c.chain_id, c.chain_id
        );
    }
    Ok(w)
}

#[cfg(feature = "evm-watcher-http")]
fn run_watch_evm(_cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::evm_watcher::{build_registry, parse_evm_chains};
    use std::time::Duration;

    let chains_json = std::env::var("BRIDGE_SIGNER_EVM_CHAINS").map_err(|_| {
        "set BRIDGE_SIGNER_EVM_CHAINS — a JSON array of \
         {chain_id, contract, confirmations, rpc, per_tx_max, per_epoch_cap, start_block}"
            .to_string()
    })?;
    let configs = parse_evm_chains(&chains_json)?;
    if configs.is_empty() {
        return Err("BRIDGE_SIGNER_EVM_CHAINS is empty — no chains to watch".into());
    }
    // Build the E.3 registry (validates uniqueness) even though the loop below only
    // needs the watchers — it is the config's single source of truth.
    let _registry = build_registry(&configs)?;

    // The L1 genesis binds every release canonical id (S6/S14, no cross-net replay).
    let genesis: [u8; 32] = match std::env::var("BRIDGE_SIGNER_GENESIS_HASH") {
        Ok(h) => config::parse_hex32(&h).ok_or("BRIDGE_SIGNER_GENESIS_HASH must be 32-byte hex")?,
        Err(_) => {
            println!("WARNING: no BRIDGE_SIGNER_GENESIS_HASH — using zeros for release canonical ids");
            [0u8; 32]
        }
    };
    let poll_secs: u64 = std::env::var("BRIDGE_SIGNER_WATCH_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    // Bound the loop for a scripted run; unset = run until interrupted.
    let max_iters: Option<u64> = std::env::var("BRIDGE_SIGNER_WATCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok());

    let mut watchers: Vec<_> =
        configs.iter().map(|c| live_evm_watcher(c).map(|w| (c.chain_id, w))).collect::<Result<_, _>>()?;
    println!(
        "watching {} EVM chain(s), polling every {poll_secs}s: {:?}",
        watchers.len(),
        configs.iter().map(|c| c.chain_id).collect::<Vec<_>>()
    );

    let mut iter = 0u64;
    loop {
        for (chain_id, w) in watchers.iter_mut() {
            match w.advance() {
                Ok(update) => {
                    for ev in &update.finalized {
                        let cid = ev.canonical_id(genesis);
                        println!(
                            "chain {chain_id}: RELEASE finalized — amount={} recipient=0x{} evm_txid=0x{} canonical_id=0x{}",
                            ev.amount,
                            hex(&ev.beldex_recipient),
                            hex(&ev.evm_txid),
                            hex(&cid),
                        );
                    }
                    for d in &update.dropped {
                        println!("chain {chain_id}: burn dropped (reorg) at height {}", d.inclusion_height);
                    }
                }
                Err(e) => eprintln!("chain {chain_id}: advance error: {e:?}"),
            }
        }
        iter += 1;
        if max_iters.is_some_and(|m| iter >= m) {
            break;
        }
        std::thread::sleep(Duration::from_secs(poll_secs));
    }
    Ok(())
}

#[cfg(not(feature = "evm-watcher-http"))]
fn run_watch_evm(_cfg: &Config) -> Result<(), String> {
    Err("the `watch-evm` subcommand requires a build with `--features evm-watcher-http`".into())
}

/// `serve` subcommand: the **autonomous watcher pipeline** (Phase L). Builds the Beldex
/// deposit watcher + one EVM burn watcher per chain, then runs the orchestrator loop
/// ([`service::serve`]) — each tick ingests finalized deposits/burns, deduplicates them into
/// duties, and (with the **dry-run** `LoggingBackend`) reports each detected duty. This
/// exercises the full autonomy pipeline (observe → resolve → dedup → duty) end to end; the
/// live signing+submission backend swaps in for `LoggingBackend`. Needs `--features autonomy`.
#[cfg(feature = "autonomy")]
fn run_serve(cfg: &Config) -> Result<(), String> {
    use beldex_bridge_signer::beldex_watcher::{BeldexWatcher, HttpBeldexRpc};
    use beldex_bridge_signer::evm_watcher::{build_registry, parse_evm_chains};
    use beldex_bridge_signer::orchestrator::{Duty, Orchestrator};
    use beldex_bridge_signer::service::{serve, LoggingBackend, ServeOptions, WatcherEventSource};
    use std::time::Duration;

    // EVM chains (burns → releases).
    let chains_json = std::env::var("BRIDGE_SIGNER_EVM_CHAINS")
        .map_err(|_| "set BRIDGE_SIGNER_EVM_CHAINS (a JSON array of chain configs; see watch-evm)".to_string())?;
    let configs = parse_evm_chains(&chains_json)?;
    if configs.is_empty() {
        return Err("BRIDGE_SIGNER_EVM_CHAINS is empty — no chains to watch".into());
    }
    let registry = build_registry(&configs)?;
    let evm: Vec<_> = configs.iter().map(live_evm_watcher).collect::<Result<_, _>>()?;

    // Beldex gateway deposits (→ mints).
    let beldexd_rpc =
        std::env::var("BRIDGE_SIGNER_BELDEXD_RPC").unwrap_or_else(|_| cfg.beldexd_rpc_url.clone());
    let gateway_id = std::env::var("BRIDGE_SIGNER_GATEWAY_ID")
        .map_err(|_| "set BRIDGE_SIGNER_GATEWAY_ID (the bridge gateway to watch for deposits)".to_string())?;
    let start_height: u64 = std::env::var("BRIDGE_SIGNER_BELDEX_START_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let view_secret = config::parse_hex32(
        &std::env::var("BRIDGE_SIGNER_GATEWAY_VIEW_SECRET").map_err(|_| {
            "set BRIDGE_SIGNER_GATEWAY_VIEW_SECRET (32-byte hex; the gateway view secret that decrypts A.5 memos)"
                .to_string()
        })?,
    )
    .ok_or("BRIDGE_SIGNER_GATEWAY_VIEW_SECRET must be 32-byte hex")?;
    // Echo the watcher config: a wrong gateway id / RPC / start height otherwise reads as
    // an eternally quiet, "healthy" pipeline (the watcher successfully finds nothing).
    println!("  beldex watcher: gateway {gateway_id} via {beldexd_rpc}, from height {start_height}");

    // Cloned before the watcher consumes them — the live backend reuses both.
    let beldexd_rpc_for_live = beldexd_rpc.clone();
    let gateway_id_for_live = gateway_id.clone();
    // Finality posture. Strict by default: a deposit is only actionable at or below
    // `get_info.immutable_height`. beldexd omits that field entirely on a chain that has
    // never checkpointed — and it never will below CHECKPOINT_QUORUM_SIZE (20) active
    // masternodes, so every local devnet is in that bucket: deposits confirm and no mint
    // duty is ever created, silently, because a poll error is treated as transient.
    // Setting this to N falls back to `top_height - N` in exactly that case; a daemon that
    // does report a checkpoint ignores it outright.
    // An empty value counts as unset (strict), so a launcher can pass the variable
    // through unconditionally — `FOO=${X:+...}` does not work as an assignment prefix,
    // because a word produced by expansion is parsed as the command name, not a prefix.
    let beldex_confirmations: Option<u64> = match std::env::var("BRIDGE_SIGNER_BELDEX_CONFIRMATIONS") {
        Ok(s) if s.trim().is_empty() => None,
        Ok(s) => Some(s.trim().parse::<u64>().map_err(|_| {
            "BRIDGE_SIGNER_BELDEX_CONFIRMATIONS must be a non-negative integer".to_string()
        })?),
        Err(_) => None,
    };
    let mut beldex = BeldexWatcher::new(HttpBeldexRpc::new(beldexd_rpc), gateway_id, start_height);
    if let Some(n) = beldex_confirmations {
        println!("  beldex finality: RELAXED — a chain with no checkpoint falls back to top_height - {n}");
        beldex = beldex.with_fallback_confirmations(n);
    }

    let mut src = WatcherEventSource { beldex, evm, view_secret, registry };
    let mut orch = Orchestrator::new();

    let poll_secs: u64 = std::env::var("BRIDGE_SIGNER_WATCH_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let max_ticks: Option<u64> = std::env::var("BRIDGE_SIGNER_WATCH_ITERS").ok().and_then(|s| s.parse().ok());
    let opts = ServeOptions { interval: Duration::from_secs(poll_secs), max_ticks };

    // Live backend path (build with `--features serve-live`, enable with BRIDGE_SIGNER_SERVE_LIVE=1):
    // signs each duty over the mesh, emits mint payloads, self-submits releases.
    #[cfg(feature = "serve-live")]
    if std::env::var("BRIDGE_SIGNER_SERVE_LIVE").map(|v| v == "1" || v == "true").unwrap_or(false) {
        return run_serve_live(
            cfg,
            &mut src,
            &mut orch,
            &opts,
            &configs,
            &beldexd_rpc_for_live,
            &gateway_id_for_live,
            poll_secs,
        );
    }
    let _ = (&beldexd_rpc_for_live, &gateway_id_for_live); // consumed only by the live path

    println!(
        "serve: autonomous watcher pipeline — DRY-RUN backend (detects + dedups duties, does NOT sign/submit)"
    );
    println!("  polling every {poll_secs}s across {} EVM chain(s)", configs.len());

    let mut backend = LoggingBackend::new(|d: &Duty| match d {
        Duty::Takeover(c) => println!(
            "CANCEL duty: chain={} takeover={} key_epoch={}",
            c.chain_id, c.takeover_id, c.key_epoch
        ),
        Duty::Mint(e) => println!(
            "MINT duty: beldex_txid=0x{} chain={} to=0x{} amount={}",
            hex(&e.beldex_txid),
            e.dst_chain.0,
            hex(&e.to),
            e.amount
        ),
        Duty::Release(e) => println!(
            "RELEASE duty: evm_txid=0x{} chain={} amount={} recipient=0x{}",
            hex(&e.evm_txid),
            e.chain.0,
            e.amount,
            hex(&e.beldex_recipient)
        ),
        Duty::Rotate(r) => println!(
            "ROTATE duty: chain={} key epoch {} -> 0x{}",
            r.chain_id,
            r.new_key_epoch,
            hex(&r.new_signer)
        ),
        Duty::Handover(h) => println!(
            "HANDOVER duty: gateway 0x{} -> owner {} (key epoch {})",
            hex(&h.gateway_id),
            hex(&h.new_owner),
            h.key_epoch
        ),
    });

    let reports = serve(&mut orch, &mut src, &mut backend, &opts, || false);
    let (pending, in_flight, done) = orch.counts();
    println!(
        "serve: finished after {} tick(s); duties pending={pending} in_flight={in_flight} done={done}",
        reports.len()
    );
    Ok(())
}

#[cfg(not(feature = "autonomy"))]
fn run_serve(_cfg: &Config) -> Result<(), String> {
    Err("the `serve` subcommand requires a build with `--features autonomy`".into())
}

/// `relay-watch` — subscribe to the daemon's mint bus and hand each payload to a broadcaster.
///
/// This is what a **relayer operator** runs. It needs no bridge key, no share material, no
/// signer-host access — only an OMQ endpoint it can reach — which is the whole point of
/// Phase I: relaying is permissionless and carries no authority. Each payload is piped to
/// `BRIDGE_SIGNER_RELAY_CMD` (default `beldex-bridge-relayer relay -`), whose own environment
/// holds the gas key.
///
/// Failures are logged and skipped, never retried in a tight loop: a payload that fails to
/// broadcast is still valid forever, another subscriber may carry it, and the wBDX contract
/// rejects a duplicate anyway.
#[cfg(feature = "omq-client")]
fn run_relay_watch_standalone() -> Result<(), String> {
    use beldex_bridge_signer::omq_client::OmqMintSubscriber;
    use std::time::Duration;

    // Comma-separated list: subscribe to EVERY endpoint given. Signers publish to their own
    // daemons by default, so a relayer that watches several daemons is robust to any one
    // signer being a straggler (its daemon then simply carries no publish that round);
    // duplicates across daemons are deduped below by txid.
    let endpoints = std::env::var("BRIDGE_SIGNER_OXENMQ_ENDPOINT").map_err(|_| {
        "set BRIDGE_SIGNER_OXENMQ_ENDPOINT (one or more comma-separated beldexd OMQ sockets \
         to subscribe to, e.g. ipc://<node>/devnet/beldexd.sock) — this is the only required \
         setting"
            .to_string()
    })?;
    let cmd = std::env::var("BRIDGE_SIGNER_RELAY_CMD")
        .unwrap_or_else(|_| "beldex-bridge-relayer relay -".to_string());
    let mut subs: Vec<OmqMintSubscriber> = endpoints
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|e| {
            println!("relay-watch: subscribing to {e}");
            OmqMintSubscriber::new(e.to_string())
        })
        .collect();
    if subs.is_empty() {
        return Err("BRIDGE_SIGNER_OXENMQ_ENDPOINT contained no endpoints".into());
    }
    println!("  each mint payload → `{cmd}`");
    println!("  (this process holds NO bridge key; the gas key lives in the relay command)");
    let mut count = 0u64;
    // Process-local dedup by (beldex_txid, output_index): the daemon replays its retained
    // backlog to a new subscriber (so an outage is caught up), and reconnections can
    // re-deliver — skip what this process already handled instead of re-running gas
    // estimation on it. The contract's replay guard remains the real idempotency authority.
    //
    // The output index is part of the key because one Beldex transaction can pay several
    // gateway outputs, each its own mint. Keying on the txid alone would drop every output
    // after the first for the life of this process.
    //
    // Only a payload that RELAYED is marked handled. One whose relay failed must stay
    // eligible: the signers re-deliver unminted payloads and the daemon re-fans them, and
    // that re-delivery is this process's only chance to try again.
    let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();
    // A key hand-off's two calls are sent once each, and the second only after the challenge
    // window: an `activate` arrives right after the new committee's DKG, long before the
    // contract will take it. One that could not be relayed yet is kept and tried again here
    // until it lands (or the relayer reports its key epoch already live), not left to a
    // re-delivery that may never come.
    let mut held: std::collections::BTreeMap<String, (String, std::time::Instant)> = Default::default();
    let mut retried_at = std::time::Instant::now();
    const HOLD_RETRY: Duration = Duration::from_secs(30);
    const HOLD_FOR: Duration = Duration::from_secs(2 * 24 * 3600);
    let per_sub_timeout = Duration::from_millis(5000 / subs.len().max(1) as u64);
    loop {
        if retried_at.elapsed() >= HOLD_RETRY && !held.is_empty() {
            retried_at = std::time::Instant::now();
            held.retain(|key, (payload, since)| {
                if since.elapsed() >= HOLD_FOR {
                    eprintln!("     {key}: still not relayed after two days — dropped");
                    return false;
                }
                match pipe_to_relay(&cmd, payload) {
                    Ok(out) => {
                        println!("     {key} relayed: {}", out.trim());
                        handled.insert(key.clone());
                        false
                    }
                    Err(_) => true,
                }
            });
        }
        for sub in subs.iter_mut() {
            match sub.poll(per_sub_timeout) {
                Ok(Some(payload)) => {
                    let field = |name: &str, quoted: bool| {
                        let pat = if quoted { format!(r#""{name}":""#) } else { format!(r#""{name}":"#) };
                        payload.split(&pat).nth(1).map(|s| {
                            let end = if quoted { '"' } else { ',' };
                            s.split(end).next().unwrap_or("").trim_end_matches('}').to_string()
                        })
                    };
                    let kind = field("kind", true).unwrap_or_default();
                    // The gateway hand-over's signature, a completed ack and an absence signature
                    // are for Beldex, not EVM calls.
                    if kind == "handover" || kind == "ack" || kind == "absence" {
                        continue;
                    }
                    let chain = field("chain_id", false).unwrap_or_default();
                    let (key, hand_off) = match kind.as_str() {
                        // The signer is part of the name: a payload for the same epoch but
                        // another key (a stale one, or a forgery) must not shadow the real one.
                        "rotate" => (
                            format!(
                                "rotate:{chain}:{}:{}",
                                field("new_key_epoch", false).unwrap_or_default(),
                                field("new_signer", true).unwrap_or_default()
                            ),
                            true,
                        ),
                        "activate" => (
                            format!(
                                "activate:{chain}:{}:{}",
                                field("pending_key_epoch", false).unwrap_or_default(),
                                field("pending_signer", true).unwrap_or_default()
                            ),
                            true,
                        ),
                        // A standby naming or takeover step: named by its signature, which is
                        // single-use on chain. Relayed once; the signers sign it again if it is
                        // still wanted, so a refused one is not held.
                        "set_standby" | "takeover_begin" | "takeover_complete" | "takeover_cancel" => (
                            format!("{kind}:{chain}:{}", field("sig", true).unwrap_or_default()),
                            false,
                        ),
                        _ => {
                            let txid = field("beldex_txid", true).unwrap_or_default();
                            let idx = field("output_index", false).unwrap_or_else(|| "0".into());
                            (if txid.is_empty() { String::new() } else { format!("{txid}:{idx}") }, false)
                        }
                    };
                    if !key.is_empty() && (handled.contains(&key) || held.contains_key(&key)) {
                        println!("(skip: {key} already relayed or held this session)");
                        continue;
                    }
                    count += 1;
                    println!("[{count}] {} payload received: {payload}", if kind.is_empty() { "mint" } else { &kind });
                    match pipe_to_relay(&cmd, &payload) {
                        Ok(out) => {
                            println!("     relayed: {}", out.trim());
                            if !key.is_empty() {
                                handled.insert(key);
                            }
                        }
                        Err(e) if hand_off => {
                            eprintln!("     not relayed yet ({e}) — held, retried every {}s", HOLD_RETRY.as_secs());
                            held.insert(key, (payload, std::time::Instant::now()));
                        }
                        Err(e) => eprintln!(
                            "     RELAY FAILED ({e}) — will try again when it is re-delivered"
                        ),
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("relay-watch: {e}; will retry that endpoint");
                }
            }
        }
    }
}

/// `handover-submit`: the gateway hand-over's submitter, run beside the relayer by whoever pays
/// the Beldex fees, with the hand-over wallet (`BRIDGE_SIGNER_HANDOVER_WALLET_RPC`, a wallet RPC
/// kept for nothing else: spending the outputs a built hand-over uses voids it).
///
///   1. Builds: the outgoing committee's leader asks `GET /build?owner=<Pgw>`, and gets the
///      unsigned descriptor update moving the reserve gateway to that owner. Only for a `Pgw`
///      whose key certificate this process checked itself (activations on the bus), and once
///      per owner: the build is kept and the same one is handed to every asker.
///   2. Collects: the committee's `handover` signature from the bus, kept only if it verifies
///      against the gateway's CURRENT owner key.
///   3. Sends: once every chain's wBDX signer is that certificate's key — never before, or the
///      gateway would follow a rotation that has not happened — then confirms the owner moved.
///
/// Rotation acknowledgements are not paid here: each member pays for its own, from its own
/// fee wallet (`serve`, `BRIDGE_SIGNER_ACK_WALLET_RPC`).
///
/// Every step is kept in `BRIDGE_SIGNER_HANDOVER_DIR` (default `handovers`), one file per
/// owner: with that directory and the wallet's seed, another machine can carry on (A41).
#[cfg(feature = "serve-live")]
fn run_handover_submit() -> Result<(), String> {
    use beldex_bridge_signer::dkg_driver::KeyCertificate;
    use beldex_bridge_signer::evm_watcher::{parse_evm_chains, HttpJsonRpc, JsonRpcClient};
    use beldex_bridge_signer::omq_client::{OmqCommitteeClient, OmqMintSubscriber};
    use std::time::{Duration, Instant};

    let need = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty()).ok_or(format!("set {k}"));
    // Every bus daemon to listen to, comma-separated; the first one also answers committees.
    let buses = bus_endpoints(&need("BRIDGE_SIGNER_OXENMQ_ENDPOINT")?);
    let bus = buses.first().cloned().ok_or("BRIDGE_SIGNER_OXENMQ_ENDPOINT lists no endpoint")?;
    let daemon = HttpJsonRpc::new(format!("{}/json_rpc", need("BRIDGE_SIGNER_BELDEXD_RPC_URL")?.trim_end_matches('/')));
    // Each wallet RPC is logged in to with the `user:password` in its own owner-only file
    // (rpc_login): without one, anything that can reach its port can spend from it.
    let login_for = |url: String, file_var: &str| -> Result<HttpJsonRpc, String> {
        match std::env::var(file_var).ok().filter(|v| !v.trim().is_empty()) {
            Some(p) => {
                let login = beldex_bridge_signer::rpc_login::read_login_file(std::path::Path::new(p.trim()))?;
                Ok(HttpJsonRpc::new(url).with_basic_auth(&login))
            }
            None => {
                println!("  WARNING: {url} is used without a login ({file_var} not set)");
                Ok(HttpJsonRpc::new(url))
            }
        }
    };
    let wallet = login_for(need("BRIDGE_SIGNER_HANDOVER_WALLET_RPC")?, "BRIDGE_SIGNER_HANDOVER_WALLET_LOGIN_FILE")?;
    let gateway = need("BRIDGE_SIGNER_RELEASE_GATEWAY")?.to_ascii_lowercase();
    let chains = parse_evm_chains(&need("BRIDGE_SIGNER_EVM_CHAINS")?)?;
    let listen = std::env::var("BRIDGE_SIGNER_HANDOVER_LISTEN").unwrap_or_else(|_| "127.0.0.1:18090".into());
    let dir = std::path::PathBuf::from(std::env::var("BRIDGE_SIGNER_HANDOVER_DIR").unwrap_or_else(|_| "handovers".into()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let server = tiny_http::Server::http(&listen).map_err(|e| format!("listen {listen}: {e}"))?;
    let committees = OmqCommitteeClient::new(bus);
    let mut subs: Vec<OmqMintSubscriber> = buses.into_iter().map(OmqMintSubscriber::new).collect();
    println!("handover-submit: gateway {gateway}, builds on http://{listen}/build?owner=<Pgw>, records in {}", dir.display());

    // One record per new owner, as JSON: what was built, the signature once collected, and
    // the transaction once sent.
    let file = |owner: &str| dir.join(format!("{owner}.json"));
    let load = |owner: &str| -> Option<serde_json::Value> { serde_json::from_str(&std::fs::read_to_string(file(owner)).ok()?).ok() };
    let save = |owner: &str, rec: &serde_json::Value| -> Result<(), String> {
        let tmp = file(&format!("{owner}.tmp"));
        std::fs::write(&tmp, rec.to_string()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, file(owner)).map_err(|e| format!("{}: {e}", file(owner).display()))
    };
    let owner_now = || -> Option<String> {
        let info = daemon.call("get_gateway_info", serde_json::json!({ "gateway_address": gateway })).ok()?;
        Some(info.get("owner_key")?.as_str()?.to_ascii_lowercase())
    };
    // A Pgw this process checked: its certificate's epoch and wBDX signer address.
    let mut verified: std::collections::BTreeMap<String, (u64, String)> = Default::default();
    let mut swept = Instant::now();
    let status = StatusBoard::start("handover-submit");
    // Below this many atomic units a wallet is reported low (unset: not checked).
    let wallet_low: Option<u64> = std::env::var("BRIDGE_SIGNER_WALLET_LOW").ok().and_then(|v| v.trim().parse().ok());

    loop {
        status.beat(Duration::from_secs(120));
        // 1. Builds.
        if let Ok(Some(req)) = server.recv_timeout(Duration::from_millis(200)) {
            let owner = req.url().split_once("owner=").map(|(_, o)| o.split('&').next().unwrap_or("").to_ascii_lowercase());
            let answer = match owner {
                Some(o) if o.len() == 64 && o.bytes().all(|b| b.is_ascii_hexdigit()) => match (load(&o), verified.get(&o)) {
                    (Some(rec), _) => Ok(rec),
                    (None, Some((epoch, signer))) => wallet
                        .call(
                            "gateway_update_descriptor",
                            serde_json::json!({ "gateway_id": gateway, "owner_key_type": "eddsa", "owner_key": o,
                                                "bridge_reserve": true, "meta_info": "bridge reserve", "priority": 1 }),
                        )
                        .map_err(|e| format!("wallet: {e:?}"))
                        .and_then(|b| {
                            let rec = serde_json::json!({
                                "owner": o, "key_epoch": epoch, "signer": signer,
                                "tx_blob": b.get("tx_blob"), "tx_metadata": b.get("tx_metadata"),
                                "hash_to_sign": b.get("hash_to_sign"), "fee": b.get("fee"),
                            });
                            save(&o, &rec)?;
                            println!("built the hand-over to {o} (key epoch {epoch}), hash {}", rec["hash_to_sign"]);
                            Ok(rec)
                        }),
                    (None, None) => Err(format!("no checked key certificate names {o}")),
                },
                _ => Err("ask for /build?owner=<64 hex Pgw>".into()),
            };
            let reply = match answer {
                Ok(rec) => tiny_http::Response::from_string(
                    serde_json::json!({ "tx_blob": rec["tx_blob"], "hash_to_sign": rec["hash_to_sign"] }).to_string(),
                ),
                Err(e) => tiny_http::Response::from_string(serde_json::json!({ "error": e }).to_string()).with_status_code(404),
            };
            let _ = req.respond(reply);
        }

        // 2. The bus: certificates to build for, and the committee's signatures.
        let mut arrived = Vec::new();
        for sub in subs.iter_mut() {
            while let Ok(Some(p)) = sub.poll(Duration::from_millis(20)) {
                arrived.push(p);
            }
        }
        for p in arrived {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&p) else { continue };
            let text = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_ascii_lowercase();
            match v.get("kind").and_then(|k| k.as_str()) {
                Some("activate") => {
                    let Ok(cert) = KeyCertificate::from_text(v.get("keycert").and_then(|x| x.as_str()).unwrap_or_default()) else { continue };
                    let owner = hex(&cert.pgw);
                    if verified.contains_key(&owner) {
                        continue;
                    }
                    match committees.fetch_committee(Some(cert.height)).map_err(|e| e.to_string()).and_then(|c| {
                        cert.verify(&c, &beldex_bridge_signer::wire_auth::LibsodiumEd25519)
                    }) {
                        Ok(()) => {
                            // Built only for a key consensus counts as attested, as the committee checks.
                            let pevm = k256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.pevm)
                                .map(|k| beldex_bridge_signer::aggregate_signature::eth_address(&k));
                            match pevm.map_err(|e| e.to_string()).and_then(|a| attested_epoch_of(&daemon, &cert.pgw, &a)) {
                                Ok(Some(e)) if e == cert.epoch => {
                                    println!("checked the epoch {} key certificate and attestation: Pgw {owner}", cert.epoch);
                                    verified.insert(owner, (cert.epoch, text("pending_signer")));
                                }
                                Ok(_) => eprintln!("  the epoch {} key {owner} is not attested on chain yet", cert.epoch),
                                Err(e) => eprintln!("  the epoch {} key's attestation could not be read: {e}", cert.epoch),
                            }
                        }
                        Err(e) => eprintln!("  an activation's key certificate does not check out: {e}"),
                    }
                }
                Some("handover") if text("gateway_id") == gateway => {
                    let owner = text("owner");
                    let Some(mut rec) = load(&owner) else { continue };
                    if rec.get("sig").is_some() || rec["hash_to_sign"].as_str().map(str::to_ascii_lowercase) != Some(text("hash_to_sign")) {
                        continue;
                    }
                    let unhex = |h: &str| (0..h.len()).step_by(2).map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect::<Option<Vec<u8>>>();
                    let (Some(sig), Some(hash), Some(cur)) = (unhex(&text("sig")), unhex(&text("hash_to_sign")), owner_now().and_then(|o| unhex(&o))) else { continue };
                    let (Ok(sig), Ok(cur)) = (<[u8; 64]>::try_from(sig), <[u8; 32]>::try_from(cur)) else { continue };
                    if beldex_bridge_signer::ffi::ed25519_verify_consensus(&sig, &hash, &cur) {
                        rec["sig"] = serde_json::json!(text("sig"));
                        if save(&owner, &rec).is_ok() {
                            println!("the outgoing committee signed the hand-over to {owner}; sent once the wBDX key has moved");
                        }
                    } else {
                        eprintln!("  a hand-over signature for {owner} does not verify against the gateway's owner key");
                    }
                }
                _ => {}
            }
        }

        // 3. Send what is signed, once the wBDX key has moved everywhere; confirm what was sent.
        if swept.elapsed() < Duration::from_secs(10) {
            continue;
        }
        swept = Instant::now();
        // What this submitter holds, for monitoring: checked keys, hand-overs by state, and its
        // wallet's balance.
        {
            let mut state: std::collections::BTreeMap<String, String> = Default::default();
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for path in entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")) {
                    let Some(owner) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else { continue };
                    let Some(rec) = load(&owner) else { continue };
                    let st = if rec.get("done").is_some() {
                        "done"
                    } else if rec.get("tx_hash").is_some() {
                        "sent, waiting for the owner to change"
                    } else if rec.get("sig").is_some() {
                        "signed, sent once the wBDX key has moved"
                    } else {
                        "built, waiting for the committee's signature"
                    };
                    state.insert(owner, st.to_string());
                }
            }
            status.set("checked_keys", verified.len());
            status.set("handovers", serde_json::json!(state));
            // Low is judged on the whole balance: right after paying, the change is locked for a
            // few blocks and the unlocked part reads 0 although nothing is short.
            let balance = |name: &str, w: &HttpJsonRpc| {
                let b = w.call("get_balance", serde_json::json!({ "account_index": 0 })).ok();
                let field = |k: &str| b.as_ref().and_then(|b| b.get(k).and_then(|x| x.as_u64()));
                let (total, unlocked) = (field("balance"), field("unlocked_balance"));
                status.set(&format!("{name}_balance"), total.map_or(serde_json::Value::Null, |u| u.into()));
                status.set(&format!("{name}_unlocked"), unlocked.map_or(serde_json::Value::Null, |u| u.into()));
                status.problem(
                    &format!("{name}_low"),
                    match (total, wallet_low) {
                        (Some(t), Some(low)) if t < low => Some(format!("{t} atomic units, below {low}")),
                        (None, _) => Some("balance unreadable".into()),
                        _ => None,
                    },
                );
            };
            balance("handover_wallet", &wallet);
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for path in entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")) {
            let Some(owner) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else { continue };
            let Some(mut rec) = load(&owner) else { continue };
            if rec.get("done").is_some() || rec.get("sig").is_none() {
                continue;
            }
            if rec.get("tx_hash").is_some() {
                if owner_now().as_deref() == Some(owner.as_str()) {
                    rec["done"] = serde_json::json!(true);
                    let _ = save(&owner, &rec);
                    println!("hand-over done: the gateway's owner is now {owner}");
                }
                continue;
            }
            let signer = rec["signer"].as_str().unwrap_or_default().to_ascii_lowercase();
            let moved = chains.iter().all(|c| {
                HttpJsonRpc::new(c.rpc_url.clone())
                    .call("eth_call", serde_json::json!([{ "to": format!("0x{}", hex(&c.contract)), "data": "0x4cd615e7" }, "latest"]))
                    .ok()
                    .and_then(|w| w.as_str().and_then(|w| w.get(26..)).map(str::to_ascii_lowercase))
                    .is_some_and(|live| !signer.is_empty() && live == signer)
            });
            if !moved {
                continue;
            }
            match wallet.call(
                "gateway_submit_descriptor_update",
                serde_json::json!({ "tx_metadata": rec["tx_metadata"], "signature": rec["sig"], "signature_type": "eddsa" }),
            ) {
                Ok(r) => {
                    rec["tx_hash"] = r.get("tx_hash").cloned().unwrap_or_default();
                    let _ = save(&owner, &rec);
                    println!("sent the hand-over to {owner}: tx {}", rec["tx_hash"]);
                }
                Err(e) => eprintln!("  sending the hand-over to {owner} failed (tried again): {e:?}"),
            }
        }
    }
}

#[cfg(not(feature = "serve-live"))]
fn run_handover_submit() -> Result<(), String> {
    Err("the `handover-submit` subcommand requires a build with `--features serve-live`".into())
}

#[cfg(not(feature = "omq-client"))]
fn run_relay_watch_standalone() -> Result<(), String> {
    Err("the `relay-watch` subcommand requires a build with `--features omq-client`".into())
}

/// Run `cmd` (via the shell, so it can carry arguments/pipes) and write `payload` to its
/// stdin — the mint hand-off from the keyless signer to a gas-paying relayer. Returns the
/// command's stdout on success. Best-effort by design: see the call site.
/// (`serve-live` implies `live-dkg` implies `omq-client`, so this one gate covers both the
/// `serve --live` hand-off and the standalone `relay-watch`.)
#[cfg(feature = "omq-client")]
fn pipe_to_relay(cmd: &str, payload: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn `{cmd}`: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("no stdin on the relay command")?
        .write_all(payload.as_bytes())
        .map_err(|e| format!("write to relay stdin: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("wait for relay: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "exit {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// An `activate` payload off the bus, as a hand-off this committee may sign. Each member
/// checks it itself; nothing on the bus is trusted:
///   * it is for a wBDX this node serves;
///   * its key certificate is the selected committee's: fetched from this node's own daemon
///     at the certificate's height, every member's signature checks out, and that committee
///     is newer than `own_epoch`, the one holding this node's key;
///   * the payload's new signer is that certificate's key, and the activation recovers to it;
///   * consensus counts that key as attested by that committee (key_attestation).
/// Returns the rotation, and the certificate's `Pgw` and epoch for the gateway hand-over.
/// `Ok(None)` for any other kind of payload.
#[cfg(feature = "serve-live")]
fn rotation_from_activation(
    payload: &str,
    own_epoch: u64,
    contracts: &std::collections::BTreeMap<u64, [u8; 20]>,
    committees: &beldex_bridge_signer::omq_client::OmqCommitteeClient,
    daemon: &beldex_bridge_signer::evm_watcher::HttpJsonRpc,
) -> Result<Option<(beldex_bridge_signer::orchestrator::RotationRequest, [u8; 32], u64)>, String> {
    use beldex_bridge_signer::aggregate_signature::{eth_address, pevm_signer};
    use beldex_bridge_signer::dkg_driver::KeyCertificate;
    let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| format!("not JSON: {e}"))?;
    if v.get("kind").and_then(|k| k.as_str()) != Some("activate") {
        return Ok(None);
    }
    let text = |f: &str| v.get(f).and_then(|x| x.as_str()).ok_or(format!("no {f}"));
    let bytes = |f: &str| -> Result<Vec<u8>, String> {
        let h = text(f)?;
        (0..h.len()).step_by(2).map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect::<Option<_>>().ok_or(format!("{f}: not hex"))
    };
    let chain_id = v.get("chain_id").and_then(|x| x.as_u64()).ok_or("no chain_id")?;
    let pending_key_epoch = v.get("pending_key_epoch").and_then(|x| x.as_u64()).ok_or("no pending_key_epoch")?;
    let contract: [u8; 20] = bytes("contract")?.try_into().map_err(|_| "contract: not 20 bytes")?;
    let new_signer: [u8; 20] = bytes("pending_signer")?.try_into().map_err(|_| "pending_signer: not 20 bytes")?;
    let sig = bytes("sig")?;
    if contracts.get(&chain_id) != Some(&contract) {
        return Err(format!("for a wBDX this node does not serve (chain {chain_id}, 0x{})", hex(&contract)));
    }
    let cert = KeyCertificate::from_text(text("keycert")?)?;
    if cert.epoch <= own_epoch {
        return Err(format!("its key is epoch {}'s, not newer than this committee's {own_epoch}", cert.epoch));
    }
    let committee = committees
        .fetch_committee(Some(cert.height))
        .map_err(|e| format!("bridge.committee at height {}: {e}", cert.height))?;
    cert.verify(&committee, &beldex_bridge_signer::wire_auth::LibsodiumEd25519).map_err(|e| format!("key certificate: {e}"))?;
    let cert_signer =
        eth_address(&k256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.pevm).map_err(|e| format!("certificate Pevm key: {e}"))?);
    if cert_signer != new_signer {
        return Err(format!("names 0x{} but its certificate's key is 0x{}", hex(&new_signer), hex(&cert_signer)));
    }
    // And on chain: consensus counts the key as that committee's (its members attested it), so
    // a hand-off only ever goes to a key every node can see, never to one only the bus vouches for.
    match attested_epoch_of(daemon, &cert.pgw, &cert_signer)? {
        Some(e) if e == cert.epoch => {}
        Some(e) => return Err(format!("its key is attested as epoch {e}'s, not epoch {}'s", cert.epoch)),
        None => return Err(format!("its key is not attested on chain yet (epoch {})", cert.epoch)),
    }
    let preimage = beldex_bridge_signer::release_policy::activate_preimage(chain_id, contract, pending_key_epoch, new_signer);
    if pevm_signer(&preimage, &sig) != Some(new_signer) {
        return Err("its signature does not recover to the new key".into());
    }
    let rotation =
        beldex_bridge_signer::orchestrator::RotationRequest { chain_id, contract, new_signer, new_key_epoch: pending_key_epoch };
    Ok(Some((rotation, cert.pgw, cert.epoch)))
}

/// A wBDX contract's rotation state, read from `client` at the latest block, the chain's
/// clock included (the deadline a member accepts is the chain's, not its own).
#[cfg(feature = "serve-live")]
fn read_rotation_state(
    client: &beldex_bridge_signer::evm_watcher::HttpJsonRpc,
    contract: &[u8; 20],
) -> Result<beldex_bridge_signer::release_policy::RotationState, String> {
    use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
    use beldex_bridge_signer::release_policy::RotationState;
    let to = format!("0x{}", hex(contract));
    let word = |selector: &str| -> Result<u64, String> {
        let raw = client
            .call("eth_call", serde_json::json!([{ "to": to, "data": selector }, "latest"]))
            .map_err(|e| format!("eth_call {selector}: {e:?}"))?;
        raw.as_str()
            .and_then(|w| w.strip_prefix("0x"))
            .filter(|w| w.len() == 64 && w[..48].bytes().all(|b| b == b'0'))
            .and_then(|w| u64::from_str_radix(&w[48..], 16).ok())
            .ok_or_else(|| format!("eth_call {selector}: {raw}"))
    };
    let block = client
        .call("eth_getBlockByNumber", serde_json::json!(["latest", false]))
        .map_err(|e| format!("latest block: {e:?}"))?;
    let now = block
        .get("timestamp")
        .and_then(|t| t.as_str())
        .and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok())
        .ok_or("latest block has no timestamp")?;
    Ok(RotationState {
        key_epoch: word("0x6fdf657e")?,          // keyEpoch()
        rotation_nonce: word("0x94603071")?,     // rotationNonce()
        pending_activate_at: word("0x0919b421")?, // pendingActivateAt()
        now,
    })
}

/// Which of a member's share trees holds the live key, read from the chain: the key that is
/// the wBDX signer on every configured chain AND owns the reserve gateway. Both legs, because
/// they move by separate transactions, and a key live on only one is not yet the one to serve.
#[cfg(feature = "serve-live")]
struct LiveKeyProbe {
    evm: Vec<(beldex_bridge_signer::evm_watcher::HttpJsonRpc, [u8; 20])>,
    daemon: beldex_bridge_signer::evm_watcher::HttpJsonRpc,
    gateway: String,
}

#[cfg(feature = "serve-live")]
impl LiveKeyProbe {
    fn new(configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig], beldexd_rpc: &str, gateway: &str) -> Self {
        use beldex_bridge_signer::evm_watcher::HttpJsonRpc;
        LiveKeyProbe {
            evm: configs.iter().map(|c| (HttpJsonRpc::new(c.rpc_url.clone()), c.contract)).collect(),
            daemon: HttpJsonRpc::new(format!("{}/json_rpc", beldexd_rpc.trim_end_matches('/'))),
            gateway: gateway.to_string(),
        }
    }

    fn word(&self, i: usize, selector: &str) -> Option<String> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        let (client, contract) = self.evm.get(i)?;
        let w = client
            .call("eth_call", serde_json::json!([{ "to": format!("0x{}", hex(contract)), "data": selector }, "latest"]))
            .ok()?;
        w.as_str().filter(|w| w.len() == 66).map(|w| w[2..].to_ascii_lowercase())
    }

    /// The first chain's key epoch: names the tree a hand-off retires.
    fn key_epoch(&self) -> Option<u64> {
        self.word(0, "0x6fdf657e").and_then(|w| u64::from_str_radix(&w[48..], 16).ok())
    }

    /// Whether `dir`'s key is live on every leg. `None` when a read fails or `dir` holds no
    /// certified key: not knowing is never taken for an answer.
    fn is_live(&self, dir: &std::path::Path) -> Option<bool> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        let cert = beldex_bridge_signer::dkg_driver::KeyCertificate::from_text(&std::fs::read_to_string(dir.join(KEY_CERT_FILE)).ok()?).ok()?;
        let signer = hex(&beldex_bridge_signer::aggregate_signature::eth_address(
            &k256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.pevm).ok()?,
        ));
        for i in 0..self.evm.len() {
            if self.word(i, "0x4cd615e7")?[24..] != signer {
                return Some(false);
            }
        }
        let info = self.daemon.call("get_gateway_info", serde_json::json!({ "gateway_address": self.gateway })).ok()?;
        Some(info.get("owner_key")?.as_str()?.eq_ignore_ascii_case(&hex(&cert.pgw)))
    }

    /// This node's successor tree beside `live`, if its key is now live: `shares-next`, or one
    /// a newer committee's key moved aside or parked (`dkg-auto`).
    fn live_successor(&self, live: &std::path::Path) -> Option<std::path::PathBuf> {
        let root = live.parent()?;
        let mut candidates = vec![root.join("shares-next")];
        if let Ok(it) = std::fs::read_dir(root) {
            for e in it.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("shares-next.superseded-at-") || name.starts_with("shares-next.unplaced-at-") {
                    candidates.push(e.path());
                }
            }
        }
        candidates.into_iter().find(|c| c.is_dir() && self.is_live(c) == Some(true))
    }

    /// Where the tree a hand-off retires goes: `shares-gen<N>`, `N` from the new key epoch, so
    /// every member names it alike whichever committees it sat on. Kept, never deleted.
    fn archive(&self, live: &std::path::Path) -> Result<std::path::PathBuf, String> {
        let root = live.parent().ok_or("share dir has no parent")?;
        let n = self.key_epoch().ok_or("cannot read the key epoch to name the retired tree")?.saturating_sub(2);
        let to = free_name(root, &format!("shares-gen{n}"));
        std::fs::rename(live, &to).map_err(|e| format!("retire {} to {}: {e}", live.display(), to.display()))?;
        Ok(to)
    }
}

/// A comma-separated list of bus daemons (BRIDGE_SIGNER_MINT_BUS_ENDPOINT, or a subscriber's
/// BRIDGE_SIGNER_OXENMQ_ENDPOINT), blanks dropped.
#[cfg(feature = "omq-client")]
fn bus_endpoints(list: &str) -> Vec<String> {
    list.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

/// `serve`'s exit status when its key has been handed over and its successor is live: restart
/// it, and it serves the successor (EX_TEMPFAIL).
#[cfg(feature = "serve-live")]
const RESTART_ON_SUCCESSOR: i32 = 75;

/// Before anything loads the shares: if this node's successor key is live on every leg, move it
/// in (the retired tree archived), so a member serves the key the bridge now trusts without a
/// person moving trees. Nothing happens while the hand-off is still going.
#[cfg(feature = "serve-live")]
fn install_successor(probe: &LiveKeyProbe, live: &std::path::Path) -> Result<Option<String>, String> {
    if probe.is_live(live) == Some(true) {
        return Ok(None);
    }
    let Some(next) = probe.live_successor(live) else { return Ok(None) };
    let retired = if live.exists() { Some(probe.archive(live)?) } else { None };
    std::fs::rename(&next, live).map_err(|e| format!("install {} as {}: {e}", next.display(), live.display()))?;
    Ok(Some(format!(
        "installed the successor key: {} -> {}{}",
        next.display(),
        live.display(),
        retired.map(|r| format!(" (retired tree kept in {})", r.display())).unwrap_or_default()
    )))
}

/// Loaded, reusable signing context for the live `serve` backend: the committee view, this
/// node's index + signer set, both legs' key material, and the mesh identity parameters. A
/// duty's sign closure ([`LiveSigners::pevm_sign`] / [`LiveSigners::pgw_sign`]) rebuilds the
/// per-leg mesh and runs one session — mirroring the `sign` subcommand, but driven by the
/// autonomy loop instead of an operator-supplied digest.
#[cfg(feature = "serve-live")]
struct LiveSigners {
    committee: beldex_bridge_signer::committee::CommitteeView,
    self_index: u16,
    signers: Vec<u16>,
    pgw_key_package: frost_ed25519::keys::KeyPackage,
    pgw_pubkey_package: frost_ed25519::keys::PublicKeyPackage,
    pgw_group_vk: [u8; 32],
    pevm_key_share: Vec<u8>,
    pevm_address: [u8; 20],
    curve_secret: [u8; 32],
    curve_public: [u8; 32],
    ed25519_secret: [u8; 64],
    port_base: u16,
    pevm_offset: u16,
    use_curve: bool,
    timeout: std::time::Duration,
}

#[cfg(feature = "serve-live")]
impl LiveSigners {
    fn build_mesh(
        &self,
        base: u16,
    ) -> (
        beldex_bridge_signer::dkg_driver::live::MeshIdentity,
        Vec<beldex_bridge_signer::dkg_driver::live::PeerTransportAddr>,
    ) {
        use beldex_bridge_signer::dkg_driver::live::{MeshIdentity, PeerTransportAddr};
        let identity = MeshIdentity {
            listen_endpoint: format!("tcp://0.0.0.0:{}", base + self.self_index),
            curve_secret: self.curve_secret,
            curve_public: self.curve_public,
            ed25519_secret: self.ed25519_secret,
        };
        let peers = self
            .committee
            .peer_transport_indexed(self.self_index as usize, base)
            .into_iter()
            .map(|(index, endpoint, curve_pubkey)| PeerTransportAddr { index, endpoint, curve_pubkey })
            .collect();
        (identity, peers)
    }

    /// `Pgw`: FROST-sign a 32-byte digest over the mesh, verify the aggregate under libsodium
    /// (the L1 consensus check), and return the 64-byte ed25519 signature.
    ///
    /// `signers` is the round's participant set — under coordinated autonomy this is the
    /// session's canonical ACK set (only members that independently verified the payload,
    /// C.5), not a static roster. `attempt` namespaces the round's mesh frames so a retry
    /// never ingests the failed attempt's messages.
    fn pgw_sign(&self, message: &[u8; 32], signers: &[u16], attempt: u32) -> Result<[u8; 64], String> {
        use beldex_bridge_signer::ffi;
        use beldex_bridge_signer::frost_sign_driver::live::run_live_sign;
        let (identity, peers) = self.build_mesh(self.port_base);
        let mut rng = rand::rngs::OsRng;
        let sig = run_live_sign(
            &self.committee,
            self.self_index,
            signers,
            self.pgw_key_package.clone(),
            self.pgw_pubkey_package.clone(),
            *message,
            attempt,
            &identity,
            &peers,
            self.use_curve,
            &mut rng,
            self.timeout,
        )
        .map_err(|e| format!("Pgw sign failed: {e:?}"))?;
        if !ffi::ed25519_verify_consensus(&sig, message, &self.pgw_group_vk) {
            return Err("Pgw aggregate failed libsodium verification".into());
        }
        Ok(sig)
    }

    /// `Pevm`: cggmp21-sign a mint preimage over the mesh, then `ecrecover` to find the
    /// recovery id and return the 65-byte `r‖s‖v` the wBDX contract verifies.
    /// `signers`/`attempt` as in [`LiveSigners::pgw_sign`].
    fn pevm_sign(&self, preimage: &[u8], signers: &[u16], attempt: u32) -> Result<[u8; 65], String> {
        use beldex_bridge_signer::cggmp21_sign_driver::live::run_live_pevm_sign;
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
        use sha3::{Digest, Keccak256};
        let (identity, peers) = self.build_mesh(self.port_base + self.pevm_offset);
        let (rs, x33) = run_live_pevm_sign(
            &self.committee,
            self.self_index,
            signers,
            &self.pevm_key_share,
            preimage,
            attempt,
            &identity,
            &peers,
            self.use_curve,
            self.timeout,
        )
        .map_err(|e| format!("Pevm sign failed: {e:?}"))?;

        let expected = VerifyingKey::from_sec1_bytes(&x33)
            .map(|vk| {
                let enc = vk.to_encoded_point(false);
                let h = Keccak256::digest(&enc.as_bytes()[1..]);
                let mut a = [0u8; 20];
                a.copy_from_slice(&h[12..]);
                a
            })
            .map_err(|e| format!("Pevm group key invalid: {e}"))?;
        let digest32: [u8; 32] = Keccak256::digest(preimage).into();
        let k_sig = K256Sig::from_slice(&rs).map_err(|e| format!("bad signature bytes: {e}"))?;
        let k_sig = k_sig.normalize_s().unwrap_or(k_sig);
        for rec in [0u8, 1u8] {
            if let Ok(vk) =
                VerifyingKey::recover_from_prehash(&digest32, &k_sig, RecoveryId::from_byte(rec).unwrap())
            {
                let enc = vk.to_encoded_point(false);
                let h = Keccak256::digest(&enc.as_bytes()[1..]);
                if h[12..] == expected {
                    // Emit the low-s form `rec` was found for: the raw (r, s) with this `v`
                    // would recover another key, and the contract rejects a high s anyway.
                    let mut out = [0u8; 65];
                    out[..64].copy_from_slice(&k_sig.to_bytes());
                    out[64] = 27 + rec;
                    return Ok(out);
                }
            }
        }
        Err("Pevm aggregate did not ecrecover to the wBDX signer".into())
    }

    /// The wBDX signer address of this node's `Pevm` group key, read from its own share.
    fn pevm_address(&self) -> Result<[u8; 20], String> {
        use cggmp21::key_share::AnyKeyShare;
        let share: cggmp21::KeyShare<
            cggmp21::supported_curves::Secp256k1,
            cggmp21::security_level::SecurityLevel128,
        > = serde_json::from_slice(&self.pevm_key_share)
            .map_err(|e| format!("deserialize Pevm key share: {e}"))?;
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(
            share.shared_public_key().to_bytes(true).as_ref(),
        )
        .map_err(|e| format!("Pevm group key invalid: {e}"))?;
        Ok(beldex_bridge_signer::aggregate_signature::eth_address(&vk))
    }
}

/// Load this node's `Pgw` key package (sealed) and public key package (public), and
/// require them to name the same group key. The public package is what the aggregator
/// verifies signature shares and the final signature against, so it must belong to the
/// share it sits beside.
#[cfg(feature = "live-dkg")]
fn load_pgw_material(
    dir: &str,
    self_index: u16,
) -> Result<(frost_ed25519::keys::KeyPackage, frost_ed25519::keys::PublicKeyPackage), String> {
    use frost_ed25519 as frost;
    let path = |suffix: &str| format!("{dir}/pgw-{self_index}.{suffix}");
    let key_package = frost::keys::KeyPackage::deserialize(
        &read_secret_file(&path("keypackage"))
            .map_err(|e| format!("pgw: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)"))?,
    )
    .map_err(|e| format!("bad pgw keypackage: {e}"))?;
    let pubkey_package = frost::keys::PublicKeyPackage::deserialize(&read_public_file(&path("pubkeypackage"))?)
        .map_err(|e| format!("bad pgw pubkeypackage: {e}"))?;
    if key_package.verifying_key() != pubkey_package.verifying_key() {
        return Err(format!(
            "{} names a different group key than the sealed share; the public file was \
             altered or belongs to another key",
            path("pubkeypackage")
        ));
    }
    Ok((key_package, pubkey_package))
}

/// The compressed `Pevm` group key inside a cggmp21 key share.
#[cfg(feature = "live-pevm-dkg")]
fn pevm_group_key_of(share: &[u8]) -> Result<Vec<u8>, String> {
    use cggmp21::key_share::AnyKeyShare;
    let share: cggmp21::KeyShare<
        cggmp21::supported_curves::Secp256k1,
        cggmp21::security_level::SecurityLevel128,
    > = serde_json::from_slice(share).map_err(|e| format!("deserialize Pevm key share: {e}"))?;
    Ok(share.shared_public_key().to_bytes(true).as_ref().to_vec())
}

/// Build the [`LiveSigners`] context: fetch the committee, resolve this node's index + signer
/// set, load both legs' key material (`dkg` output under `BRIDGE_SIGNER_SHARE_DIR`), and derive
/// the mesh identity from the MN key. Mirrors the `sign` subcommand's setup.
#[cfg(feature = "serve-live")]
fn build_live_signers(cfg: &Config) -> Result<LiveSigners, String> {
    let dir = std::env::var("BRIDGE_SIGNER_SHARE_DIR")
        .map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR (where `dkg` wrote the shares)".to_string())?;
    let port_base: u16 = std::env::var("BRIDGE_SIGNER_MESH_PORT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or("set BRIDGE_SIGNER_MESH_PORT_BASE (single-host devnet)")?;
    build_live_signers_for(cfg, &dir, port_base)
}

/// [`build_live_signers`] for the key in `dir`, on a mesh at `port_base` — so `dkg-auto` can
/// sign with a key it has just made, apart from the one `serve` signs with.
#[cfg(feature = "serve-live")]
fn build_live_signers_for(cfg: &Config, dir: &str, port_base: u16) -> Result<LiveSigners, String> {
    use beldex_bridge_signer::ffi;
    use std::time::Duration;

    let (committee, self_index) = load_key_committee(cfg, dir)?;
    let signers: Vec<u16> = match std::env::var("BRIDGE_SIGNER_SIGN_SIGNERS") {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => (0..committee.threshold as u16).collect(),
    };
    if !signers.contains(&self_index) {
        return Err(format!("this node ({self_index}) is not in the signer set {signers:?}"));
    }

    let pevm_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_PEVM_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let key_path =
        std::env::var("BRIDGE_SIGNER_MN_KEY_FILE").map_err(|_| "set BRIDGE_SIGNER_MN_KEY_FILE".to_string())?;
    let sk_bytes = std::fs::read(&key_path).map_err(|e| format!("read MN key {key_path}: {e}"))?;
    if sk_bytes.len() != 64 {
        return Err(format!("MN key {key_path} is {} bytes, expected 64", sk_bytes.len()));
    }
    let mut ed25519_secret = [0u8; 64];
    ed25519_secret.copy_from_slice(&sk_bytes);
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&ed25519_secret[32..64]);
    let curve_secret = ffi::ed25519_sk_to_x25519(&ed25519_secret)?;
    let curve_public = ffi::ed25519_pk_to_x25519(&ed_pub)?;
    if let Some(expected) = committee.member_x25519.get(self_index as usize) {
        if !expected.iter().all(|&b| b == 0) && curve_public != *expected {
            return Err("derived x25519 does not match this node's bridge.committee entry".into());
        }
    }
    let use_curve = std::env::var("BRIDGE_SIGNER_MESH_USE_CURVE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    let timeout = Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_SIGN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );

    // Pgw FROST material. The share files are indexed by this node's committee index AT
    // DKG TIME; committee indices are canonical (pubkey-sorted) per epoch, so they are
    // stable while the committee's membership is stable. If the file for our CURRENT
    // index is missing but a differently-indexed share exists, the committee has changed
    // (membership, or a daemon predating the canonical-order rule) — say so explicitly,
    // because the bare ENOENT reads as "dkg never ran".
    if !std::path::Path::new(&format!("{dir}/pgw-{self_index}.keypackage")).exists() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let others: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with("pgw-") && n.ends_with(".keypackage"))
                .collect();
            if !others.is_empty() {
                return Err(format!(
                    "this node's committee index is now {self_index}, but its share dir holds \
                     {others:?} — the committee order/membership changed since the DKG ran. \
                     Re-run the DKG for the current committee (shares, the contract signer, \
                     and the gateway owner key must all be regenerated together)."
                ));
            }
        }
    }
    let (pgw_key_package, pgw_pubkey_package) = load_pgw_material(&dir, self_index)?;
    let pgw_group_vk: [u8; 32] = pgw_pubkey_package
        .verifying_key()
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("cannot serialize pgw group verifying key")?;

    // Pevm cggmp21 keyshare (sealed; the driver deserializes the opened bytes).
    let pevm_key_share = read_secret_file(&format!("{dir}/pevm-{self_index}.keyshare"))
        .map_err(|e| format!("pevm: {e} (run `dkg` first with BRIDGE_SIGNER_SHARE_DIR set)"))?;
    // The wBDX signer address this share set signs as — what the contract's `currentSigner`
    // reads while this key is the live one. Taken from the sealed share, not the public
    // group-key file beside it, which only has to agree.
    let pevm_address = {
        use k256::ecdsa::VerifyingKey;
        let x33 = pevm_group_key_of(&pevm_key_share)?;
        let on_disk = read_public_file(&format!("{dir}/pevm-{self_index}.groupkey"))?;
        if on_disk != x33 {
            return Err(format!(
                "{dir}/pevm-{self_index}.groupkey does not match the group key in the sealed \
                 share; the public file was altered or belongs to another key"
            ));
        }
        let vk = VerifyingKey::from_sec1_bytes(&x33).map_err(|e| format!("bad pevm group key: {e}"))?;
        beldex_bridge_signer::aggregate_signature::eth_address(&vk)
    };

    Ok(LiveSigners {
        committee,
        self_index,
        signers,
        pgw_key_package,
        pgw_pubkey_package,
        pgw_group_vk,
        pevm_key_share,
        pevm_address,
        curve_secret,
        curve_public,
        ed25519_secret,
        port_base,
        pevm_offset,
        use_curve,
        timeout,
    })
}

/// The live `serve` path: the **coordinated autonomy loop**. Composes the
/// [`Coordinator`](beldex_bridge_signer::coordinator::Coordinator) (deterministic per-duty
/// sessions + leader over the S4-authenticated OMQ mesh) with
/// [`DualPolicy`](beldex_bridge_signer::release_policy::DualPolicy) (mint C.5 byte-rebuild +
/// release R1–R6 via the member's own daemon), [`LiveSigners`] (per-duty Pevm/Pgw mesh
/// sessions), and [`HttpGatewayRpc`] (release build with the replay-guard ref + verify +
/// submit). Enabled by `--features serve-live` + `BRIDGE_SIGNER_SERVE_LIVE=1`.
#[cfg(feature = "serve-live")]
#[allow(clippy::too_many_arguments)]
/// Split a failed release build into "retry" and "give up".
///
/// Treating every failure as transient retries a permanently impossible duty forever: a burn
/// naming an address the daemon cannot parse re-opens a session every few seconds, for as long
/// as the process runs, and hammers the daemon building a withdrawal it will always refuse.
///
/// The daemon answers a malformed request with the JSON-RPC "invalid params" code, which is a
/// statement about the request itself and cannot become true later. Everything else — a
/// transport failure, a timeout, an internal error — is a statement about right now, so it
/// keeps retrying. The asymmetry is deliberate: a wrong "transient" costs some retries, a
/// wrong "unactionable" drops a payable release.
///
/// The burn is discharged on the EVM side either way, so an unactionable release means the
/// user has lost their funds. That must not disappear into a counter — it is logged here,
/// where the recipient and the burn reference are both in hand.
fn classify_release_build_error(
    ev: &beldex_bridge_signer::watch::ReleaseEvent,
    recipient: &str,
    e: String,
) -> beldex_bridge_signer::coordinator::BuildError {
    // The error text is produced by this crate's own JSON-RPC client, which embeds the
    // daemon's error object verbatim: `<method>: rpc error {"code":-1,"message":"..."}`.
    //
    // Match the MESSAGE, not the code. The daemon returns ERROR_WRONG_PARAM (-1) both for a
    // request that can never work and for "insufficient gateway balance for withdrawal +
    // fee", which is about right now and must keep retrying — abandoning that one would drop
    // a payable release and the user's burn is already discharged.
    //
    // The destination is also the ONLY field here that comes from outside: the burn carries
    // it, a user typed it. Every other parameter this call sends is built by the signer, so
    // the daemon rejecting one of those is a bug in us, and looping loudly on it is the right
    // outcome rather than silently dropping the duty.
    if e.contains("invalid destination address") {
        eprintln!(
            "!! UNROUTABLE RELEASE — burn {}:{} of {} atomic units names an address the daemon \
             cannot use ({recipient:?}); the wBDX is already burned and this release can never \
             be paid. Abandoning it. Daemon said: {e}",
            hex(&ev.evm_txid),
            ev.log_index,
            ev.amount,
        );
        return beldex_bridge_signer::coordinator::BuildError::Unactionable(e);
    }
    beldex_bridge_signer::coordinator::BuildError::Transient(e)
}

/// The ways a signed mint payload leaves this node: the daemon's mint bus and the optional
/// relay command. Shared by the duty's completion and the mint outbox's re-delivery sweep,
/// so a retry goes out exactly the way the first attempt did.
#[cfg(feature = "omq-client")]
struct MintHandoff {
    /// Every bus daemon to publish to (BRIDGE_SIGNER_MINT_BUS_ENDPOINT, comma-separated): a
    /// daemon fans a payload out to its own subscribers only, so one daemon down must not be
    /// the bus down. Receivers drop the duplicates.
    bus: Vec<(String, beldex_bridge_signer::omq_client::OmqCommitteeClient)>,
    bus_genesis: [u8; 32],
    bus_sign_key: [u8; 64],
    /// This node's master node pubkey, named in every publication so the daemon can
    /// authenticate a member of a committee it has moved past with one lookup.
    bus_master_node: [u8; 32],
    self_index: u16,
    relay_cmd: Option<String>,
    relay_stagger_ms: u64,
}

#[cfg(feature = "omq-client")]
impl MintHandoff {
    /// Best effort on every path: the payload is already saved, and the sweep re-delivers
    /// anything that has not minted, so a failure here is logged and nothing more.
    fn deliver(&self, payload: &str) {
        self.publish(payload);
        if let Some(cmd) = &self.relay_cmd {
            if self.relay_stagger_ms > 0 && self.self_index > 0 {
                std::thread::sleep(std::time::Duration::from_millis(
                    self.relay_stagger_ms * self.self_index as u64,
                ));
            }
            match pipe_to_relay(cmd, payload) {
                Ok(out) => println!("  relayed: {}", out.trim()),
                Err(e) => eprintln!("  RELAY FAILED ({e}) — kept for re-delivery"),
            }
        }
    }

    /// The bus half of [`Self::deliver`] alone: for a payload no EVM relayer carries.
    fn publish(&self, payload: &str) {
        for (endpoint, bus) in &self.bus {
            use beldex_bridge_signer::omq_client::mint_publish_message;
            let msg = mint_publish_message(&self.bus_genesis, payload);
            match beldex_bridge_signer::ffi::ed25519_sign_detached(&self.bus_sign_key, &msg) {
                Ok(pub_sig) => match bus.publish_mint_payload(payload, self.self_index, &pub_sig, &self.bus_master_node) {
                    // `DUPLICATE` = a peer in the same quorum published it moments ago.
                    // Expected and desirable: one fan-out per deposit, not t+1.
                    Ok(status) => println!("  published to mint bus {endpoint}: {status}"),
                    Err(e) => eprintln!("  mint-bus publish to {endpoint} failed ({e}) — kept for re-delivery"),
                },
                Err(e) => eprintln!("  mint-bus signing failed ({e}) — kept for re-delivery"),
            }
        }
    }
}

/// One wBDX contract's takeover state, read at the tip.
#[cfg(feature = "serve-live")]
struct EvmTakeoverState {
    signer: [u8; 20],
    standby: [u8; 20],
    started_at: u64,
    nonce: u64,
    key_epoch: u64,
    delay: u64,
    cooldown_until: u64,
    /// The latest block's timestamp: the contract's clock.
    now: u64,
    /// A rotation is pending (`pendingActivateAt` != 0): its activation clears the standby.
    rotation_pending: bool,
}

#[cfg(feature = "serve-live")]
impl EvmTakeoverState {
    fn running(&self) -> bool {
        self.started_at != 0
    }
    fn ready(&self) -> bool {
        self.running() && self.now >= self.started_at.saturating_add(self.delay)
    }
    fn cooling(&self) -> bool {
        self.now < self.cooldown_until
    }
}

/// The gateway's takeover state, read from get_gateway_info.
#[cfg(feature = "serve-live")]
struct GatewayTakeoverState {
    owner: String,
    standby: String,
    started: u64,
    ready_height: u64,
    cooldown_until: u64,
    height: u64,
    steps: u64,
    cancel_message: Option<[u8; 32]>,
    begin_message: Option<[u8; 32]>,
    complete_message: Option<[u8; 32]>,
    /// The block the standby proves it can sign over now, and the exact message.
    alive_height: u64,
    alive_message: Option<[u8; 32]>,
    /// When the standby was last named or proved itself, and whether that is too long ago.
    last_seen: Option<u64>,
    stale: bool,
}

#[cfg(feature = "serve-live")]
impl GatewayTakeoverState {
    fn ready(&self) -> bool {
        self.started != 0 && self.height >= self.ready_height
    }
    fn cooling(&self) -> bool {
        self.height < self.cooldown_until
    }
}

/// Standby-takeover state for this node's key, read from its own RPCs at the chain tip, and
/// what that means for this node's role:
///  - live: a takeover begun against its key is cancelled while the key can sign;
///  - standby: when this node sees the live key failing (a deposit final for the outage
///    window and still unminted), the takeover is begun on every chain, and once every half
///    is ready, completed on every chain, never one alone.
/// Shared by detection, the takeover policy and its reconciler.
#[cfg(feature = "serve-live")]
struct TakeoverReader {
    /// Each wBDX chain: id, client, contract.
    evm: Vec<(u64, beldex_bridge_signer::evm_watcher::HttpJsonRpc, [u8; 20])>,
    gateway_rpc: beldex_bridge_signer::evm_watcher::HttpJsonRpc,
    gateway: String,
    pevm_address: [u8; 20],
    pgw_group_vk: [u8; 32],
    standby_role: bool,
    /// Standby role: whether this node itself sees the live key failing (set by the loop).
    outage: std::cell::Cell<bool>,
}

#[cfg(feature = "serve-live")]
impl TakeoverReader {
    /// One 32-byte word from a no-argument wBDX getter.
    fn word(client: &beldex_bridge_signer::evm_watcher::HttpJsonRpc, contract: &[u8; 20], getter: &str) -> Result<[u8; 32], String> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        use sha3::{Digest, Keccak256};
        let data = format!("0x{}", hex(&Keccak256::digest(getter.as_bytes())[..4]));
        let reply = client
            .call("eth_call", serde_json::json!([{ "to": format!("0x{}", hex(contract)), "data": data }, "latest"]))
            .map_err(|e| format!("{getter}: {e:?}"))?;
        reply
            .as_str()
            .filter(|w| w.len() == 66)
            .and_then(|w| config::parse_hex32(&w[2..]))
            .ok_or_else(|| format!("{getter}: unexpected reply {reply}"))
    }

    fn low_u64(w: &[u8; 32]) -> u64 {
        u64::from_be_bytes(w[24..].try_into().expect("8 bytes"))
    }

    fn address(w: &[u8; 32]) -> [u8; 20] {
        w[12..].try_into().expect("20 bytes")
    }

    fn evm_state(client: &beldex_bridge_signer::evm_watcher::HttpJsonRpc, contract: &[u8; 20]) -> Result<EvmTakeoverState, String> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        let block = client
            .call("eth_getBlockByNumber", serde_json::json!(["latest", false]))
            .map_err(|e| format!("latest block: {e:?}"))?;
        let now = block
            .get("timestamp")
            .and_then(|t| t.as_str())
            .and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok())
            .ok_or("latest block has no timestamp")?;
        Ok(EvmTakeoverState {
            signer: Self::address(&Self::word(client, contract, "currentSigner()")?),
            standby: Self::address(&Self::word(client, contract, "standbySigner()")?),
            started_at: Self::low_u64(&Self::word(client, contract, "takeoverStartedAt()")?),
            nonce: Self::low_u64(&Self::word(client, contract, "takeoverNonce()")?),
            key_epoch: Self::low_u64(&Self::word(client, contract, "keyEpoch()")?),
            delay: Self::low_u64(&Self::word(client, contract, "standbyTakeoverDelayOrDefault()")?),
            cooldown_until: Self::low_u64(&Self::word(client, contract, "takeoverCooldownUntil()")?),
            now,
            rotation_pending: Self::low_u64(&Self::word(client, contract, "pendingActivateAt()")?) != 0,
        })
    }

    /// This node's daemon's tip.
    fn tip_height(&self) -> Option<u64> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        self.gateway_rpc.call("get_info", serde_json::json!({})).ok()?.get("height")?.as_u64()
    }

    fn gateway_state(&self) -> Result<GatewayTakeoverState, String> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        let info = self
            .gateway_rpc
            .call("get_gateway_info", serde_json::json!({ "gateway_address": self.gateway }))
            .map_err(|e| format!("get_gateway_info: {e:?}"))?;
        let s = |k: &str| info.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_lowercase();
        let n = |k: &str| info.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let m = |k: &str| info.get(k).and_then(|v| v.as_str()).and_then(config::parse_hex32);
        let height = self.tip_height().ok_or("get_info: no height")?;
        Ok(GatewayTakeoverState {
            owner: s("owner_key"),
            standby: s("standby_owner_key"),
            started: n("takeover_started_height"),
            ready_height: n("takeover_ready_height"),
            cooldown_until: n("takeover_cooldown_until_height"),
            height,
            steps: n("takeover_steps"),
            cancel_message: m("takeover_cancel_message"),
            begin_message: m("takeover_begin_message"),
            complete_message: m("takeover_complete_message"),
            alive_height: n("standby_alive_height"),
            alive_message: m("standby_alive_message"),
            last_seen: info.get("standby_last_seen_height").and_then(|v| v.as_u64()),
            stale: info.get("standby_stale").and_then(|v| v.as_bool()).unwrap_or(false),
        })
    }

    /// The daemon's view of the bridge gateway's standby, and the key attestations.
    fn standby_view(
        &self,
    ) -> Option<(beldex_bridge_signer::key_attestation::StandbyView, Vec<beldex_bridge_signer::key_attestation::Record>)> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        use beldex_bridge_signer::key_attestation as ka;
        let v = self.gateway_rpc.call("bridge_get_standby", serde_json::json!({})).ok()?;
        Some((ka::parse_view(&v)?, ka::parse_records(&v)?))
    }

    /// Live role: the standby every chain should name (key_attestation::standby_target): the
    /// named one while it works, else the one to name in its place. None if there is none, or
    /// the bridge gateway's owner is not this node's key or not attested yet.
    fn standby_target(&self) -> Option<beldex_bridge_signer::key_attestation::Record> {
        let (view, records) = self.standby_view()?;
        if view.owner_key != Some(self.pgw_group_vk) {
            return None;
        }
        beldex_bridge_signer::key_attestation::standby_target(&view, &records).cloned()
    }

    /// Every takeover step this node's role should sign now, with the exact bytes, from one
    /// read of every chain. A chain that cannot be read contributes nothing, and in the
    /// standby role blocks any complete: never finish one half without seeing the others.
    fn wanted(&self) -> Vec<(beldex_bridge_signer::watch::TakeoverStep, Vec<u8>)> {
        use beldex_bridge_signer::takeover_guard::{
            evm_begin_preimage, evm_cancel_preimage, evm_complete_preimage, evm_set_standby_preimage, standby_deadline,
        };
        use beldex_bridge_signer::watch::{TakeoverStep, TakeoverStepKind};
        let ours_vk = hex(&self.pgw_group_vk);
        let evm: Vec<_> = self
            .evm
            .iter()
            .map(|(id, client, contract)| (*id, client, *contract, Self::evm_state(client, contract)))
            .collect();
        let gw = self.gateway_state();
        let mut out = Vec::new();

        if !self.standby_role {
            for (chain_id, client, contract, st) in &evm {
                let Ok(st) = st else { continue };
                if st.signer != self.pevm_address || !st.running() {
                    continue;
                }
                if let Ok(tag) = Self::word(client, contract, "TAKEOVER_CANCEL_TAG()") {
                    out.push((
                        TakeoverStep { chain_id: *chain_id, step: TakeoverStepKind::Cancel, takeover_id: st.nonce, key_epoch: st.key_epoch },
                        evm_cancel_preimage(tag, *chain_id, *contract, st.key_epoch, st.nonce),
                    ));
                }
            }
            if let Ok(g) = &gw {
                if g.owner == ours_vk && g.started != 0 {
                    if let Some(m) = g.cancel_message {
                        out.push((
                            TakeoverStep { chain_id: TakeoverStep::GATEWAY, step: TakeoverStepKind::Cancel, takeover_id: g.started, key_epoch: 0 },
                            m.to_vec(),
                        ));
                    }
                }
            }
            // Name the standby wherever it is missing and no takeover runs: the same key on
            // every chain, the one the attestations on L1 give. A standby that stopped proving
            // it can sign (stale) counts as missing. Without a working standby, a lost live key
            // would stop the bridge until governance stepped in.
            let gw_unnamed =
                gw.as_ref().is_ok_and(|g| g.owner == ours_vk && g.started == 0 && (g.standby.is_empty() || g.stale));
            let evm_ours = evm.iter().any(|(_, _, _, st)| st.as_ref().is_ok_and(|st| st.signer == self.pevm_address && !st.running()));
            // Not while this committee's key is being handed off: naming spends the rotation
            // nonce the hand-off was signed with, and the hand-off drops the standby on every
            // chain and on the gateway anyway. The incoming committee names its own.
            let handing_off = evm.iter().any(|(_, _, _, st)| st.as_ref().is_ok_and(|st| st.rotation_pending));
            if (evm_ours || gw_unnamed) && !handing_off {
                if let Some(cand) = self.standby_target() {
                    for (chain_id, client, contract, st) in &evm {
                        let Ok(st) = st else { continue };
                        if st.signer != self.pevm_address || st.standby == cand.pevm_address || st.running() {
                            continue;
                        }
                        if let (Ok(tag), Ok(nonce)) =
                            (Self::word(client, contract, "STANDBY_TAG()"), Self::word(client, contract, "rotationNonce()"))
                        {
                            let next = Self::low_u64(&nonce) + 1;
                            out.push((
                                TakeoverStep { chain_id: *chain_id, step: TakeoverStepKind::NameStandby, takeover_id: next, key_epoch: st.key_epoch },
                                evm_set_standby_preimage(tag, *chain_id, *contract, st.key_epoch, cand.pevm_address, next, standby_deadline(st.now)),
                            ));
                        }
                    }
                    if gw_unnamed && gw.as_ref().is_ok_and(|g| g.standby != hex(&cand.pgw_vk)) {
                        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
                        let info = self.gateway_rpc.call(
                            "get_gateway_info",
                            serde_json::json!({ "gateway_address": self.gateway, "standby_owner_key": hex(&cand.pgw_vk) }),
                        );
                        if let Ok(info) = info {
                            let nonce = info.get("standby_name_nonce").and_then(|v| v.as_u64());
                            let msg = info.get("standby_name_message").and_then(|v| v.as_str()).and_then(config::parse_hex32);
                            if let (Some(n), Some(m)) = (nonce, msg) {
                                out.push((
                                    TakeoverStep { chain_id: TakeoverStep::GATEWAY, step: TakeoverStepKind::NameStandby, takeover_id: n, key_epoch: cand.committee_height },
                                    m.to_vec(),
                                ));
                            }
                        }
                    }
                }
            }
            return out;
        }

        // Standby role. Complete only when every half is ready or already ours: a half that is
        // neither was cancelled by a live key, and completing the rest would split the bridge.
        let evm_settled = |st: &EvmTakeoverState| st.signer == self.pevm_address || (st.standby == self.pevm_address && st.ready());
        let all_ready = evm.iter().all(|(_, _, _, st)| st.as_ref().is_ok_and(|st| evm_settled(st)))
            && gw.as_ref().is_ok_and(|g| g.owner == ours_vk || (g.standby == ours_vk && g.ready()));
        // Begin only while every half still names this standby (or is already ours): a chain that
        // dropped it, as a hand-off to the next committee does, could never be completed, so a
        // begin anywhere would only cost its fee and hold off a real takeover by its cooldown.
        let named_everywhere = evm
            .iter()
            .all(|(_, _, _, st)| st.as_ref().is_ok_and(|st| st.standby == self.pevm_address || st.signer == self.pevm_address))
            && gw.as_ref().is_ok_and(|g| g.standby == ours_vk || g.owner == ours_vk);
        let outage = self.outage.get() && named_everywhere;
        let steps_before = out.len();
        for (chain_id, client, contract, st) in &evm {
            let Ok(st) = st else { continue };
            if st.standby != self.pevm_address || st.signer == self.pevm_address {
                continue;
            }
            if !st.running() && !st.cooling() && outage {
                if let Ok(tag) = Self::word(client, contract, "TAKEOVER_BEGIN_TAG()") {
                    let next = st.nonce + 1;
                    out.push((
                        TakeoverStep { chain_id: *chain_id, step: TakeoverStepKind::Begin, takeover_id: next, key_epoch: st.key_epoch },
                        evm_begin_preimage(tag, *chain_id, *contract, st.key_epoch, st.standby, next),
                    ));
                }
            } else if st.ready() && all_ready {
                if let Ok(tag) = Self::word(client, contract, "TAKEOVER_COMPLETE_TAG()") {
                    out.push((
                        TakeoverStep { chain_id: *chain_id, step: TakeoverStepKind::Complete, takeover_id: st.nonce, key_epoch: st.key_epoch },
                        evm_complete_preimage(tag, *chain_id, *contract, st.key_epoch + 1, st.standby),
                    ));
                }
            }
        }
        if let Ok(g) = &gw {
            if g.standby == ours_vk && g.owner != ours_vk {
                if g.started == 0 && !g.cooling() && outage {
                    if let Some(m) = g.begin_message {
                        out.push((
                            TakeoverStep { chain_id: TakeoverStep::GATEWAY, step: TakeoverStepKind::Begin, takeover_id: g.steps, key_epoch: 0 },
                            m.to_vec(),
                        ));
                    }
                } else if g.ready() && all_ready {
                    if let Some(m) = g.complete_message {
                        out.push((
                            TakeoverStep { chain_id: TakeoverStep::GATEWAY, step: TakeoverStepKind::Complete, takeover_id: g.started, key_epoch: 0 },
                            m.to_vec(),
                        ));
                    }
                }
                // Prove this standby can still sign, once per slot: one that stops is replaced.
                // A running takeover is no reason to stop, since its delay can outlast the proof's
                // limit, but a takeover step that is due goes first: rounds run one at a time.
                if out.len() == steps_before && g.alive_height != 0 && g.last_seen.is_none_or(|seen| seen < g.alive_height) {
                    if let Some(m) = g.alive_message {
                        out.push((
                            TakeoverStep { chain_id: TakeoverStep::GATEWAY, step: TakeoverStepKind::StandbyAlive, takeover_id: g.alive_height, key_epoch: 0 },
                            m.to_vec(),
                        ));
                    }
                }
            }
        }
        out
    }

    /// Whether a takeover by this node's key is running on any chain. Its holders are what
    /// completes it, so they do not step aside while it runs, however stale the key reads.
    fn own_takeover_running(&self) -> bool {
        self.gateway_state().is_ok_and(|g| g.standby == hex(&self.pgw_group_vk) && g.started != 0)
            || self.evm.iter().any(|(_, client, contract)| {
                Self::evm_state(client, contract).is_ok_and(|st| st.standby == self.pevm_address && st.running())
            })
    }

    /// Whether every chain answers to this node's key: each wBDX signer and the gateway owner.
    /// An unreadable chain is not "ours".
    fn all_ours(&self) -> bool {
        self.evm.iter().all(|(_, client, contract)| {
            Self::evm_state(client, contract).is_ok_and(|st| st.signer == self.pevm_address)
        }) && self.gateway_state().is_ok_and(|g| g.owner == hex(&self.pgw_group_vk))
    }

    /// What this node would sign for `s` now: its bytes while this node's role still wants
    /// that step, Ended once it does not (see takeover_guard::TakeoverView).
    fn view(&self, s: &beldex_bridge_signer::watch::TakeoverStep) -> Result<beldex_bridge_signer::takeover_guard::TakeoverView, String> {
        use beldex_bridge_signer::takeover_guard::TakeoverView;
        // A transport failure must not read as "ended": check the chain this step is on.
        if s.on_gateway() {
            self.gateway_state()?;
        } else if let Some((_, client, contract)) = self.evm.iter().find(|(id, _, _)| *id == s.chain_id) {
            Self::evm_state(client, contract)?;
        }
        Ok(match self.wanted().into_iter().find(|(w, _)| w == s) {
            Some((_, bytes)) => TakeoverView::Running(bytes),
            None => TakeoverView::Ended,
        })
    }
}

/// Standby role: refresh whether this node sees the live key failing. A deposit seen final
/// at least `window` ago and still unminted on its chain is that evidence; minted ones are
/// dropped. Each standby member judges this from its own daemon and RPCs, so a begin needs
/// `threshold` members who each saw it.
#[cfg(feature = "serve-live")]
fn update_outage(
    reader: &TakeoverReader,
    evidence: &mut std::collections::BTreeMap<([u8; 32], u32), (u64, std::time::Instant)>,
    minted: &mut beldex_bridge_signer::reconcile::EvmMintReconciler<beldex_bridge_signer::evm_watcher::HttpJsonRpc>,
    window: std::time::Duration,
) {
    use beldex_bridge_signer::reconcile::DutyReconciler;
    let mut stuck: Option<([u8; 32], u32, u64, u64)> = None;
    evidence.retain(|(txid, idx), (chain, seen)| {
        let d = beldex_bridge_signer::orchestrator::Duty::Mint(beldex_bridge_signer::watch::MintEvent {
            beldex_txid: *txid,
            output_index: *idx,
            dst_chain: beldex_bridge_signer::chain_registry::ChainId(*chain),
            to: [0u8; 20],
            amount: 0,
        });
        match minted.is_settled(&d) {
            Some(true) => false,
            Some(false) => {
                if stuck.is_none() && seen.elapsed() >= window {
                    stuck = Some((*txid, *idx, *chain, seen.elapsed().as_secs()));
                }
                true
            }
            None => true, // unreadable: keep it, decide nothing
        }
    });
    let was = reader.outage.replace(stuck.is_some());
    match (was, stuck) {
        (false, Some((txid, idx, chain, age))) => eprintln!(
            "!! LIVE KEY NOT MINTING: deposit {}:{idx} to chain {chain} has been final for {age}s and is \
             still unminted",
            hex(&txid)
        ),
        (true, None) => println!("the live key is minting again: no deposit is unminted past the outage window"),
        _ => {}
    }
}

/// Standby role, optional: a small deposit to the bridge every so often while none is
/// pending, so the live key's failure shows even when nobody is using the bridge. It mints
/// to the configured address like any deposit, so it costs only the fees.
#[cfg(feature = "serve-live")]
struct ProbeDeposit {
    wallet: beldex_bridge_signer::evm_watcher::HttpJsonRpc,
    daemon: beldex_bridge_signer::evm_watcher::HttpJsonRpc,
    gateway: String,
    every: std::time::Duration,
    chain_id: u64,
    evm_address: String,
    amount: u64,
}

#[cfg(feature = "serve-live")]
impl ProbeDeposit {
    /// BRIDGE_SIGNER_PROBE_WALLET_RPC (+ _LOGIN_FILE), _EVERY_SECS (0 or unset: off),
    /// _CHAIN_ID, _EVM_ADDRESS, _AMOUNT (atomic, default 1 BDX).
    fn from_env(gateway: String, beldexd_rpc: &str) -> Option<ProbeDeposit> {
        let v = |k: &str| std::env::var(k).ok().map(|x| x.trim().to_string()).filter(|x| !x.is_empty());
        let every: u64 = v("BRIDGE_SIGNER_PROBE_EVERY_SECS")?.parse().ok().filter(|n| *n > 0)?;
        let url = v("BRIDGE_SIGNER_PROBE_WALLET_RPC")?;
        let wallet = match v("BRIDGE_SIGNER_PROBE_WALLET_LOGIN_FILE") {
            Some(f) => match beldex_bridge_signer::rpc_login::read_login_file(std::path::Path::new(&f)) {
                Ok(login) => beldex_bridge_signer::evm_watcher::HttpJsonRpc::new(url).with_basic_auth(&login),
                Err(e) => {
                    eprintln!("!! probe deposits off: {e}");
                    return None;
                }
            },
            None => beldex_bridge_signer::evm_watcher::HttpJsonRpc::new(url),
        };
        Some(ProbeDeposit {
            wallet,
            daemon: beldex_bridge_signer::evm_watcher::HttpJsonRpc::new(format!("{}/json_rpc", beldexd_rpc.trim_end_matches('/'))),
            gateway,
            every: std::time::Duration::from_secs(every),
            chain_id: v("BRIDGE_SIGNER_PROBE_CHAIN_ID")?.parse().ok()?,
            evm_address: v("BRIDGE_SIGNER_PROBE_EVM_ADDRESS")?,
            amount: v("BRIDGE_SIGNER_PROBE_AMOUNT").and_then(|a| a.parse().ok()).unwrap_or(1_000_000_000),
        })
    }

    fn maybe_probe(&self, idle: bool, last: &mut Option<std::time::Instant>) {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        if !idle || last.is_some_and(|t| t.elapsed() < self.every) {
            return;
        }
        *last = Some(std::time::Instant::now());
        let address = match self.daemon.call("get_gateway_info", serde_json::json!({ "gateway_address": self.gateway })) {
            Ok(info) => info.get("address").and_then(|a| a.as_str()).unwrap_or_default().to_string(),
            Err(e) => {
                eprintln!("  probe deposit skipped: get_gateway_info: {e:?}");
                return;
            }
        };
        let params = serde_json::json!({
            "destinations": [{
                "address": address,
                "amount": self.amount,
                "bridge_chain_id": self.chain_id,
                "bridge_evm_address": self.evm_address,
            }],
            "priority": 1,
        });
        match self.wallet.call("transfer", params) {
            Ok(r) => println!("  probe deposit sent: {}", r.get("tx_hash").cloned().unwrap_or_default()),
            Err(e) => eprintln!("  probe deposit failed: {e:?}"),
        }
    }
}

/// Standby role, waiting for shares: generate the next standby key when this node is on the
/// committee of a standby round (key_attestation::standby_round_due). Consensus draws a round
/// only while a standby is due, and every member starts on seeing the round's block. The round
/// is the key generation, so each round has one attempt under fresh execution ids, which the
/// execution ledger requires; a failed one costs only until the next round, whose committee
/// is another. The shares are written beside the share directory and moved in only once
/// complete, so a failed ceremony never leaves half a set to serve.
#[cfg(feature = "serve-live")]
struct AutoStandbyDkg {
    last_round: u64,
    last_reason: String,
}

#[cfg(feature = "serve-live")]
impl AutoStandbyDkg {
    fn maybe_run(&mut self, cfg: &Config, share_dir: &std::path::Path, beldexd_rpc: &str) {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        use beldex_bridge_signer::key_attestation as ka;
        let now = beldex_bridge_signer::release_outbox::now_secs();
        let daemon = beldex_bridge_signer::evm_watcher::HttpJsonRpc::new(format!(
            "{}/json_rpc",
            beldexd_rpc.trim_end_matches('/')
        ));
        let due = daemon
            .call("bridge_get_standby", serde_json::json!({}))
            .map_err(|e| format!("bridge_get_standby: {e:?}"))
            .and_then(|v| ka::parse_view(&v).ok_or_else(|| "bridge_get_standby: unexpected reply".to_string()))
            .and_then(|view| ka::standby_round_due(&view));
        let round = match due {
            Ok(round) => round,
            Err(why) => {
                if why != self.last_reason {
                    println!("  standby key generation not due: {why}");
                    self.last_reason = why;
                }
                return;
            }
        };
        if round == self.last_round {
            return;
        }
        let reply = beldex_bridge_signer::omq_client::OmqCommitteeClient::new(cfg.oxenmq_endpoint.clone())
            .fetch_standby_round_json(round)
            .map_err(|e| e.to_string())
            .and_then(|json| {
                beldex_bridge_signer::committee::CommitteeView::from_bridge_committee_json(&json).map_err(|e| e.to_string())
            });
        // A lookup that fails has not used the round's attempt: the key needs every member, so
        // one member giving up on a passing error would cost the whole committee its round.
        let reply = match reply {
            Ok(c) => c,
            Err(e) => {
                let why = format!("standby round {round}: no committee yet ({e}); retrying");
                if why != self.last_reason {
                    eprintln!("  {why}");
                    self.last_reason = why;
                }
                return;
            }
        };
        self.last_round = round;
        self.last_reason.clear();
        if reply.daemon_self_index.is_none() && reply.self_index(&cfg.self_mn_pubkey).is_none() {
            println!("  standby round {round}: this node is not on its committee");
            return;
        }
        let Ok(keygen) = u32::try_from(round) else { return };
        let staging = std::path::PathBuf::from(format!("{}.dkg-{keygen}", share_dir.display()));
        let _ = std::fs::remove_dir_all(&staging);
        println!("NO STANDBY: generating the next standby key with the committee of standby round {round}");
        let result = match staging.to_str() {
            Some(dir) => run_dkg_into(cfg, Some(dir), keygen, Some(round)),
            None => Err("the share directory's path is not UTF-8".into()),
        };
        match result {
            Ok(()) if beldex_bridge_signer::share_watch::fingerprint(&staging).is_some() => {
                // An empty or half-written directory in the way is set aside, never deleted.
                let in_place = std::fs::remove_dir(share_dir).is_ok() || !share_dir.exists() || {
                    let aside = format!("{}.incomplete-{now}", share_dir.display());
                    std::fs::rename(share_dir, &aside).is_ok()
                };
                match in_place.then(|| std::fs::rename(&staging, share_dir)) {
                    Some(Ok(())) => println!("standby key generated: shares in {}", share_dir.display()),
                    _ => eprintln!(
                        "!! standby key generated in {} but could not be moved to {}: move it by hand",
                        staging.display(),
                        share_dir.display()
                    ),
                }
            }
            Ok(()) => {
                eprintln!("  standby key generation left no complete share set; next round");
                let _ = std::fs::remove_dir_all(&staging);
            }
            Err(e) => {
                eprintln!("  standby key generation failed ({e}); next round");
                let _ = std::fs::remove_dir_all(&staging);
            }
        }
    }
}

// The live backend: coordinated signing over the mesh. Only built with `serve-live`, the
// feature that brings the mesh, the live signers and the release builder it uses; without
// it `serve` runs the dry-run backend and this is never called.
#[cfg(feature = "serve-live")]
fn run_serve_live<B, C>(
    cfg: &Config,
    src: &mut beldex_bridge_signer::service::WatcherEventSource<B, C>,
    orch: &mut beldex_bridge_signer::orchestrator::Orchestrator,
    opts: &beldex_bridge_signer::service::ServeOptions,
    configs: &[beldex_bridge_signer::evm_watcher::EvmChainConfig],
    beldexd_rpc: &str,
    gateway_id: &str,
    poll_secs: u64,
) -> Result<(), String>
where
    B: beldex_bridge_signer::beldex_watcher::BeldexRpc,
    C: beldex_bridge_signer::evm_watcher::JsonRpcClient,
{
    use beldex_bridge_signer::coordinator::{BuildError, Coordinator, MintPolicy, OpenGate};
    use beldex_bridge_signer::live_backend::{mint_relay_payload_json, GatewayRpc, HttpGatewayRpc};
    use beldex_bridge_signer::omq_mesh::{MeshAuth, OmqMeshConfig, OmqPeerTransport, PeerAddr};
    use beldex_bridge_signer::evm_watcher::HttpJsonRpc;
    use beldex_bridge_signer::orchestrator::{Duty, EventSource, ExecOutcome};
    use beldex_bridge_signer::reconcile::{
        observe_reconciled, DualReconciler, DutyReconciler, EvmMintReconciler,
        GatewayReleaseReconciler, ObserveOutcome,
    };
    use beldex_bridge_signer::release_policy::{
        DescriptorUpdateView, DualPolicy, HandoverPolicy, ReleasePolicy, ReleaseProposal, RotatePolicy, RotationState,
    };
    use beldex_bridge_signer::transport::Leg;
    use beldex_bridge_signer::watch::ReleaseEvent;
    use beldex_bridge_signer::wire_auth::{LibsodiumEd25519, LibsodiumSigner};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    // Test-network settings: the signers' own, plus how this node settles each chain.
    let mut settings = test_network_settings();
    for c in configs.iter().filter(|c| c.depth_only_finality) {
        settings.push(format!("chain {} settles burns on depth alone (depth_only_finality)", c.chain_id));
    }
    if std::env::var("BRIDGE_SIGNER_BELDEX_CONFIRMATIONS").is_ok_and(|v| !v.trim().is_empty()) {
        settings.push("deposits settle on a confirmation count (BRIDGE_SIGNER_BELDEX_CONFIRMATIONS)".to_string());
    }
    // The rotation-ack wallet spends this node's funds. Without a login, anything that can
    // reach its port can spend them too.
    let nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let ack_wallet_login = match nonempty("BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE") {
        Some(p) => Some(beldex_bridge_signer::rpc_login::read_login_file(std::path::Path::new(p.trim()))?),
        None => None,
    };
    if nonempty("BRIDGE_SIGNER_ACK_WALLET_RPC").is_some() && ack_wallet_login.is_none() {
        settings.push(
            "rotation-ack wallet RPC without a login (BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE)".to_string(),
        );
    }
    enforce_network_policy(cfg, &settings)?;

    // The role: `live` (the default) serves the key the chains name, mints, releases and
    // cancels takeovers begun against it; `standby` serves a standby key, and only begins
    // and completes a takeover by it when this node sees the live key failing.
    let standby_role = std::env::var("BRIDGE_SIGNER_ROLE").is_ok_and(|r| r.trim() == "standby");

    // Run under a supervisor that restarts this process (share_watch): with no share set in
    // its directory (a node not on the current committee, a standby with none named yet)
    // it waits for one rather than exiting into a restart loop, and it remembers which set
    // it loaded, to restart when that set is replaced on disk.
    let share_dir = std::path::PathBuf::from(
        std::env::var("BRIDGE_SIGNER_SHARE_DIR").map_err(|_| "set BRIDGE_SIGNER_SHARE_DIR".to_string())?,
    );
    // A successor key that is live on both legs goes in before anything loads the shares.
    // (Live role only: a standby process's tree is its standby key, never the live successor.)
    let key_probe = LiveKeyProbe::new(
        configs,
        beldexd_rpc,
        &std::env::var("BRIDGE_SIGNER_RELEASE_GATEWAY").unwrap_or_else(|_| gateway_id.to_string()),
    );
    let status = StatusBoard::start(if standby_role { "serve-standby" } else { "serve" });
    if !standby_role {
        if let Some(m) = install_successor(&key_probe, &share_dir)? {
            println!("{m}");
            status.set("installed", m);
        }
    }
    if beldex_bridge_signer::share_watch::fingerprint(&share_dir).is_none() {
        println!("serve: no share set in {} yet: waiting for one", share_dir.display());
        // A standby signer with no key generates the next standby itself, when a standby round
        // draws it (BRIDGE_SIGNER_AUTO_DKG=0 turns this off).
        let auto_dkg = standby_role && !std::env::var("BRIDGE_SIGNER_AUTO_DKG").is_ok_and(|v| v.trim() == "0");
        if auto_dkg {
            println!("  standby key generation: automatic, when a standby round draws this node");
        }
        // A member joining at a hand-off has only its successor tree: it waits for that key to go
        // live on both legs instead of failing, and serves it from then on.
        if !standby_role {
            println!("  live role: waiting for this node's successor key to go live on both legs");
        }
        let mut auto = AutoStandbyDkg { last_round: 0, last_reason: String::new() };
        while beldex_bridge_signer::share_watch::fingerprint(&share_dir).is_none() {
            status.set("state", "no share set yet: waiting for one");
            // A standby DKG holds this loop for up to its timeout.
            status.beat(std::time::Duration::from_secs(if auto_dkg { 1200 } else { poll_secs.max(1) * 10 }));
            if !standby_role {
                if let Some(m) = install_successor(&key_probe, &share_dir)? {
                    println!("{m}");
                    status.set("installed", m);
                    continue;
                }
            }
            if auto_dkg {
                auto.maybe_run(cfg, &share_dir, beldexd_rpc);
            }
            std::thread::sleep(std::time::Duration::from_secs(15));
        }
        println!("serve: a share set appeared in {}", share_dir.display());
    }
    let loaded_share_set = beldex_bridge_signer::share_watch::fingerprint(&share_dir);

    let ls = Rc::new(build_live_signers(cfg)?);
    let committee = ls.committee.clone();
    status.set("state", "serving");
    status.set("key_epoch", ls.committee.epoch);
    status.set("self_index", ls.self_index);
    status.set("pgw", hex(&ls.pgw_group_vk));
    let self_index = ls.self_index;

    // --- Coordinator mesh: its own port range (the per-session sign meshes bind
    // port_base / port_base+pevm_offset per session; the coordinator's transport is
    // long-lived, so it gets a dedicated offset), CURVE + S4 auth from the committee.
    let coord_offset: u16 = std::env::var("BRIDGE_SIGNER_MESH_COORD_OFFSET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let base = ls.port_base + coord_offset;
    let peers: Vec<PeerAddr> = committee
        .peer_transport_indexed(self_index as usize, base)
        .into_iter()
        .map(|(index, endpoint, curve_pubkey)| PeerAddr {
            index,
            endpoint,
            curve_pubkey,
            signer_ed25519: committee
                .signer_keys
                .get(index as usize)
                .copied()
                .unwrap_or([0u8; 32]),
        })
        .collect();
    let mesh_cfg = OmqMeshConfig {
        self_index,
        listen_endpoint: format!("tcp://0.0.0.0:{}", base + self_index),
        use_curve: ls.use_curve,
        self_curve_secret: ls.curve_secret,
        self_curve_public: ls.curve_public,
        peers,
    };
    let auth = MeshAuth::from_committee(
        Box::new(LibsodiumSigner { sk64: ls.ed25519_secret }),
        Box::new(LibsodiumEd25519),
        &committee,
    )
    .ok_or("bridge.committee returned no signer_keys — cannot authenticate the coordinator mesh")?;
    // A port can still be held for a moment by the process this one replaces (just restarted
    // on a successor key, or a peer on the same host whose committee index this one now has),
    // so a bind that fails is tried again for two minutes before it counts.
    let mut bound = OmqPeerTransport::bind(&mesh_cfg);
    for _ in 0..24 {
        match &bound {
            Err(e) if format!("{e:?}").contains("in use") => {
                eprintln!("coordinator mesh port busy ({e:?}); trying again in 5s");
                std::thread::sleep(std::time::Duration::from_secs(5));
                bound = OmqPeerTransport::bind(&mesh_cfg);
            }
            _ => break,
        }
    }
    let mut net = bound.map_err(|e| format!("coordinator mesh bind: {e:?}"))?.with_auth(auth);

    // --- Policies. One shared daemon RPC client for build / inspect / submit (the loop is
    // single-threaded; the closures never call each other, so RefCell borrows never nest).
    let rpc = Rc::new(RefCell::new(HttpGatewayRpc::new(beldexd_rpc.to_string())));
    let contracts: BTreeMap<u64, [u8; 20]> = configs.iter().map(|c| (c.chain_id, c.contract)).collect();
    let release_gateway =
        std::env::var("BRIDGE_SIGNER_RELEASE_GATEWAY").unwrap_or_else(|_| gateway_id.to_string());
    // The release fee is the one each chain's contract declares: the contract only accepts
    // burns that exceed it, and every member builds and checks releases with exactly it,
    // so what the contract promised at burn time is what the committee pays. An unset or
    // unreadable fee is fatal rather than defaulted.
    let mut fees: BTreeMap<u64, u64> = BTreeMap::new();
    for c in configs {
        let fee = beldex_bridge_signer::reconcile::read_redemption_fee(
            &HttpJsonRpc::new(c.rpc_url.clone()),
            &c.contract,
        )
        .map_err(|e| format!("chain {}: {e}", c.chain_id))?;
        fees.insert(c.chain_id, fee);
    }
    // BRIDGE_SIGNER_RELEASE_FEE no longer chooses the fee; when set it must agree.
    if let Ok(v) = std::env::var("BRIDGE_SIGNER_RELEASE_FEE") {
        let expected: u64 = v.parse().map_err(|e| format!("BRIDGE_SIGNER_RELEASE_FEE: {e}"))?;
        if let Some((chain, fee)) = fees.iter().find(|(_, &f)| f != expected) {
            return Err(format!(
                "BRIDGE_SIGNER_RELEASE_FEE={expected} but chain {chain}'s contract declares {fee}"
            ));
        }
    }
    println!("  release fees from the contracts: {fees:?}");
    // Default to the native per-withdrawal maximum: consensus refuses anything larger.
    const GATEWAY_RELEASE_PER_TX_MAX: u128 = 50_000 * 1_000_000_000;
    let per_tx_cap: u128 = std::env::var("BRIDGE_SIGNER_RELEASE_PER_TX_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(GATEWAY_RELEASE_PER_TX_MAX)
        .min(GATEWAY_RELEASE_PER_TX_MAX);

    // --- H-06 / M-05: the economic invariants, from this node's own RPCs ---------------
    // Each contract must be the one configured (chain id, code, MINT_TAG, caps), its proxy
    // must point at the implementation this node pinned, the caps
    // this signer, the contracts and consensus describe must agree, the caps on all chains
    // together must fit under the slashable bond, and the wBDX in circulation must be
    // backed by the gateway's balance. The first three are fatal here; supply above the
    // reserve holds signing instead, so this node keeps observing and acknowledging
    // rotations (the way out of a compromised key) while it signs nothing.
    for (w, c) in src.evm.iter().zip(configs) {
        w.verify_contract(c.per_tx_max, c.per_epoch_cap)
            .map_err(|e| format!("refusing to serve: {e}"))?;
    }
    let solvency_check = {
        use beldex_bridge_signer::solvency::{check_configuration, check_solvency, read, ConfiguredCaps};
        let mut gateways = vec![gateway_id.to_string()];
        if release_gateway != gateway_id {
            gateways.push(release_gateway.clone()); // both hold bridge BDX
        }
        let daemon = HttpJsonRpc::new(format!("{}/json_rpc", beldexd_rpc.trim_end_matches('/')));
        let chains: Vec<(u64, HttpJsonRpc, [u8; 20])> =
            configs.iter().map(|c| (c.chain_id, HttpJsonRpc::new(c.rpc_url.clone()), c.contract)).collect();
        let configured: Vec<ConfiguredCaps> = configs
            .iter()
            .map(|c| ConfiguredCaps {
                chain_id: c.chain_id,
                per_tx_max: c.per_tx_max,
                per_epoch_cap: c.per_epoch_cap,
                implementation: c.implementation,
            })
            .collect();
        move || -> Result<(Vec<beldex_bridge_signer::solvency::Problem>, String), String> {
            // The balance before the supplies: see check_solvency.
            let mut native: Option<beldex_bridge_signer::solvency::NativeFigures> = None;
            for gw in &gateways {
                let n = read::native_figures(&daemon, gw)?;
                native = Some(match native {
                    None => n,
                    Some(mut acc) => {
                        acc.gateway_balance = acc.gateway_balance.saturating_add(n.gateway_balance);
                        acc
                    }
                });
            }
            let native = native.ok_or("no reserve gateway")?;
            let figures = chains
                .iter()
                .map(|(id, client, contract)| read::chain_figures(client, *id, contract))
                .collect::<Result<Vec<_>, _>>()?;
            let mut problems = check_configuration(&configured, &figures, &native);
            problems.extend(check_solvency(&figures, &native));
            let supply: u128 = figures.iter().map(|f| f.total_supply).sum();
            let exposure: u128 = figures.iter().map(|f| f.window_mint_cap.saturating_mul(2)).sum();
            let summary = format!(
                "wBDX supply {supply} / gateway reserve {}; two mint windows on every chain {exposure} / slashable backing {}",
                native.gateway_balance, native.slashable_backing
            );
            Ok((problems, summary))
        }
    };
    let mut solvency_guard = beldex_bridge_signer::solvency::SolvencyGuard::new();
    {
        use beldex_bridge_signer::solvency::Problem;
        let (first, summary) = solvency_check().map_err(|e| format!("refusing to serve: solvency check: {e}"))?;
        let fatal: Vec<String> =
            first.iter().filter(|p| !matches!(p, Problem::Insolvent { .. })).map(ToString::to_string).collect();
        if !fatal.is_empty() {
            return Err(format!("refusing to serve: {}", fatal.join("; ")));
        }
        solvency_guard.observe(&first);
        if !first.is_empty() {
            // One reading can be a race (a mint between the two reads); look again.
            std::thread::sleep(std::time::Duration::from_secs(5));
            if let Ok((again, _)) = solvency_check() {
                solvency_guard.observe(&again);
            }
        }
        println!("  solvency: {summary}");
        if let Some(why) = solvency_guard.hold() {
            eprintln!("!! SIGNING HELD from startup: {why}. Mints and releases wait until the supply is backed again.");
        }
    }

    // Leader-side release build: gateway_create_transfer + the HF23 replay-guard ref +
    // the disclosed tx key (verifiers open the stealth outputs with it).
    let build_rpc = rpc.clone();
    let build_gw = release_gateway.clone();
    let build_fees = fees.clone();
    let build_tx = move |ev: &ReleaseEvent| {
        let recipient = String::from_utf8(ev.beldex_recipient.clone())
            .map_err(|_| BuildError::Unactionable("burn recipient is not a utf-8 address".into()))?;
        let fee = *build_fees
            .get(&ev.chain.0)
            .ok_or_else(|| BuildError::Unactionable("no redemption fee for the burn's chain".into()))?;
        let amount = ev
            .amount
            .checked_sub(u128::from(fee))
            .filter(|a| *a > 0)
            .ok_or_else(|| BuildError::Unactionable("burn amount does not exceed the fee".into()))?;
        build_rpc
            .borrow_mut()
            .create_release(&build_gw, &recipient, amount, fee, ev.chain.0, &ev.evm_txid, ev.log_index)
            .map_err(|e| classify_release_build_error(ev, &recipient, e))
    };

    // Member-side inspection: this node's OWN daemon reads the proposed withdrawal.
    let insp_rpc = rpc.clone();
    let insp_gw = release_gateway.clone();
    let inspect = move |p: &ReleaseProposal, expected: &[u8]| {
        let addr = std::str::from_utf8(expected).map_err(|_| "recipient not utf-8".to_string())?;
        insp_rpc.borrow_mut().decode_withdrawal(p, addr, &insp_gw)
    };

    // The guard (takeover_guard): this node's own view of any standby takeover begun against
    // its key, shared by detection, the cancel policy and its reconciler.
    let takeover = Rc::new(TakeoverReader {
        evm: configs.iter().map(|c| (c.chain_id, HttpJsonRpc::new(c.rpc_url.clone()), c.contract)).collect(),
        gateway_rpc: HttpJsonRpc::new(format!("{}/json_rpc", beldexd_rpc.trim_end_matches('/'))),
        gateway: release_gateway.clone(),
        pevm_address: ls.pevm_address,
        pgw_group_vk: ls.pgw_group_vk,
        standby_role,
        outage: std::cell::Cell::new(false),
    });
    let policy_view = takeover.clone();
    // Key hand-offs: each member reads the contract's rotation state from its own RPC, the
    // clock included, so the deadline it accepts is the chain's and not its own.
    let rotation_rpcs: BTreeMap<u64, (HttpJsonRpc, [u8; 20])> =
        configs.iter().map(|c| (c.chain_id, (HttpJsonRpc::new(c.rpc_url.clone()), c.contract))).collect();
    let read_rotation = move |chain_id: u64| -> Result<RotationState, String> {
        let (client, contract) = rotation_rpcs.get(&chain_id).ok_or("no RPC for that chain")?;
        read_rotation_state(client, contract)
    };
    // How long a signed rotateSigner stays valid on chain. Long enough to be relayed, short
    // enough that an authorization nobody sent cannot be dug out later.
    let rotation_valid_secs: u64 =
        std::env::var("BRIDGE_SIGNER_ROTATION_VALID_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(6 * 3600);

    // The gateway hand-over: the leader asks the hand-over submitter (whose wallet builds and
    // pays for it) for the unsigned update; every member reads it with its own daemon.
    let handover_builder = std::env::var("BRIDGE_SIGNER_HANDOVER_BUILDER").ok().filter(|s| !s.trim().is_empty());
    match &handover_builder {
        Some(u) => println!("  gateway hand-over: built by {u}, checked on this node's daemon"),
        None => println!("  gateway hand-over: no BRIDGE_SIGNER_HANDOVER_BUILDER, so this node leads none"),
    }
    let fetch_handover = move |owner: &[u8; 32]| -> Result<Vec<u8>, String> {
        let base = handover_builder.as_deref().ok_or("no BRIDGE_SIGNER_HANDOVER_BUILDER")?;
        let v: serde_json::Value = beldex_bridge_signer::http_agent()
            .get(&format!("{}/build?owner={}", base.trim_end_matches('/'), hex(owner)))
            .call()
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())?;
        let blob = v.get("tx_blob").and_then(|b| b.as_str()).ok_or(format!("no tx_blob in {v}"))?;
        (0..blob.len()).step_by(2).map(|i| blob.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect::<Option<Vec<u8>>>().ok_or("tx_blob: not hex".into())
    };
    let decode_rpc = HttpJsonRpc::new(format!("{}/json_rpc", beldexd_rpc.trim_end_matches('/')));
    let decode_handover = move |blob: &[u8]| -> Result<DescriptorUpdateView, String> {
        use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
        let r = decode_rpc
            .call("gateway_decode_descriptor_update", serde_json::json!({ "tx_blob": hex(blob) }))
            .map_err(|e| format!("{e:?}"))?;
        let field = |k: &str| r.get(k).and_then(|v| v.as_str()).ok_or(format!("no {k} in {r}"));
        let bytes = |k: &str| -> Result<Vec<u8>, String> {
            let h = field(k)?;
            (0..h.len()).step_by(2).map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect::<Option<_>>().ok_or(format!("{k}: not hex"))
        };
        Ok(DescriptorUpdateView {
            gateway_id: bytes("gateway_id")?.try_into().map_err(|_| "gateway_id: not 32 bytes")?,
            owner_key_type: field("owner_key_type")?.to_string(),
            owner_key: bytes("owner_key")?,
            bridge_reserve: r.get("bridge_reserve").and_then(|v| v.as_bool()).unwrap_or(false),
            // A daemon that does not say is taken to name one: nothing it cannot vouch for is signed.
            has_standby: r
                .get("has_standby")
                .and_then(|v| v.as_bool().or_else(|| v.as_u64().map(|n| n != 0)))
                .unwrap_or(true),
            hash_to_sign: bytes("hash_to_sign")?.try_into().map_err(|_| "hash_to_sign: not 32 bytes")?,
        })
    };
    let reserve_gateway: [u8; 32] = config::parse_hex32(&release_gateway).unwrap_or([0u8; 32]);

    let policy = DualPolicy {
        cancel: beldex_bridge_signer::takeover_guard::TakeoverPolicy {
            read: move |c: &beldex_bridge_signer::watch::TakeoverStep| policy_view.view(c),
        },
        mint: MintPolicy { contracts: contracts.clone() },
        release: ReleasePolicy {
            build_tx,
            inspect,
            release_gateway: release_gateway.clone(),
            fees,
            per_tx_cap,
        },
        rotate: RotatePolicy { read: read_rotation, contracts: contracts.clone(), valid_secs: rotation_valid_secs },
        handover: HandoverPolicy { fetch: fetch_handover, decode: decode_handover, gateway_id: reserve_gateway },
    };

    // --- The per-duty threshold signers: one mesh round per duty among the session's
    // canonical ACK set (only members that independently verified the payload — C.5),
    // namespaced by the session attempt so a retry never ingests stale frames.
    let sign_ls = ls.clone();
    let sign = move |leg: Leg, message: &[u8], signers: &[u16], attempt: u32| -> Result<Vec<u8>, String> {
        println!("  signing {leg:?} round: participants {signers:?} attempt {attempt}");
        match leg {
            Leg::Pevm => sign_ls.pevm_sign(message, signers, attempt).map(|s| s.to_vec()),
            Leg::Pgw => {
                let m: [u8; 32] =
                    message.try_into().map_err(|_| "Pgw signing message must be 32 bytes".to_string())?;
                sign_ls.pgw_sign(&m, signers, attempt).map(|s| s.to_vec())
            }
        }
    };

    // --- Completion: emit the mint relayer payload / self-submit the release.
    //
    // Mint hand-off. The signer holds no EVM gas key by design, so it does not broadcast:
    // it produces the signed payload and hands it off. Two mechanisms, in order:
    //
    //   1. `BRIDGE_SIGNER_RELAY_CMD` — spawn that command and write the payload JSON to its
    //      stdin (e.g. `beldex-bridge-relayer relay -`). The gas key lives in *that*
    //      process's environment, never here.
    //   2. Always: print `MINT-PAYLOAD <json>`, which anyone can broadcast by hand with
    //      `relay -` or `prepare` + `cast send`.
    //
    // Before either, the payload is saved to the mint outbox (`BRIDGE_SIGNER_MINT_OUTBOX`),
    // and a sweep re-delivers it until `processedDeposits` shows it minted. That record,
    // not the log line, is what keeps a missed hand-off from stranding the deposit.
    //
    // Broadcast failure therefore does NOT fail the duty: re-running a whole mesh signing
    // round to retry an HTTP call would be the wrong layer, and the saved payload is
    // re-delivered anyway. Failures are logged loudly instead.
    //
    // Enabling the hook on several nodes is safe but not free: a *late* duplicate costs
    // nothing (gas estimation catches `Replay()` before broadcasting), while *simultaneous*
    // duplicates all pass estimation and all but one revert on-chain, burning gas. Set
    // `BRIDGE_SIGNER_RELAY_STAGGER_MS` (multiplied by this node's committee index) so
    // configured relayers fire in sequence rather than at once. Each needs its own gas key —
    // a shared key means colliding nonces.
    // Preferred hand-off: publish to the daemon's mint bus (`bridge.mint_payload`), which
    // fans out to every subscribed relayer. Relayers then need no signer-host access at all.
    // The daemon dedups by beldex_txid, so all t+1 members publishing is expected and only
    // one fan-out occurs. Off by default only because it needs the OMQ endpoint.
    let publish_bus = std::env::var("BRIDGE_SIGNER_PUBLISH_MINT_BUS")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(true);
    // The daemon accepts a publication only from a seated committee member, so we sign each
    // one with this node's `signer_ed25519` — the same key the mesh authenticates with, and
    // the one consensus records for our committee index.
    let bus_genesis: [u8; 32] = match std::env::var("BRIDGE_SIGNER_GENESIS_HASH") {
        Ok(h) => config::parse_hex32(&h).unwrap_or([0u8; 32]),
        Err(_) => [0u8; 32],
    };
    // Where to publish. Default: this node's own daemon — correct when relayers subscribe
    // broadly. But a publisher→own-daemon / subscriber→one-daemon topology only intersects
    // by luck (found live: the one subscribed daemon's signer was a straggler that round,
    // so every fan-out happened where nobody listened). BRIDGE_SIGNER_MINT_BUS_ENDPOINT
    // points all signers at a common bus daemon; publishing is signature-authenticated,
    // not socket-authenticated, so a remote daemon works fine.
    let bus_endpoint = std::env::var("BRIDGE_SIGNER_MINT_BUS_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| cfg.oxenmq_endpoint.clone());
    let activation_bus = bus_endpoint.clone();
    let bus_client: Vec<_> = if publish_bus {
        println!("  mint hand-off: publishing to bridge.mint_payload at {bus_endpoint}");
        if bus_genesis == [0u8; 32] {
            println!("    WARNING: no BRIDGE_SIGNER_GENESIS_HASH — publications will not verify \
                      against a daemon that binds a real genesis");
        }
        bus_endpoints(&bus_endpoint)
            .into_iter()
            .map(|e| (e.clone(), beldex_bridge_signer::omq_client::OmqCommitteeClient::new(e)))
            .collect()
    } else {
        Vec::new()
    };
    let bus_sign_key = ls.ed25519_secret;
    // Named in every publication, so the daemon can authenticate a member of a committee
    // it has since moved past with one lookup and one signature check.
    let bus_master_node = ls.committee.members[ls.self_index as usize];

    // Where signed releases are kept until they are known to have landed. A release that
    // cannot be re-sent is a payout that can go missing silently.
    let release_outbox_dir = std::env::var("BRIDGE_SIGNER_RELEASE_OUTBOX")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "releases".to_string());
    println!("  signed releases kept in: {release_outbox_dir}");
    // The completion closure takes ownership; the retry sweep needs its own handle.
    let outbox_dir_for_sweep = release_outbox_dir.clone();
    // The sweep's own reconciler: the outbox holds raw records, not duties, so it needs a
    // way to ask consensus "is this burn discharged?" independently of the duty pipeline.
    let mut sweep_reconciler =
        GatewayReleaseReconciler::new(beldexd_rpc.to_string(), release_gateway.clone());
    // A stored record carries only what identifies the burn; `is_settled` looks at the
    // chain, tx id and log index alone, so the remaining fields are immaterial here.
    let rec_duty = |rec: &beldex_bridge_signer::release_outbox::ReleaseRecord| {
        let mut evm_txid = [0u8; 32];
        if let Some(b) = config::parse_hex32(&rec.evm_txid) {
            evm_txid = b;
        }
        Duty::Release(beldex_bridge_signer::watch::ReleaseEvent {
            evm_txid,
            log_index: rec.log_index,
            chain: beldex_bridge_signer::chain_registry::ChainId(rec.chain_id),
            amount: 0,
            beldex_recipient: Vec::new(),
        })
    };

    let relay_cmd = std::env::var("BRIDGE_SIGNER_RELAY_CMD").ok().filter(|s| !s.trim().is_empty());
    let relay_stagger_ms: u64 = std::env::var("BRIDGE_SIGNER_RELAY_STAGGER_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    match &relay_cmd {
        Some(c) => println!("  mint hand-off: piping payloads to `{c}` (stagger {}ms)", relay_stagger_ms * self_index as u64),
        None => println!("  mint hand-off: log only (set BRIDGE_SIGNER_RELAY_CMD to auto-broadcast)"),
    }
    // Takeover cancels on wBDX go through the same relay command as mints; on the gateway,
    // through the rotation-ack wallet (gateway_takeover_cancel).
    let cancel_relay_cmd = relay_cmd.clone();
    let cancel_wallet = std::env::var("BRIDGE_SIGNER_ACK_WALLET_RPC")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|url| match &ack_wallet_login {
            Some(login) => HttpJsonRpc::new(url).with_basic_auth(login),
            None => HttpJsonRpc::new(url),
        });
    let cancel_gateway = release_gateway.clone();
    let mint_handoff = Rc::new(MintHandoff {
        bus: bus_client,
        bus_genesis,
        bus_sign_key,
        bus_master_node,
        self_index,
        relay_cmd,
        relay_stagger_ms,
    });
    let handoff_for_sweep = Rc::clone(&mint_handoff);

    // Where signed mints are kept until `processedDeposits` shows them minted. The hand-off
    // above is fire-and-forget; this is what makes a missed one recoverable without a
    // person reading logs.
    let mint_outbox_dir = std::env::var("BRIDGE_SIGNER_MINT_OUTBOX")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "mints".to_string());
    println!("  signed mints kept in: {mint_outbox_dir}");
    let mint_outbox_for_sweep = mint_outbox_dir.clone();

    let done_rpc = rpc.clone();
    let done_contracts_for_rotation = contracts.clone();
    let done_contracts = contracts;
    let done_view = takeover.clone();
    let done_pgw_vk = ls.pgw_group_vk;
    let complete = move |d: &Duty, proposal: &[u8], sig: &[u8]| -> ExecOutcome {
        match d {
            Duty::Takeover(c) if c.on_gateway() => {
                use beldex_bridge_signer::watch::TakeoverStepKind;
                if sig.len() != 64 {
                    return ExecOutcome::Retry;
                }
                let action = match c.step {
                    TakeoverStepKind::Cancel => "cancel",
                    TakeoverStepKind::Begin => "begin",
                    TakeoverStepKind::Complete => "complete",
                    TakeoverStepKind::NameStandby => "name_standby",
                    TakeoverStepKind::StandbyAlive => "standby_alive",
                };
                // The key named: the candidate of the committee this duty was for. If the daemon
                // now gives another, the signature is for a key no longer wanted.
                let named = if c.step == TakeoverStepKind::NameStandby {
                    match done_view.standby_target() {
                        Some(cand) if cand.committee_height == c.key_epoch => Some(cand.pgw_vk),
                        _ => {
                            eprintln!("  standby naming on the gateway: the candidate changed; not submitted");
                            return ExecOutcome::Retry;
                        }
                    }
                } else {
                    None
                };
                println!(
                    "TAKEOVER-{} gateway={cancel_gateway} started_height={} signature={}",
                    action.to_uppercase(),
                    c.takeover_id,
                    hex(sig)
                );
                let Some(wallet) = &cancel_wallet else {
                    eprintln!(
                        "!! no wallet RPC (BRIDGE_SIGNER_ACK_WALLET_RPC) to carry the gateway takeover \
                         {action}: submit the line above with the wallet RPC gateway_takeover_step NOW"
                    );
                    return ExecOutcome::Submitted;
                };
                use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
                let mut params = serde_json::json!({
                    "gateway_id": cancel_gateway,
                    "action": action,
                    "started_height": c.takeover_id,
                    "signature": hex(sig),
                    "signature_type": "eddsa",
                });
                if c.step == TakeoverStepKind::Complete || c.step == TakeoverStepKind::StandbyAlive {
                    params["new_owner_key"] = serde_json::json!(hex(&done_pgw_vk));
                    params["new_owner_key_type"] = serde_json::json!("eddsa");
                }
                if let Some(vk) = named {
                    params["new_owner_key"] = serde_json::json!(hex(&vk));
                    params["new_owner_key_type"] = serde_json::json!("eddsa");
                }
                match wallet.call("gateway_takeover_step", params) {
                    Ok(r) => {
                        println!("TAKEOVER {} submitted on the gateway: {}", action.to_uppercase(), r.get("tx_hash").cloned().unwrap_or_default());
                        ExecOutcome::Submitted
                    }
                    // Another member's wallet got there first (the pool keeps one per step),
                    // or the chain has moved past this step: either way, done.
                    Err(e) if {
                        let m = format!("{e:?}").to_lowercase();
                        m.contains("double spend") || m.contains("same subject")
                            || matches!(done_view.view(c), Ok(beldex_bridge_signer::takeover_guard::TakeoverView::Ended))
                    } => {
                        println!("TAKEOVER {} on the gateway already submitted or no longer needed (ok): {e:?}", action.to_uppercase());
                        ExecOutcome::Submitted
                    }
                    Err(e) => {
                        eprintln!("gateway takeover {action} not submitted (will retry): {e:?}");
                        ExecOutcome::Retry
                    }
                }
            }
            Duty::Takeover(c) => {
                use beldex_bridge_signer::watch::TakeoverStepKind;
                let Some(&contract) = done_contracts.get(&c.chain_id) else {
                    return ExecOutcome::Abandon;
                };
                let kind = match c.step {
                    TakeoverStepKind::Cancel => "takeover_cancel",
                    TakeoverStepKind::Begin => "takeover_begin",
                    TakeoverStepKind::Complete => "takeover_complete",
                    TakeoverStepKind::NameStandby => "set_standby",
                    TakeoverStepKind::StandbyAlive => return ExecOutcome::Abandon, // gateway only
                };
                let payload = if c.step == TakeoverStepKind::NameStandby {
                    // The standby, nonce and deadline are in what was signed.
                    let Some((standby, nonce, deadline)) =
                        beldex_bridge_signer::takeover_guard::evm_set_standby_fields(proposal)
                    else {
                        return ExecOutcome::Abandon;
                    };
                    format!(
                        r#"{{"kind":"set_standby","contract":"{}","chain_id":{},"standby":"{}","nonce":{nonce},"deadline":"{deadline}","sig":"{}"}}"#,
                        hex(&contract),
                        c.chain_id,
                        hex(&standby),
                        hex(sig)
                    )
                } else {
                    format!(
                        r#"{{"kind":"{kind}","contract":"{}","chain_id":{},"sig":"{}"}}"#,
                        hex(&contract),
                        c.chain_id,
                        hex(sig)
                    )
                };
                println!("TAKEOVER-STEP-PAYLOAD {payload}");
                // On the bus too, as mints and hand-offs are: the runner's relayer (relay-watch)
                // pays EVM gas, and the signers need hold no gas key of their own.
                mint_handoff.publish(&payload);
                match &cancel_relay_cmd {
                    Some(cmd) => match pipe_to_relay(cmd, &payload) {
                        Ok(out) => {
                            println!("  {kind} relayed: {}", out.trim());
                            ExecOutcome::Submitted
                        }
                        // The contract refused it because the chain has moved past this step
                        // (another member's landed first, or the takeover ended): done.
                        Err(e) if matches!(done_view.view(c), Ok(beldex_bridge_signer::takeover_guard::TakeoverView::Ended)) => {
                            println!("  {kind} not needed any more on chain {} ({})", c.chain_id, e.lines().last().unwrap_or_default());
                            ExecOutcome::Submitted
                        }
                        // Re-signing is cheap next to missing the window: try again.
                        Err(e) => {
                            eprintln!("  {kind} RELAY FAILED ({e}); will sign and relay again");
                            ExecOutcome::Retry
                        }
                    },
                    None => {
                        println!(
                            "  {kind} published for the relayer (no BRIDGE_SIGNER_RELAY_CMD here); signed \
                             again if it is still wanted once it should have landed"
                        );
                        ExecOutcome::Submitted
                    }
                }
            }
            Duty::Mint(ev) => {
                let Some(&contract) = done_contracts.get(&ev.dst_chain.0) else {
                    return ExecOutcome::Abandon;
                };
                let payload = mint_relay_payload_json(ev, contract, sig);
                // Print first: the payload must survive even if every hand-off below fails.
                println!("MINT-PAYLOAD {payload}");
                // Keep it BEFORE handing it off. Nothing re-runs a completed duty, so a
                // hand-off that misses with no saved copy strands the deposit until a person
                // finds the log line above.
                let record = beldex_bridge_signer::mint_outbox::MintRecord {
                    chain_id: ev.dst_chain.0,
                    beldex_txid: hex(&ev.beldex_txid),
                    output_index: ev.output_index,
                    payload: payload.clone(),
                    first_seen: beldex_bridge_signer::release_outbox::now_secs(),
                    last_attempt: beldex_bridge_signer::release_outbox::now_secs(),
                    attempts: 1,
                    warned: false,
                    gave_up: false,
                };
                match beldex_bridge_signer::mint_outbox::save(&mint_outbox_dir, &record) {
                    Ok(path) => println!("  mint saved for re-delivery: {}", path.display()),
                    Err(e) => {
                        // Same rule as releases: never hand off what could not be re-sent.
                        // A retry costs a signing round; the contract's replay guard makes
                        // a second signature for this deposit harmless.
                        eprintln!("  mint outbox write failed ({e}); not handing off yet");
                        return ExecOutcome::Retry;
                    }
                }
                mint_handoff.deliver(&payload);
                ExecOutcome::Submitted
            }
            // The outgoing committee's rotateSigner, for a relayer to send like a mint. The
            // nonce and deadline are the ones in the accepted proposal.
            Duty::Rotate(r) => {
                let word = |i: usize| u64::from_be_bytes(proposal[i * 32 + 24..i * 32 + 32].try_into().expect("8 bytes"));
                if proposal.len() != 7 * 32 || sig.len() != 65 {
                    return ExecOutcome::Abandon;
                }
                let payload = format!(
                    r#"{{"kind":"rotate","contract":"{}","chain_id":{},"new_signer":"{}","new_key_epoch":{},"nonce":{},"deadline":"{}","sig":"{}"}}"#,
                    hex(&r.contract),
                    r.chain_id,
                    hex(&r.new_signer),
                    r.new_key_epoch,
                    word(5),
                    word(6),
                    hex(sig)
                );
                println!("ROTATE-PAYLOAD {payload}");
                mint_handoff.deliver(&payload);
                ExecOutcome::Submitted
            }
            // The outgoing committee's owner signature on the gateway hand-over, for the
            // submitter whose wallet built it (bus only: no EVM relayer carries it).
            Duty::Handover(h) => {
                if sig.len() != 64 || proposal.len() <= 32 {
                    return ExecOutcome::Abandon;
                }
                let payload = format!(
                    r#"{{"kind":"handover","gateway_id":"{}","owner":"{}","key_epoch":{},"hash_to_sign":"{}","sig":"{}"}}"#,
                    hex(&h.gateway_id),
                    hex(&h.new_owner),
                    h.key_epoch,
                    hex(&proposal[..32]),
                    hex(sig)
                );
                println!("HANDOVER-PAYLOAD {payload}");
                mint_handoff.publish(&payload);
                ExecOutcome::Submitted
            }
            Duty::Release(_) => {
                let Some(p) = ReleaseProposal::decode(proposal) else {
                    return ExecOutcome::Abandon; // cannot happen for an accepted proposal
                };
                if sig.len() != 64 {
                    return ExecOutcome::Retry;
                }
                let mut s64 = [0u8; 64];
                s64.copy_from_slice(sig);
                let blob_hex: String = p.unsigned_tx_blob.iter().map(|b| format!("{b:02x}")).collect();
                let sig_hex: String = s64.iter().map(|b| format!("{b:02x}")).collect();
                let evm_txid_hex: String = p.evm_txid.iter().map(|b| format!("{b:02x}")).collect();

                // Keep the signed bytes BEFORE submitting. Acceptance into a mempool is not
                // inclusion in a block: a fee spike can evict this, and without a saved copy
                // nothing could ever re-send it — the user's wBDX is already destroyed.
                let record = beldex_bridge_signer::release_outbox::ReleaseRecord {
                    txid: hex(&p.hash_to_sign),
                    tx_blob: blob_hex.clone(),
                    signature: sig_hex,
                    chain_id: p.chain_id,
                    evm_txid: evm_txid_hex,
                    log_index: p.log_index,
                    first_seen: beldex_bridge_signer::release_outbox::now_secs(),
                    attempts: 1,
                    warned: false,
                };
                match beldex_bridge_signer::release_outbox::save(&release_outbox_dir, &record) {
                    Ok(path) => println!("  release saved for re-send: {}", path.display()),
                    Err(e) => {
                        // Submitting something we cannot re-send is how a payout goes
                        // missing silently. Retry rather than proceed blind.
                        eprintln!("  release outbox write failed ({e}); not submitting yet");
                        return ExecOutcome::Retry;
                    }
                }

                match done_rpc.borrow_mut().submit_transfer(&blob_hex, &s64) {
                    Ok(txid) => {
                        println!("RELEASE submitted: {txid}");
                        ExecOutcome::Submitted
                    }
                    Err(e) => {
                        // Every finalizing node submits the SAME signed tx; only the first
                        // lands, and the daemon reports the rest as duplicates / replays.
                        // That is success, not failure — retrying would reopen a session
                        // for a settled burn and churn against the consensus replay guard.
                        let el = e.to_lowercase();
                        if el.contains("already") || el.contains("replay") || el.contains("discharged")
                        {
                            println!("RELEASE already submitted by a peer (ok): {e}");
                            ExecOutcome::Submitted
                        } else {
                            eprintln!("release submit failed (will retry): {e}");
                            ExecOutcome::Retry
                        }
                    }
                }
            }
        }
    };

    // Aggregates — this node's own and any a peer announces — are checked against the group
    // keys loaded from this node's shares before they are stored or submitted.
    let verifier = beldex_bridge_signer::aggregate_signature::AggregateVerifier {
        pevm_address: ls.pevm_address()?,
        pgw_group_vk: ls.pgw_group_vk,
    };
    let mut coord = Coordinator::new(
        committee,
        self_index,
        policy,
        move |leg, message, signature| verifier.verify(leg, message, signature),
        sign,
        complete,
    );
    if let Some(t) = std::env::var("BRIDGE_SIGNER_STAGE_TIMEOUT_TICKS").ok().and_then(|s| s.parse().ok()) {
        coord.stage_timeout_ticks = t;
    }
    coord.hold = solvency_guard.hold().map(str::to_string);
    // TARGET_BLOCK_TIME in the daemon's cryptonote_config.h.
    const BLOCK_SECS: u64 = 30;
    let open_every_blocks = OpenGate::blocks_for(coord.committee.size(), coord.committee.threshold, coord.stage_timeout_ticks, poll_secs, BLOCK_SECS);
    coord.open_gate = Some(OpenGate::new(open_every_blocks));

    println!("serve: LIVE COORDINATED mode — per-duty sessions over the authenticated mesh");
    println!("  committee epoch {} size {} threshold {}; self_index {self_index}", coord.committee.epoch, coord.committee.size(), coord.committee.threshold);
    println!("  coordinator mesh on port base {base}; polling every {poll_secs}s across {} EVM chain(s)", configs.len());
    println!("  sessions open together, every {open_every_blocks} blocks");

    // On-chain reconciliation: a restarted signer must not re-work settled duties. Each
    // newly observed duty is checked once (mints: processedDeposits; releases: the daemon's
    // release-ref set); an undeterminable answer leaves it unregistered so a later poll
    // retries. Disable with BRIDGE_SIGNER_RECONCILE=0 (then every duty is worked).
    let reconcile_on =
        std::env::var("BRIDGE_SIGNER_RECONCILE").map(|v| v != "0" && v != "false").unwrap_or(true);
    let reconcile_view = takeover.clone();
    let mut reconciler = DualReconciler {
        cancel: beldex_bridge_signer::takeover_guard::TakeoverReconciler {
            read: move |c: &beldex_bridge_signer::watch::TakeoverStep| reconcile_view.view(c),
        },
        // Per-chain client + contract, so a multi-chain deployment queries the right chain.
        mint: EvmMintReconciler {
            chains: configs
                .iter()
                .map(|c| (c.chain_id, (HttpJsonRpc::new(c.rpc_url.clone()), c.contract)))
                .collect(),
        },
        release: GatewayReleaseReconciler::new(beldexd_rpc.to_string(), release_gateway.clone()),
    };
    if !reconcile_on {
        println!("  reconciliation DISABLED (BRIDGE_SIGNER_RECONCILE=0)");
    }

    // The committee this process was built against. It is read once at startup — the
    // shares, the mesh identities and the signer indices all derive from it — and it is
    // the committee that holds this share dir's key (`load_key_committee`), not whichever
    // one consensus has selected since. Consensus moving on does not retire that key: it
    // stays live, and signable only by its own holders, until the rotation replacing it
    // lands — and the outgoing committee is who has to keep the bridge running until then.
    // So a new committee is only reported. What stops this node taking new work is its key
    // being replaced on chain, per leg: the wBDX signer (per chain) and the gateway owner
    // are handed over by separate transactions. In-flight work still finishes, and the node
    // is restarted on the successor shares.
    let started_with = ls.committee.membership_bytes();
    let committee_probe = beldex_bridge_signer::omq_client::OmqCommitteeClient::new(
        cfg.oxenmq_endpoint.clone(),
    );
    let mut committee_changed = false;
    // (chain, client, contract, confirmations, depth_only_finality): the signer is read at
    // the same point the watcher treats as settled — the chain's finalized block, or on a
    // depth-only test chain `confirmations` below the tip.
    let key_probe_evm: Vec<(u64, HttpJsonRpc, [u8; 20], u64, bool)> = configs
        .iter()
        .map(|c| (c.chain_id, HttpJsonRpc::new(c.rpc_url.clone()), c.contract, c.confirmations, c.depth_only_finality))
        .collect();
    let key_probe_gw = HttpJsonRpc::new(format!("{}/json_rpc", beldexd_rpc.trim_end_matches('/')));
    let mut mint_key_replaced: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    // The key each replaced chain's wBDX now answers to (see the gateway hand-over below).
    let mut replaced_by: BTreeMap<u64, [u8; 20]> = BTreeMap::new();
    let mut release_key_replaced = false;
    // A key that differs from the contract's before this process ever saw it live is not
    // replaced but incoming: promoted and restarted while the change that names it (a
    // rotation's activation, a standby takeover) is still short of the probe's depth. Its
    // mints are held, not dropped, until the contract answers with this key.
    let mut mint_key_live: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut mint_key_incoming: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut held_mints: Vec<beldex_bridge_signer::watch::MintEvent> = Vec::new();
    // When each chain's key was first seen incoming, and when that was last reported. A key
    // promoted for a change that never lands (a takeover cancelled after the shares were
    // swapped) would otherwise hold its deposits silently for ever.
    let mut incoming_since: BTreeMap<u64, (std::time::Instant, std::time::Instant)> = BTreeMap::new();
    const HELD_REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(600);
    // Whether each chain (and the gateway, as chain 0) was last seen naming no standby. Without
    // one, a mass loss of this key's holders halts the bridge until governance steps in.
    let mut no_standby: BTreeMap<u64, bool> = BTreeMap::new();

    // H.6.3 rotation acknowledgements. Each member observes a wBDX key change on its own
    // RPC, signs the fact, and shares that signature over the mesh; once threshold-many
    // agree, any member may submit the evidence. Until L1 sees it, `observed_key_epoch`
    // never advances and a departed member's bond stays locked forever.
    let mut ack_collector = beldex_bridge_signer::rotation_ack::RotationAckCollector::for_round(ls.committee.round_height);
    if bus_genesis == [0u8; 32] {
        println!("  rotation acks DISABLED: BRIDGE_SIGNER_GENESIS_HASH is unset, and the \
                  acknowledgement is genesis-bound");
    }
    // Completed acknowledgements, retried until L1's observed key epoch shows them. Handing
    // one to the daemon is not the end: it still has to be paid for and mined, and until it
    // is, departing members' bonds stay locked. With a wallet RPC configured
    // (BRIDGE_SIGNER_ACK_WALLET_RPC, e.g. http://127.0.0.1:19092/json_rpc, a local wallet
    // RPC, logged in to with BRIDGE_SIGNER_ACK_WALLET_LOGIN_FILE), this node pays for it
    // itself. The mempool keeps
    // one per (chain, key epoch), so several members doing so pays only once.
    let mut ack_submissions = beldex_bridge_signer::rotation_ack::AckSubmissions::new();
    let ack_wallet = std::env::var("BRIDGE_SIGNER_ACK_WALLET_RPC")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|url| match &ack_wallet_login {
            Some(login) => HttpJsonRpc::new(url).with_basic_auth(login),
            None => HttpJsonRpc::new(url),
        });
    match &ack_wallet {
        Some(_) => println!("  rotation acks: submitted and paid for by the configured wallet RPC"),
        None => println!(
            "  rotation acks: no wallet RPC (BRIDGE_SIGNER_ACK_WALLET_RPC); each one is printed, to be \
             submitted by hand"
        ),
    }
    // The fee wallet reported low below this many atomic units (default 5 BDX): its balance and
    // address are on /status, so whoever tops the seats' wallets up knows where and when.
    let fee_wallet_low: u64 = std::env::var("BRIDGE_SIGNER_WALLET_LOW")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(5_000_000_000);
    let mut fee_wallet_address: Option<String> = None;
    // L1's observed key epoch per chain, refreshed with the ack sweep.
    let mut l1_observed: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();

    // Re-send pacing in loop ticks. A Beldex block is ~30s, so re-sending every tick
    // would repeat before a block could even exist.
    // Look at the mint outbox about once a minute; each record's own `due` paces its
    // re-delivery, so this only bounds how late past its interval it goes out.
    let mint_retry_ticks = std::cmp::max(1, 60 / poll_secs.max(1));
    let release_retry_ticks =
        std::cmp::max(1, beldex_bridge_signer::release_outbox::RETRY_INTERVAL_SECS / poll_secs.max(1));
    // Re-check queued duties against the chain about once a minute: often enough that a
    // member which missed a completion stops within a round or two, rare enough that it is
    // one extra RPC per duty per minute rather than per tick.
    let reconcile_recheck_ticks = std::cmp::max(1, 60 / poll_secs.max(1));
    // The rotation-ack sweep: about once a minute.
    let ack_sweep_ticks = std::cmp::max(1, 60 / poll_secs.max(1));
    // This node's attestation that its committee generated the key it serves: consensus
    // names a standby only between keys whose committees it knows. Sent once, by each
    // member, whichever role it serves; re-sent if not counted after a while (a dropped
    // tx), and never once the key is attested.
    let mut attest_next_at: u64 = 0;
    let mut attest_done = bus_genesis == [0u8; 32];
    if attest_done {
        println!("  key attestation DISABLED: BRIDGE_SIGNER_GENESIS_HASH is unset, and the attestation is genesis-bound");
    }
    // The solvency check (H-06): about once a minute unless configured.
    let solvency_secs: u64 = std::env::var("BRIDGE_SIGNER_SOLVENCY_CHECK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let solvency_ticks = std::cmp::max(1, solvency_secs / poll_secs.max(1));

    // --- H-04: resume each chain where it was fully handled --------------------------
    // A cursor is trusted only if the chain still has the block it names (see watch_cursor).
    // Without one, or with one that does not match, the watchers start from their
    // configured heights, as before.
    let cursor_dir: Option<std::path::PathBuf> = match std::env::var("BRIDGE_SIGNER_WATCH_CURSOR_DIR") {
        Ok(v) if v.trim() == "off" => None,
        Ok(v) if !v.trim().is_empty() => Some(v.trim().into()),
        // A standby process on the same node keeps its own: it must never move the live
        // process's cursors.
        _ => Some(if standby_role { "watch-cursors-standby" } else { "watch-cursors" }.into()),
    };
    let beldex_identity = format!("beldex gateway {gateway_id}");
    let evm_identity = |c: &beldex_bridge_signer::evm_watcher::EvmChainConfig| {
        format!("evm chain {} contract {}", c.chain_id, hex(&c.contract))
    };
    // The key each cursor's progress was made under: the mint key for deposits, the gateway
    // owner key for burns. After a key change, a cursor saved under the old one is not
    // resumed from but rescanned behind (see watch_cursor), so work the old key signed and
    // that never landed is seen, and signed, again. The windows default to the mint
    // outbox's give-up time: a week of blocks.
    let beldex_key = hex(&ls.pevm_address);
    let evm_key = hex(&ls.pgw_group_vk);
    let env_u64 = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(d);
    let beldex_rekey_window = env_u64("BRIDGE_SIGNER_REKEY_RESCAN_BLOCKS", 20_160);
    let evm_rekey_window = env_u64("BRIDGE_SIGNER_EVM_REKEY_RESCAN_BLOCKS", 50_400);
    let beldex_start = env_u64("BRIDGE_SIGNER_BELDEX_START_HEIGHT", 0);
    let mut beldex_saved: u64 = 0;
    let mut evm_saved: BTreeMap<u64, u64> = BTreeMap::new();
    match &cursor_dir {
        None => println!("  watch cursors: OFF (every restart rescans from the configured start)"),
        Some(dir) => {
            use beldex_bridge_signer::watch_cursor;
            println!("  watch cursors kept in: {}", dir.display());
            match watch_cursor::load(dir, "beldex", &beldex_identity, &beldex_key) {
                Ok(Some(watch_cursor::Loaded::OtherKey(c))) => match src.beldex.block_hash(c.height) {
                    Ok(h) if h == c.hash => {
                        let from = watch_cursor::rescan_from(&c, beldex_rekey_window, beldex_start);
                        src.beldex.resume_after(from);
                        println!(
                            "  beldex watcher: the saved cursor ({}) was made under another mint key; rescanning \
                             after height {from} for deposits that key signed and that never minted",
                            c.height
                        );
                    }
                    _ => println!("  beldex watcher: the saved cursor (another key) does not match this chain; scanning from the configured start"),
                },
                Ok(Some(watch_cursor::Loaded::Ours(c))) => match src.beldex.block_hash(c.height) {
                    Ok(h) if h == c.hash => {
                        src.beldex.resume_after(c.height);
                        beldex_saved = c.height;
                        println!("  beldex watcher: resuming after height {} (saved cursor)", c.height);
                    }
                    Ok(_) => println!(
                        "  beldex watcher: the saved cursor names a block this chain does not have at {}; \
                         scanning from the configured start",
                        c.height
                    ),
                    Err(e) => println!(
                        "  beldex watcher: could not check the saved cursor ({e:?}); scanning from the configured start"
                    ),
                },
                Ok(None) => {}
                Err(e) => eprintln!("  beldex watcher: ignoring the saved cursor: {e}"),
            }
            for (w, c) in src.evm.iter_mut().zip(configs) {
                match watch_cursor::load(dir, &format!("evm-{}", c.chain_id), &evm_identity(c), &evm_key) {
                    Ok(Some(watch_cursor::Loaded::OtherKey(cur))) => match w.block_hash(cur.height) {
                        Ok(Some(h)) if h == cur.hash => {
                            let from = watch_cursor::rescan_from(&cur, evm_rekey_window, c.start_block);
                            w.resume_from(from);
                            println!(
                                "  evm chain {}: the saved cursor ({}) was made under another gateway key; rescanning \
                                 from block {from} for burns that key signed and that were never released",
                                c.chain_id, cur.height
                            );
                        }
                        _ => println!(
                            "  evm chain {}: the saved cursor (another key) does not match this chain; scanning from the configured start",
                            c.chain_id
                        ),
                    },
                    Ok(Some(watch_cursor::Loaded::Ours(cur))) => match w.block_hash(cur.height) {
                        Ok(Some(h)) if h == cur.hash => {
                            w.resume_from(cur.height + 1);
                            evm_saved.insert(c.chain_id, cur.height);
                            println!("  evm chain {}: resuming after block {} (saved cursor)", c.chain_id, cur.height);
                        }
                        Ok(_) => println!(
                            "  evm chain {}: the saved cursor names a block this chain does not have at {}; \
                             scanning from the configured start",
                            c.chain_id, cur.height
                        ),
                        Err(e) => println!(
                            "  evm chain {}: could not check the saved cursor ({e:?}); scanning from the configured start",
                            c.chain_id
                        ),
                    },
                    Ok(None) => {}
                    Err(e) => eprintln!("  evm chain {}: ignoring the saved cursor: {e}", c.chain_id),
                }
            }
        }
    }
    // Duties whose first reconcile could not be answered; asked again every tick (the
    // watchers hand each event out only once).
    let mut deferred: Vec<Duty> = Vec::new();
    // The highest key epoch each chain's watcher has handed out as a rotation. A chain's
    // cursor waits until L1 has acknowledged it: the acknowledgement is built from that
    // event, which a restart past it would never see again.
    let mut rotation_seen: BTreeMap<u64, u64> = BTreeMap::new();

    // The guard's cadence, and how long a handed-off cancel may take to land.
    let guard_ticks = std::cmp::max(1, 15 / poll_secs.max(1));
    const CANCEL_LAND_GRACE: std::time::Duration = std::time::Duration::from_secs(120);
    let mut cancel_done_since: BTreeMap<beldex_bridge_signer::orchestrator::DutyKey, std::time::Instant> =
        BTreeMap::new();
    // Standby role: the deposits seen final and when, as evidence of whether the live key
    // still mints (update_outage), and the optional probe deposit that creates such evidence
    // when the bridge is idle.
    let mut evidence: BTreeMap<([u8; 32], u32), (u64, std::time::Instant)> = BTreeMap::new();
    let mut evidence_reconciler = EvmMintReconciler {
        chains: configs.iter().map(|c| (c.chain_id, (HttpJsonRpc::new(c.rpc_url.clone()), c.contract))).collect(),
    };
    let outage_window = std::time::Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_OUTAGE_WINDOW_SECS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(600),
    );
    let probe = if standby_role { ProbeDeposit::from_env(release_gateway.clone(), beldexd_rpc) } else { None };
    let mut last_probe: Option<std::time::Instant> = None;
    let mut said_promote = false;
    let supervised = std::env::var("BRIDGE_SIGNER_SUPERVISED").is_ok_and(|v| v.trim() == "1");
    let retire_after = std::time::Duration::from_secs(
        std::env::var("BRIDGE_SIGNER_RETIRE_AFTER_SECS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(600),
    );
    let mut retired_since: Option<std::time::Instant> = None;
    let mut standby_retire_since: Option<std::time::Instant> = None;
    if standby_role {
        println!(
            "serve: STANDBY role: signs only takeover begin/complete for this share set's key, after \
             this node sees a deposit final for {}s and unminted; probe deposits {}",
            outage_window.as_secs(),
            if probe.is_some() { "on" } else { "off (BRIDGE_SIGNER_PROBE_*)" }
        );
    }

    // A rotation handed off but not taken by the contract is signed again after this long
    // (see the hand-offs below), read on its own clients.
    const ROTATE_LAND_GRACE: std::time::Duration = std::time::Duration::from_secs(15 * 60);
    let mut rotate_done_since: BTreeMap<beldex_bridge_signer::orchestrator::DutyKey, std::time::Instant> = BTreeMap::new();
    let rotation_check_rpcs: BTreeMap<u64, (HttpJsonRpc, [u8; 20])> =
        configs.iter().map(|c| (c.chain_id, (HttpJsonRpc::new(c.rpc_url.clone()), c.contract))).collect();
    // The bus the incoming committee publishes its activations to (the mint bus).
    let mut activation_subs: Vec<_> =
        bus_endpoints(&activation_bus).into_iter().map(beldex_bridge_signer::omq_client::OmqMintSubscriber::new).collect();
    let rotation_contracts = done_contracts_for_rotation;

    let mut ticks = 0u64;
    loop {
        // The share set this process loaded was replaced on disk (a promotion after a
        // rotation or a takeover): exit, so the supervisor restarts it on the new set.
        if ticks % 12 == 0 && beldex_bridge_signer::share_watch::fingerprint(&share_dir) != loaded_share_set {
            println!(
                "serve: the share set in {} changed: exiting so the supervisor restarts on the new one",
                share_dir.display()
            );
            std::process::exit(beldex_bridge_signer::share_watch::RESTART_EXIT_CODE);
        }
        status.beat(std::time::Duration::from_secs(poll_secs.max(1) * 10));
        let (pending, in_flight, done) = orch.counts();
        status.set("duties", serde_json::json!({ "pending": pending, "in_flight": in_flight, "done": done }));
        status.set("wbdx_key_replaced_on", serde_json::json!(mint_key_replaced.iter().collect::<Vec<_>>()));
        status.set("gateway_key_replaced", release_key_replaced);
        status.problem("solvency_hold", coord.hold.clone());
        // Re-read the committee about once a minute. A transport error is not a change —
        // only a view that parses and differs counts, or a blip would stall the node.
        if !committee_changed && ticks % 12 == 0 {
            if let Ok(now) = committee_probe.fetch_committee(None) {
                if now.membership_bytes() != started_with {
                    committee_changed = true;
                    println!(
                        "committee moved on (epoch {} -> {}): this node keeps serving the key it \
                         holds until that key is replaced on chain",
                        ls.committee.epoch, now.epoch
                    );
                }
            }
        }
        // Is this node's key still the live one? Same cadence. An unreadable answer is not a
        // replacement — only a signer / owner that reads back and differs counts. The wBDX
        // signer is read at the watcher's confirmation depth, not the tip: stopping is not
        // undone, so it must not act on an activation a reorg can still take back.
        if !standby_role && ticks % 12 == 0 {
            use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
            use sha3::{Digest, Keccak256};
            let ours = format!("0x{}", hex(&ls.pevm_address));
            let selector = format!("0x{}", hex(&Keccak256::digest(b"currentSigner()")[..4]));
            for (chain_id, client, contract, confirmations, depth_only) in &key_probe_evm {
                if mint_key_replaced.contains(chain_id) {
                    continue;
                }
                // Depth is not finality: on a chain that reports one, read at its finalized
                // block, as the watcher settles events. Depth only where it was chosen.
                let at = if *depth_only {
                    let Ok(tip) = client.call("eth_blockNumber", serde_json::json!([])) else { continue };
                    let Some(tip) = tip.as_str().and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok()) else {
                        continue;
                    };
                    let Some(at) = tip.checked_sub(*confirmations) else { continue };
                    format!("0x{at:x}")
                } else {
                    "finalized".to_string()
                };
                let params = serde_json::json!([
                    { "to": format!("0x{}", hex(contract)), "data": selector },
                    at
                ]);
                let Ok(word) = client.call("eth_call", params) else { continue };
                let Some(word) = word.as_str().filter(|w| w.len() == 66) else { continue };
                let live = format!("0x{}", &word[26..]).to_lowercase();
                if live == ours {
                    mint_key_live.insert(*chain_id);
                    incoming_since.remove(chain_id);
                    if mint_key_incoming.remove(chain_id) {
                        println!("chain {chain_id}: this share set's key {ours} is now live; opening its held mints");
                    }
                    // Is a standby named? Read at the tip: this is a warning, not a decision.
                    let sel = format!("0x{}", hex(&Keccak256::digest(b"standbySigner()")[..4]));
                    let q = serde_json::json!([{ "to": format!("0x{}", hex(contract)), "data": sel }, "latest"]);
                    if let Ok(w) = client.call("eth_call", q) {
                        if let Some(w) = w.as_str().filter(|w| w.len() == 66) {
                            let missing = w[26..].bytes().all(|b| b == b'0');
                            if no_standby.insert(*chain_id, missing) != Some(missing) {
                                if missing {
                                    eprintln!(
                                        "!! chain {chain_id}: wBDX names no standby key. If this key loses its \
                                         holders the bridge halts until governance acts: generate a standby \
                                         with another committee and register it."
                                    );
                                } else {
                                    println!("chain {chain_id}: wBDX names a standby key");
                                }
                            }
                        }
                    }
                } else if !mint_key_live.contains(chain_id) && {
                    // Never seen live by this process, but the contract may already have
                    // retired it (this signer restarted after its key was replaced). That is
                    // replaced, not incoming: its mints belong to the successor.
                    let sel = format!("0x{}", hex(&Keccak256::digest(b"retiredKey(address)")[..4]));
                    let q = serde_json::json!([{
                        "to": format!("0x{}", hex(contract)),
                        "data": format!("{sel}{:0>64}", hex(&ls.pevm_address)),
                    }, at]);
                    !client
                        .call("eth_call", q)
                        .ok()
                        .and_then(|w| w.as_str().map(|w| w.ends_with('1')))
                        .unwrap_or(false)
                } {
                    let now = std::time::Instant::now();
                    if mint_key_incoming.insert(*chain_id) {
                        incoming_since.insert(*chain_id, (now, now));
                        println!(
                            "chain {chain_id}: the wBDX signer is still {live}, not yet this share set's {ours}; \
                             holding mints until the change is settled"
                        );
                    } else if let Some((since, last)) = incoming_since.get_mut(chain_id) {
                        if now.duration_since(*last) >= HELD_REPORT_EVERY {
                            *last = now;
                            let held = held_mints.iter().filter(|m| m.dst_chain.0 == *chain_id).count();
                            eprintln!(
                                "!! chain {chain_id}: still holding {held} mint(s) after {} min: the wBDX signer \
                                 is {live}, not this share set's {ours}. If the change that named this key was \
                                 cancelled, these shares should not be live: restore the previous ones.",
                                now.duration_since(*since).as_secs() / 60
                            );
                        }
                    }
                } else {
                    mint_key_replaced.insert(*chain_id);
                    let a = (0..20).map(|i| live.get(2 + 2 * i..4 + 2 * i).and_then(|b| u8::from_str_radix(b, 16).ok())).collect::<Option<Vec<u8>>>();
                    if let Some(a) = a.and_then(|v| <[u8; 20]>::try_from(v).ok()) {
                        replaced_by.insert(*chain_id, a);
                    }
                    eprintln!(
                        "!! KEY REPLACED on chain {chain_id}: the wBDX signer is now {live}, not this \
                         share set's {ours}. Not opening further mints for it; in-flight work will \
                         finish. Promote the successor shares and restart."
                    );
                }
            }
            if !release_key_replaced {
                let params = serde_json::json!({ "gateway_address": release_gateway });
                if let Ok(info) = key_probe_gw.call("get_gateway_info", params) {
                    if let Some(owner) = info.get("owner_key").and_then(|v| v.as_str()) {
                        if owner.eq_ignore_ascii_case(&hex(&ls.pgw_group_vk)) {
                            if let Some(has) = info.get("has_standby").and_then(|v| v.as_bool()) {
                                if no_standby.insert(0, !has) != Some(!has) {
                                    if has {
                                        println!("gateway: names a standby owner");
                                    } else {
                                        eprintln!(
                                            "!! gateway: names no standby owner. If this key loses its holders the \
                                             reserve is stuck until governance re-points it: register a standby."
                                        );
                                    }
                                }
                            }
                        } else {
                            release_key_replaced = true;
                            eprintln!(
                                "!! KEY REPLACED on the gateway: its owner key is now {owner}, not \
                                 this share set's {}. Not opening further releases; in-flight work \
                                 will finish. Promote the successor shares and restart.",
                                hex(&ls.pgw_group_vk)
                            );
                        }
                    }
                }
            }
        }
        // Both legs handed over and nothing left in flight: this key's work is done. With a
        // successor live, exit for the supervisor to restart this process on it (installed at
        // start, `install_successor`). Without one this node is not on the incoming committee:
        // retire the tree, kept, and stop.
        if ticks % 12 == 0
            && release_key_replaced
            && key_probe_evm.iter().all(|(id, ..)| mint_key_replaced.contains(id))
            && orch.counts().1 == 0
        {
            if key_probe.live_successor(&share_dir).is_some() {
                println!("both legs are on this node's successor key: exiting to be restarted on it");
                std::process::exit(RESTART_ON_SUCCESSOR);
            }
            if key_probe.is_live(&share_dir) == Some(false) {
                match key_probe.archive(&share_dir) {
                    Ok(to) => println!("this node holds no share of the live key: retired its tree to {}, stopping", to.display()),
                    Err(e) => eprintln!("this node holds no share of the live key, and retiring its tree failed: {e}"),
                }
                std::process::exit(0);
            }
        }

        // Supervised (BRIDGE_SIGNER_SUPERVISED=1): a live share set replaced on every chain and
        // the gateway, for long enough that a reorg will not bring it back, serves nothing
        // more. Archive it, as promote-shares.sh does for a leaving node, and exit: the
        // supervisor restarts this signer, which then waits for the node's next share set
        // instead of holding a retired key, its mesh ports and its RPC load.
        if supervised && !standby_role && ticks % 12 == 0 {
            let everywhere = release_key_replaced && configs.iter().all(|c| mint_key_replaced.contains(&c.chain_id));
            match (everywhere, retired_since) {
                (false, _) => retired_since = None,
                (true, None) => retired_since = Some(std::time::Instant::now()),
                // Duties still open are not waited for: a replaced key can never sign them (that
                // is why it was replaced), and its successor's signers pick the same deposits and
                // burns up under their own key. Waiting would hold the retired key, its mesh ports
                // and its RPC load for good.
                (true, Some(t)) if t.elapsed() >= retire_after => {
                    let left = orch.outstanding().len();
                    let mut to = share_dir.as_os_str().to_owned();
                    to.push(format!(".retired-{}", beldex_bridge_signer::release_outbox::now_secs()));
                    match std::fs::rename(&share_dir, &to) {
                        Ok(()) => {
                            println!(
                                "serve: this share set's key was replaced on every chain {}s ago: archived it to \
                                 {} and exiting ({left} duty(ies) left to the successor key); this signer waits \
                                 for the node's next share set",
                                t.elapsed().as_secs(),
                                std::path::Path::new(&to).display()
                            );
                            std::process::exit(beldex_bridge_signer::share_watch::RESTART_EXIT_CODE);
                        }
                        Err(e) => eprintln!("!! could not archive the replaced share set: {e}"),
                    }
                }
                _ => {}
            }
        }
        // Re-ask the chain about every duty not yet done — in flight as well as queued, since
        // a session that keeps timing out and reopening is almost never in the queued state.
        // Reconciliation on first sighting is
        // not enough: a duty is settled by WHICHEVER member submits, and the members that
        // did not submit have no other way to learn it happened. If they also missed the
        // signature aggregate they cannot take the straggler path either, so their sessions
        // time out and reopen for a release that is already on chain — forever, each round
        // asking its own daemon to build and decode a withdrawal that will never be sent.
        // Left alone on a 20-member committee that is 19 nodes spinning on every completed
        // release for the life of the process.
        if reconcile_on && ticks % reconcile_recheck_ticks == 0 {
            let queued: Vec<Duty> = orch.outstanding().into_iter().cloned().collect();
            for d in queued {
                if reconciler.is_settled(&d) == Some(true) {
                    orch.mark_done(&d.key());
                    println!("reconciled late: duty settled on-chain by another member");
                }
            }
        }

        // Ingest the watchers (re-emission is safe — the orchestrator dedups, and a duty is
        // reconciled against chain state at most once per SIGHTING; the re-check above
        // covers duties that settle after they were queued).
        if reconcile_on && !deferred.is_empty() {
            let resolved = beldex_bridge_signer::reconcile::retry_undetermined(orch, &mut reconciler, &mut deferred);
            if resolved > 0 {
                println!("reconciled {resolved} duty(ies) the chain could not answer for earlier");
            }
        }
        let mut ingest = |orch: &mut beldex_bridge_signer::orchestrator::Orchestrator, d: Duty| {
            if reconcile_on {
                match observe_reconciled(orch, &mut reconciler, d.clone()) {
                    ObserveOutcome::AlreadySettled => {
                        println!("reconciled: duty already settled on-chain — not re-worked")
                    }
                    // The watcher will not hand it out again: keep it and ask again.
                    ObserveOutcome::Undetermined => deferred.push(d),
                    _ => {}
                }
            } else {
                orch.observe(d);
            }
        };
        // Takeover steps, about every 15s from the chain tip. Live role: a standby takeover
        // begun against this node's key is cancelled while the key can still sign. Standby
        // role: first refresh whether this node sees the live key failing, then begin or
        // complete. A step handed off that is still wanted two minutes later is signed and
        // sent again (Orchestrator::reopen).
        if ticks % guard_ticks == 0 {
            if standby_role && takeover.all_ours() {
                // Every chain answers to this standby key now: it is the live key. Move this
                // share set into the live directory (archiving the old one) and exit; the live
                // signer on this node restarts on it, and this one waits for the next standby.
                match std::env::var("BRIDGE_SIGNER_PROMOTE_TO").ok().filter(|v| !v.trim().is_empty()) {
                    Some(live_dir) => {
                        let now = beldex_bridge_signer::release_outbox::now_secs();
                        match beldex_bridge_signer::share_watch::promote(&share_dir, std::path::Path::new(live_dir.trim()), now) {
                            Ok(archived) => {
                                println!(
                                    "PROMOTED: every chain answers to this standby key; its shares are now the \
                                     live set in {}{}. Exiting for the restart.",
                                    live_dir.trim(),
                                    archived.map(|a| format!(" (the old set kept in {})", a.display())).unwrap_or_default()
                                );
                                std::process::exit(beldex_bridge_signer::share_watch::RESTART_EXIT_CODE);
                            }
                            Err(e) => eprintln!("!! could not promote the standby shares: {e}"),
                        }
                    }
                    None if !said_promote => {
                        said_promote = true;
                        eprintln!(
                            "!! every chain answers to this standby key: promote its shares to the live \
                             directory and restart (or set BRIDGE_SIGNER_PROMOTE_TO to have it done)"
                        );
                    }
                    None => {}
                }
            }
            // A standby set whose key went stale (its holders cannot sign together), or that a
            // newer standby replaced, serves nothing: archive it and wait in the pool, where the
            // node can help generate the next standby.
            if standby_role && supervised {
                let why = if takeover.own_takeover_running() {
                    None
                } else {
                    takeover.standby_view().and_then(|(view, records)| {
                        beldex_bridge_signer::key_attestation::standby_set_retired(&view, &records, &ls.pgw_group_vk, ls.committee.height, ls.committee.round_height)
                    })
                };
                match (why, standby_retire_since) {
                    (None, _) => standby_retire_since = None,
                    (Some(why), None) => {
                        eprintln!("!! this standby set should step aside: {why}");
                        standby_retire_since = Some(std::time::Instant::now());
                    }
                    // As for a replaced live key: a stale or superseded standby's open duties
                    // (a begin it can no longer get signed) are not waited for.
                    (Some(why), Some(t)) if t.elapsed() >= retire_after => {
                        let mut to = share_dir.as_os_str().to_owned();
                        to.push(format!(".retired-{}", beldex_bridge_signer::release_outbox::now_secs()));
                        match std::fs::rename(&share_dir, &to) {
                            Ok(()) => {
                                println!(
                                    "serve: {why}. Archived this standby set to {} and exiting; this signer \
                                     waits for the node's next standby set",
                                    std::path::Path::new(&to).display()
                                );
                                std::process::exit(beldex_bridge_signer::share_watch::RESTART_EXIT_CODE);
                            }
                            Err(e) => eprintln!("!! could not archive the standby set: {e}"),
                        }
                    }
                    _ => {}
                }
            }
            if standby_role {
                update_outage(&takeover, &mut evidence, &mut evidence_reconciler, outage_window);
                if let Some(p) = &probe {
                    p.maybe_probe(evidence.is_empty(), &mut last_probe);
                }
            }
            for (c, _) in takeover.wanted() {
                use beldex_bridge_signer::watch::TakeoverStepKind;
                let d = Duty::Takeover(c);
                let key = d.key();
                let what = if c.on_gateway() {
                    format!("the gateway (takeover {})", c.takeover_id)
                } else {
                    format!("chain {} (takeover {}, key epoch {})", c.chain_id, c.takeover_id, c.key_epoch)
                };
                match orch.status(&key) {
                    None => {
                        match c.step {
                            TakeoverStepKind::Cancel => eprintln!(
                                "!! STANDBY TAKEOVER BEGUN against this committee's live key on {what}: \
                                 cancelling it (it lands only if this committee can still reach its threshold)"
                            ),
                            TakeoverStepKind::Begin => eprintln!(
                                "!! LIVE KEY FAILING: beginning the standby takeover on {what}"
                            ),
                            TakeoverStepKind::Complete => eprintln!(
                                "!! standby takeover ready on every chain: completing it on {what}"
                            ),
                            TakeoverStepKind::NameStandby => println!(
                                "no working standby named on {what}: naming the newest attested key within the overlap limit"
                            ),
                            TakeoverStepKind::StandbyAlive => println!(
                                "proving this standby key can still sign (over block {})",
                                c.takeover_id
                            ),
                        }
                        ingest(orch, d);
                    }
                    Some(beldex_bridge_signer::orchestrator::DutyStatus::Done) => {
                        let since = *cancel_done_since.entry(key).or_insert_with(std::time::Instant::now);
                        if since.elapsed() >= CANCEL_LAND_GRACE && orch.reopen(&key) {
                            cancel_done_since.remove(&key);
                            eprintln!(
                                "!! takeover step on {what} still wanted {}s after it was handed off: signing \
                                 and sending it again",
                                since.elapsed().as_secs()
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        // Keep draining the watchers so their cursors advance, but do not turn events into
        // duties for a key that has been replaced — they belong to the successor committee.
        if standby_role {
            // A standby signs no mint or release; it watches deposits only to see whether the
            // live key is minting them (update_outage).
            for m in src.poll_mints() {
                evidence.entry((m.beldex_txid, m.output_index)).or_insert((m.dst_chain.0, std::time::Instant::now()));
            }
            let _ = src.poll_releases();
        }
        held_mints.extend(if standby_role { Vec::new() } else { src.poll_mints() });
        for m in std::mem::take(&mut held_mints) {
            if mint_key_incoming.contains(&m.dst_chain.0) {
                held_mints.push(m);
            } else if !mint_key_replaced.contains(&m.dst_chain.0) {
                ingest(orch, Duty::Mint(m));
            }
        }
        for r in if standby_role { Vec::new() } else { src.poll_releases() } {
            if !release_key_replaced {
                ingest(orch, Duty::Release(r));
            }
        }
        // The gateway hand-over, from the chain alone: once every wBDX chain answers to one newer
        // committee's attested key and the gateway is still this key's, hand it over to that
        // key's Pgw. The incoming committee's activations raise it too, but they stop once wBDX
        // has moved, so a member restarted after that would otherwise never sign it.
        if !standby_role
            && !release_key_replaced
            && ticks % ack_sweep_ticks == 0
            && !key_probe_evm.is_empty()
            && key_probe_evm.iter().all(|(id, ..)| mint_key_replaced.contains(id))
        {
            use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
            use beldex_bridge_signer::key_attestation as ka;
            let signers: std::collections::BTreeSet<[u8; 20]> = replaced_by.values().copied().collect();
            if let (1, Some(to)) = (signers.len(), signers.iter().next().copied()) {
                let next = key_probe_gw
                    .call("bridge_get_standby", serde_json::json!({}))
                    .ok()
                    .and_then(|v| ka::parse_records(&v))
                    .and_then(|recs| {
                        recs.into_iter()
                            .filter(|r| r.attested_height != 0 && r.round_height == 0 && r.pevm_address == to)
                            .filter(|r| r.epoch > ls.committee.epoch)
                            .min_by_key(|r| r.attested_height)
                    });
                if let Some(r) = next {
                    let d = Duty::Handover(beldex_bridge_signer::orchestrator::HandoverRequest {
                        gateway_id: reserve_gateway,
                        new_owner: r.pgw_vk,
                        key_epoch: r.epoch,
                    });
                    if orch.status(&d.key()).is_none() {
                        println!(
                            "gateway hand-over requested from the chain: wBDX answers to the epoch {} key 0x{}, \
                             attested with gateway key {}",
                            r.epoch,
                            hex(&to),
                            hex(&r.pgw_vk)
                        );
                    }
                    ingest(orch, d);
                }
            }
        }
        // Hand-offs: the incoming committee's activations, each checked here before it can
        // become a rotation to sign (rotation_from_activation).
        let mut arrived = Vec::new();
        for sub in activation_subs.iter_mut() {
            while let Ok(Some(p)) = sub.poll(std::time::Duration::from_millis(20)) {
                arrived.push(p);
            }
        }
        for p in arrived {
            match rotation_from_activation(&p, ls.committee.epoch, &rotation_contracts, &committee_probe, &key_probe_gw) {
                Ok(Some((r, pgw, key_epoch))) if !mint_key_replaced.contains(&r.chain_id) => {
                    // The gateway follows the same key: one hand-over per certificate.
                    if !release_key_replaced {
                        ingest(
                            orch,
                            Duty::Handover(beldex_bridge_signer::orchestrator::HandoverRequest {
                                gateway_id: reserve_gateway,
                                new_owner: pgw,
                                key_epoch,
                            }),
                        );
                    }
                    let d = Duty::Rotate(r.clone());
                    // Signed and handed off, but the contract never took it: its nonce was spent
                    // first (a standby naming) or its deadline passed. Sign it again, on the
                    // contract's state now, once it has had time to land.
                    if orch.status(&d.key()) == Some(beldex_bridge_signer::orchestrator::DutyStatus::Done) {
                        let since = *rotate_done_since.entry(d.key()).or_insert_with(std::time::Instant::now);
                        let landed = rotation_check_rpcs
                            .get(&r.chain_id)
                            .map(|(c, a)| read_rotation_state(c, a))
                            .and_then(Result::ok)
                            .map(|st| st.pending_activate_at != 0 || st.key_epoch >= r.new_key_epoch);
                        if landed == Some(true) {
                            rotate_done_since.remove(&d.key());
                        } else if landed == Some(false) && since.elapsed() >= ROTATE_LAND_GRACE && orch.reopen(&d.key()) {
                            rotate_done_since.remove(&d.key());
                            eprintln!(
                                "!! rotateSigner for chain {} key epoch {} not taken {}s after it was handed off \
                                 (its nonce was spent or its deadline passed): signing it again",
                                r.chain_id,
                                r.new_key_epoch,
                                since.elapsed().as_secs()
                            );
                        }
                    }
                    if orch.status(&d.key()).is_none() {
                        if let Duty::Rotate(r) = &d {
                            println!(
                                "hand-off requested: chain {} key epoch {} -> 0x{} (certificate and activation check out)",
                                r.chain_id, r.new_key_epoch, hex(&r.new_signer)
                            );
                        }
                    }
                    ingest(orch, d);
                }
                Ok(_) => {}
                Err(e) => eprintln!("  activation on the bus not taken: {e}"),
            }
        }
        // Observe: a settled key change on any watched chain. Sign it and tell the mesh.
        if !standby_role && bus_genesis != [0u8; 32] {
            for r in src.poll_rotations() {
                let seen = rotation_seen.entry(r.chain.0).or_insert(0);
                *seen = (*seen).max(r.key_epoch);
                // Already applied on L1 (seen again after a restart re-scanned the chain):
                // nothing left to acknowledge.
                if l1_observed.get(&r.chain.0).is_some_and(|have| *have >= r.key_epoch) {
                    continue;
                }
                let ack = beldex_bridge_signer::rotation_ack::RotationAck::from_event(&r);
                let key = ack.mesh_key(&bus_genesis);
                match ack_collector.observe_and_sign(
                    ack,
                    ls.committee.epoch,
                    ls.self_index,
                    &ls.ed25519_secret,
                    &bus_genesis,
                ) {
                    Ok(body) => {
                        println!(
                            "rotation observed: chain {} key epoch {} -> {}",
                            r.chain.0,
                            r.key_epoch,
                            hex(&r.new_signer)
                        );
                        // `payload_hash` is the fact's own hash, so peers group signatures
                        // for the same rotation and can never pool two different ones.
                        let msg = beldex_bridge_signer::wire::WireMsg {
                            leg: Leg::Pgw,
                            epoch: ls.committee.epoch,
                            payload_hash: key,
                            attempt: 0,
                            from: ls.self_index,
                            body: beldex_bridge_signer::wire::SessionMsg::RotationAckSig(body),
                        };
                        use beldex_bridge_signer::wire::SessionTransport as _;
                        beldex_bridge_signer::wire::note_send_failure(
                            "rotation-ack",
                            net.broadcast(&msg),
                        );
                    }
                    Err(e) => eprintln!("  rotation ack signing failed: {e}"),
                }
            }

            // Absorb peers' signatures. Each was set aside by the coordinator's pump, which
            // sees them before a session would drop them as unopened. A signature for a
            // rotation this node has not observed itself is refused inside `absorb` — the
            // bond gate must never turn on someone else's word about what happened.
            for (key, body) in std::mem::take(&mut coord.rotation_ack_inbox) {
                ack_collector.absorb(&key, &body, &bus_genesis);
            }

            for done in ack_collector.take_complete(&ls.committee, &bus_genesis) {
                println!(
                    "rotation ack complete for chain {} key epoch {}: queued for L1",
                    done.ack.chain_id, done.ack.key_epoch
                );
                ack_submissions.add(done);
            }

            // About once a minute: learn what L1 has applied, stop working on that, re-send
            // this node's own signatures for anything still collecting (a member that started
            // late missed them), and put the next acknowledgement per chain on chain.
            if ticks % ack_sweep_ticks == 0 {
                use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
                use beldex_bridge_signer::rotation_ack::{parse_observed_key_epochs, rotation_hex_from_reply};
                match key_probe_gw.call("bridge_get_seats", serde_json::json!({})) {
                    Ok(v) => match parse_observed_key_epochs(&v) {
                        Some(m) => l1_observed = m,
                        None => eprintln!("  bridge_get_seats: no observed_key_epoch in the reply"),
                    },
                    Err(e) => eprintln!("  bridge_get_seats failed ({e:?}); keeping the last view"),
                }
                let observed = |chain: u64| l1_observed.get(&chain).copied();
                ack_collector.forget_observed(observed);
                ack_submissions.forget_observed(observed);

                for (key, body) in ack_collector.own_signatures(ls.self_index, &bus_genesis) {
                    let msg = beldex_bridge_signer::wire::WireMsg {
                        leg: Leg::Pgw,
                        epoch: ls.committee.epoch,
                        payload_hash: key,
                        attempt: 0,
                        from: ls.self_index,
                        body: beldex_bridge_signer::wire::SessionMsg::RotationAckSig(body),
                    };
                    use beldex_bridge_signer::wire::SessionTransport as _;
                    beldex_bridge_signer::wire::note_send_failure("rotation-ack", net.broadcast(&msg));
                }

                let now = beldex_bridge_signer::release_outbox::now_secs();
                for done in ack_submissions.due(observed, now) {
                    ack_submissions.attempted(&done.ack, now);
                    let (chain, epoch) = (done.ack.chain_id, done.ack.key_epoch);
                    // The daemon re-checks the evidence and the chain's binding, and leaves
                    // out any observer that is no longer bonded.
                    let reply = match committee_probe.submit_rotation_ack(&done.to_submission_json()) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("  rotation ack chain {chain} key epoch {epoch}: daemon refused ({e}); will retry");
                            continue;
                        }
                    };
                    let Some(rotation_hex) = rotation_hex_from_reply(&reply) else {
                        eprintln!("  rotation ack chain {chain} key epoch {epoch}: no rotation_hex in {reply}");
                        continue;
                    };
                    match &ack_wallet {
                        Some(w) => match w.call(
                            "bridge_rotation_ack",
                            serde_json::json!({ "rotation_hex": rotation_hex }),
                        ) {
                            Ok(r) => println!(
                                "rotation ack chain {chain} key epoch {epoch} submitted: tx {}",
                                r.get("tx_hash").and_then(serde_json::Value::as_str).unwrap_or("?")
                            ),
                            // Includes "already in the pool" when another member got there
                            // first; the next sweep sees L1 apply it and stops.
                            Err(e) => eprintln!(
                                "  rotation ack chain {chain} key epoch {epoch}: wallet did not submit ({e:?}); will retry"
                            ),
                        },
                        // No wallet here, as on a member that pays no fees: the runner's
                        // submitter (handover-submit) pays for it, off the bus. Published
                        // every sweep until L1 applies it, like the wallet path retries.
                        None => {
                            let payload = format!(
                                r#"{{"kind":"ack","chain_id":{chain},"key_epoch":{epoch},"rotation_hex":"{rotation_hex}"}}"#
                            );
                            handoff_for_sweep.publish(&payload);
                            println!(
                                "rotation ack chain {chain} key epoch {epoch} is ready and published for a submitter to pay for \
                                 (or submit it with `bridge_rotation_ack {rotation_hex}` from any funded wallet). \
                                 Until it is mined, departing members' bonds stay locked."
                            );
                        }
                    }
                }
            }
        }

        // The fee wallet: its balance (whole and unlocked) and address on /status, and a problem
        // on /health while it is low. Low is judged on the whole balance: right after paying,
        // the change is locked for a few blocks and the unlocked part reads 0.
        if ticks % (ack_sweep_ticks * 5) == 0 {
            if let Some(w) = &ack_wallet {
                use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
                let b = w.call("get_balance", serde_json::json!({ "account_index": 0 })).ok();
                let field = |k: &str| b.as_ref().and_then(|b| b.get(k).and_then(|x| x.as_u64()));
                let (total, unlocked) = (field("balance"), field("unlocked_balance"));
                status.set("fee_wallet_balance", total.map_or(serde_json::Value::Null, |u| u.into()));
                status.set("fee_wallet_unlocked", unlocked.map_or(serde_json::Value::Null, |u| u.into()));
                status.problem(
                    "fee_wallet_low",
                    match total {
                        Some(t) if t < fee_wallet_low => Some(format!("{t} atomic units, below {fee_wallet_low}: top it up")),
                        None => Some("fee wallet balance unreadable".into()),
                        _ => None,
                    },
                );
                if fee_wallet_address.is_none() {
                    fee_wallet_address = w
                        .call("get_address", serde_json::json!({ "account_index": 0 }))
                        .ok()
                        .and_then(|a| a.get("address").and_then(|x| x.as_str()).map(str::to_string));
                    if let Some(a) = &fee_wallet_address {
                        status.set("fee_wallet_address", a.as_str());
                    }
                }
            }
        }

        if !attest_done && ticks % ack_sweep_ticks == 0 {
            use beldex_bridge_signer::evm_watcher::JsonRpcClient as _;
            use beldex_bridge_signer::key_attestation as ka;
            let now = beldex_bridge_signer::release_outbox::now_secs();
            let records = key_probe_gw
                .call("bridge_get_standby", serde_json::json!({}))
                .map_err(|e| format!("{e:?}"))
                .and_then(|v| ka::parse_records(&v).ok_or_else(|| "no attestations in the reply".to_string()));
            match records.map(|r| ka::status(&r, ls.committee.epoch, ls.committee.round_height, &ls.pgw_group_vk, &ls.pevm_address, ls.self_index)) {
                Ok(ka::Status::Attested) => {
                    println!(
                        "key attested: committee epoch {} holds gateway key {}",
                        ls.committee.epoch,
                        hex(&ls.pgw_group_vk)
                    );
                    attest_done = true;
                }
                Ok(ka::Status::Counted) => {}
                Ok(ka::Status::Missing) if now >= attest_next_at => {
                    match ka::sign(&ls.ed25519_secret, &bus_genesis, ls.committee.epoch, ls.committee.round_height, &ls.pgw_group_vk, &ls.pevm_address) {
                        Err(e) => eprintln!("  key attestation not signed: {e}"),
                        Ok(sig) => match &ack_wallet {
                            Some(w) => match w.call(
                                "bridge_key_attestation",
                                serde_json::json!({
                                    "epoch": ls.committee.epoch,
                                    "round_height": ls.committee.round_height,
                                    "pgw_vk": hex(&ls.pgw_group_vk),
                                    "pevm_address": hex(&ls.pevm_address),
                                    "voter_index": ls.self_index,
                                    "signature": hex(&sig),
                                }),
                            ) {
                                Ok(r) => {
                                    println!(
                                        "key attestation (committee epoch {}, member {}) submitted: tx {}",
                                        ls.committee.epoch,
                                        ls.self_index,
                                        r.get("tx_hash").and_then(serde_json::Value::as_str).unwrap_or("?")
                                    );
                                    attest_next_at = now + 600;
                                }
                                Err(e) => {
                                    eprintln!("  key attestation not submitted ({e:?}); will retry");
                                    attest_next_at = now + 60;
                                }
                            },
                            None => {
                                println!(
                                    "KEY-ATTESTATION epoch={} round_height={} pgw_vk={} pevm_address={} voter_index={} signature={} \
                                     (no wallet RPC: submit with the wallet RPC bridge_key_attestation)",
                                    ls.committee.epoch,
                                    ls.committee.round_height,
                                    hex(&ls.pgw_group_vk),
                                    hex(&ls.pevm_address),
                                    ls.self_index,
                                    hex(&sig)
                                );
                                attest_next_at = now + 3600;
                            }
                        },
                    }
                }
                Ok(ka::Status::Missing) => {}
                Err(e) => eprintln!("  bridge_get_standby failed ({e}); key attestation waits"),
            }
        }

        // Re-deliver any signed mint the contract has not minted yet. Safe for ever — the
        // contract refuses a deposit it already minted — so the only reasons to stop are
        // that it landed, or that a week of re-delivery has not made it land.
        if !standby_role && ticks % mint_retry_ticks == 0 {
            use beldex_bridge_signer::mint_outbox as outbox;
            let now = beldex_bridge_signer::release_outbox::now_secs();
            for (_, mut rec) in outbox::load_all(&mint_outbox_for_sweep) {
                // Given up by an earlier run: move it out of the working set.
                if rec.gave_up {
                    let _ = outbox::archive(&mint_outbox_for_sweep, &rec);
                    continue;
                }
                if !rec.due(now) {
                    continue;
                }
                let Some(beldex_txid) = config::parse_hex32(&rec.beldex_txid) else {
                    continue;
                };
                let duty = Duty::Mint(beldex_bridge_signer::watch::MintEvent {
                    beldex_txid,
                    output_index: rec.output_index,
                    dst_chain: beldex_bridge_signer::chain_registry::ChainId(rec.chain_id),
                    to: [0u8; 20],
                    amount: 0,
                });
                match reconciler.is_settled(&duty) {
                    Some(true) => {
                        println!(
                            "mint landed on chain {} (deposit {} output {}) — no longer tracked",
                            rec.chain_id, rec.beldex_txid, rec.output_index
                        );
                        outbox::remove(&mint_outbox_for_sweep, &rec);
                        continue;
                    }
                    // The RPC could not say. Leave it for the next sweep rather than
                    // re-deliver blind or give up on a transport error.
                    None => continue,
                    Some(false) => {}
                }
                if rec.should_give_up(now) {
                    rec.gave_up = true;
                    let kept = outbox::archive(&mint_outbox_for_sweep, &rec)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|e| format!("{mint_outbox_for_sweep} (could not move it: {e})"));
                    eprintln!(
                        "!! MINT UNDELIVERED after {} days — chain {} deposit {} output {}\n   \
                         payload kept in {}; NOT re-delivering further. If the wBDX signer \
                         has rotated since it was signed, it can no longer mint and the \
                         deposit needs a fresh signature.",
                        outbox::GIVE_UP_AFTER_SECS / 86_400,
                        rec.chain_id,
                        rec.beldex_txid,
                        rec.output_index,
                        kept
                    );
                    continue;
                }
                if rec.is_stale(now) && !rec.warned {
                    rec.warned = true;
                    eprintln!(
                        "!! mint still unminted after {}h — chain {} deposit {} output {}. \
                         Re-delivering; check the relayers' gas, whether the contract is \
                         paused, and whether its signer rotated.",
                        outbox::STALE_AFTER_SECS / 3600,
                        rec.chain_id,
                        rec.beldex_txid,
                        rec.output_index
                    );
                }
                println!(
                    "re-delivering mint (chain {} deposit {} output {}, attempt {})",
                    rec.chain_id,
                    rec.beldex_txid,
                    rec.output_index,
                    rec.attempts + 1
                );
                handoff_for_sweep.deliver(&rec.payload);
                rec.last_attempt = beldex_bridge_signer::release_outbox::now_secs();
                rec.attempts += 1;
                let _ = outbox::save(&mint_outbox_for_sweep, &rec);
            }
        }

        // Re-send any release that has not been seen in a block yet. The SAME signed
        // bytes, never a fresh signature: a duplicate carries the same transaction id and
        // the chain ignores it, so paying twice is impossible by construction.
        if !standby_role && ticks % release_retry_ticks == 0 {
            use beldex_bridge_signer::release_outbox as outbox;
            let now = outbox::now_secs();
            for (_, mut rec) in outbox::load_all(&outbox_dir_for_sweep) {
                // Re-sent until discharged, however long that takes: consensus refuses a
                // second payout for the same burn for ever, so no re-send can pay twice.
                // Past STALE_AFTER_SECS it is reported once, and still re-sent.
                if rec.is_stale(now) && !rec.warned {
                    rec.warned = true;
                    let _ = outbox::save(&outbox_dir_for_sweep, &rec);
                    eprintln!(
                        "!! release still unmined after {}h — chain {} burn {} log {} (txid {})\n   \
                         Still re-sending the same signed transaction (it can never pay twice). \
                         Check the daemon's answer to it, and whether the gateway inputs it spends \
                         are still unspent. Kept in {}.",
                        outbox::STALE_AFTER_SECS / 3600,
                        rec.chain_id,
                        rec.evm_txid,
                        rec.log_index,
                        rec.txid,
                        outbox_dir_for_sweep
                    );
                }
                // ASK consensus whether this burn is already discharged, rather than
                // inferring it from a submit error. Re-submitting a release that has been
                // mined fails on its INPUT — the gateway output it spends is gone — so the
                // daemon answers with a spent-output error and the replay guard's
                // "already-discharged" wording never appears. Matching on that wording left
                // a delivered release retrying for the full twelve hours and then marked
                // undelivered, while consensus had recorded it from the first block.
                if sweep_reconciler.is_settled(&rec_duty(&rec)) == Some(true) {
                    println!(
                        "release settled on chain (burn {} log {}) — no longer tracked",
                        rec.evm_txid, rec.log_index
                    );
                    outbox::remove(&outbox_dir_for_sweep, &rec);
                    continue;
                }

                let mut sig = [0u8; 64];
                let Some(bytes) = config::parse_hex64(&rec.signature) else {
                    continue;
                };
                sig.copy_from_slice(&bytes);
                // Not discharged: re-send. Either answer only bumps the attempt count —
                // the discharged check above is what ends the record's life.
                let _ = rpc.borrow_mut().submit_transfer(&rec.tx_blob, &sig);
                rec.attempts += 1;
                let _ = outbox::save(&outbox_dir_for_sweep, &rec);
            }
        }

        // Record how far each chain has been fully handled, about once a minute, when it
        // has nothing unfinished (see watch_cursor for what that covers).
        if let (Some(dir), true) = (&cursor_dir, ticks % reconcile_recheck_ticks == 0) {
            use beldex_bridge_signer::watch_cursor::{self, Cursor};
            let unfinished: Vec<&Duty> = orch.outstanding().into_iter().chain(deferred.iter()).collect();
            let h = src.beldex.finalized_up_to();
            if h > beldex_saved && mint_key_replaced.is_empty() && held_mints.is_empty() && watch_cursor::mints_settled(unfinished.iter().copied()) {
                match src.beldex.block_hash(h) {
                    Ok(hash) => match watch_cursor::save(dir, "beldex", &beldex_identity, &beldex_key, &Cursor { height: h, hash }) {
                        Ok(()) => beldex_saved = h,
                        Err(e) => eprintln!("  beldex cursor not saved: {e}"),
                    },
                    Err(e) => eprintln!("  beldex cursor not saved: block {h}: {e:?}"),
                }
            }
            for (w, c) in src.evm.iter().zip(configs) {
                let Some(h) = w.resume_point().checked_sub(1) else { continue };
                let acked = rotation_seen
                    .get(&c.chain_id)
                    .is_none_or(|e| l1_observed.get(&c.chain_id).is_some_and(|o| o >= e));
                if h <= evm_saved.get(&c.chain_id).copied().unwrap_or(0)
                    || release_key_replaced
                    || !acked
                    || !watch_cursor::releases_settled(c.chain_id, unfinished.iter().copied())
                {
                    continue;
                }
                match w.block_hash(h) {
                    Ok(Some(hash)) => {
                        let name = format!("evm-{}", c.chain_id);
                        match watch_cursor::save(dir, &name, &evm_identity(c), &evm_key, &Cursor { height: h, hash }) {
                            Ok(()) => {
                                evm_saved.insert(c.chain_id, h);
                            }
                            Err(e) => eprintln!("  evm chain {} cursor not saved: {e}", c.chain_id),
                        }
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("  evm chain {} cursor not saved: block {h}: {e:?}", c.chain_id),
                }
            }
        }

        if !standby_role && ticks > 0 && ticks % solvency_ticks == 0 {
            use beldex_bridge_signer::solvency::Change;
            match solvency_check() {
                Ok((problems, summary)) => match solvency_guard.observe(&problems) {
                    Some(Change::Tripped(why)) => eprintln!(
                        "!! SIGNING HELD: {why}. Mints and releases wait until this clears ({summary})"
                    ),
                    Some(Change::Cleared) => println!("solvency restored, signing resumes: {summary}"),
                    None if !problems.is_empty() && solvency_guard.hold().is_none() => eprintln!(
                        "  solvency check failed once, rechecking before holding: {}",
                        problems.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
                    ),
                    None => {}
                },
                // Not evidence either way: the hold stays as it was.
                Err(e) => eprintln!("  solvency check could not be made ({e}); signing state unchanged"),
            }
            coord.hold = solvency_guard.hold().map(str::to_string);
        }

        if let (Some(gate), Some(height)) = (coord.open_gate.as_mut(), takeover.tip_height()) {
            gate.observe(height);
        }
        let rep = coord.step(orch, &mut net);
        if rep != Default::default() {
            let (pending, in_flight, done) = orch.counts();
            println!(
                "tick {ticks}: opened={} acked={} nacked={} signed={} completed={} requeued={} abandoned={} resolved={} | duties p={pending} f={in_flight} d={done}",
                rep.opened, rep.acked, rep.nacked, rep.signed, rep.completed, rep.requeued, rep.abandoned, rep.resolved
            );
        }
        // Idle heartbeat (~once a minute): proves the watchers are scanning and shows how
        // far finality has advanced — a stalled `finalized_up_to` means the chain (or the
        // miner) stopped; one that advances past a deposit with no duty means the deposit
        // didn't resolve (and the `deposit held` line above says why).
        if ticks % 12 == 0 {
            let (pending, in_flight, done) = orch.counts();
            // The EVM half matters as much as the Beldex half. A burn is held in the
            // watcher's `pending` set until its inclusion block is `confirmations` deep
            // (watch.rs FinalityGate: depth = tip - inclusion_height), so on an idle
            // automine chain — anvil started without --block-time — the tip stops at the
            // block containing the burn, depth stays 0, and the release never opens.
            // Without a pending count that is indistinguishable from "no burn happened",
            // which is the one thing the operator most needs to tell apart.
            let evm: Vec<String> = src
                .evm
                .iter()
                .map(|w| {
                    let tip = w
                        .tip()
                        .map(|t| t.to_string())
                        .unwrap_or_else(|e| format!("unreachable({e:?})"));
                    format!("chain {} tip={} pending={}", w.chain().0, tip, w.pending_len())
                })
                .collect();
            println!(
                "watch: beldex finalized_up_to={} | evm {} | duties p={pending} f={in_flight} d={done}",
                src.beldex.finalized_up_to(),
                evm.join("; ")
            );
            // What waits on disk, so growth is visible before it is a problem: mints being
            // re-delivered, mints given up (each waits for a person), releases being re-sent.
            {
                use beldex_bridge_signer::{mint_outbox, release_outbox};
                let now = release_outbox::now_secs();
                let releases = release_outbox::load_all(&outbox_dir_for_sweep);
                let stale = releases.iter().filter(|(_, r)| r.is_stale(now)).count();
                let given_up = mint_outbox::load_archived(&mint_outbox_for_sweep).len();
                println!(
                    "outboxes: mints {} re-delivering, {given_up} given up (in {}/{}) | releases {} re-sending ({stale} stale)",
                    mint_outbox::load_all(&mint_outbox_for_sweep).len(),
                    mint_outbox_for_sweep,
                    mint_outbox::GAVE_UP_SUBDIR,
                    releases.len(),
                );
            }
        }
        ticks += 1;
        if opts.max_ticks.is_some_and(|max| ticks >= max) {
            break;
        }
        if !opts.interval.is_zero() {
            std::thread::sleep(opts.interval);
        }
    }

    let (pending, in_flight, done) = orch.counts();
    println!("serve: finished after {ticks} tick(s); duties pending={pending} in_flight={in_flight} done={done}");
    Ok(())
}

fn main() -> ExitCode {
    let subcommand = std::env::args().nth(1);

    // `relay-watch` is dispatched BEFORE the config load, deliberately: it is the
    // relayer-operator command, and a relayer holds no signer identity — no gateway, no MN
    // key, no shares. Requiring the full signer config here would force operators to invent
    // dummy values for keys they must not have. It needs exactly one setting: the OMQ
    // endpoint to subscribe to.
    // `list-stuck` is dispatched BEFORE the config load, deliberately: it is the recovery
    // command, and the moment it is most needed is when something is wrong. Requiring a
    // full signer identity to ask "which payouts are outstanding" would make it unusable
    // from an operator's laptop, or on a node whose config is the thing that broke. It
    // needs exactly one setting: where the signed releases are kept.
    // `verify-keycert <file>`: whether a key certificate is the selected committee's — the
    // committee beldexd (BRIDGE_SIGNER_OXENMQ_ENDPOINT) reports at the certificate's height.
    // Needs no signer identity, so anyone can check a key before trusting it.
    if subcommand.as_deref() == Some("verify-keycert") {
        return match run_verify_keycert(std::env::args().nth(2)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("verify-keycert: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if subcommand.as_deref() == Some("list-stuck") {
            // The daily sweep: every release still outstanding, and whether it is still
            // being retried or is waiting for a person.
            use beldex_bridge_signer::release_outbox as outbox;
            let dir = std::env::var("BRIDGE_SIGNER_RELEASE_OUTBOX")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "releases".to_string());
            let now = outbox::now_secs();
            let all = outbox::load_all(&dir);
            if all.is_empty() {
                println!("no outstanding releases in {dir}");
            } else {
                println!("{} outstanding release(s) in {dir}:\n", all.len());
                for (path, r) in &all {
                    let hours = r.age_secs(now) / 3600;
                    let state = if r.is_stale(now) {
                        "still retrying, but unmined past the stale mark: check why"
                    } else {
                        "still retrying"
                    };
                    println!(
                        "  burn chain {} tx {} log {}\n    txid      {}\n    waiting   {hours}h ({} attempts)\n    state     {state}\n    file      {}\n",
                        r.chain_id, r.evm_txid, r.log_index, r.txid, r.attempts, path.display()
                    );
                }
                println!(
                    "Each is the one signed transaction that can pay its burn: a release is never\n\
                     re-signed, and consensus refuses a second payout for the same burn for ever.\n\
                     The signers keep re-sending these until they land; one still here long\n\
                     after its burn usually means the gateway inputs it spends are gone."
                );
            }
            // Mints the signer stopped re-delivering: each needs a person.
            use beldex_bridge_signer::mint_outbox;
            let mdir = std::env::var("BRIDGE_SIGNER_MINT_OUTBOX")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "mints".to_string());
            let given_up = mint_outbox::load_archived(&mdir);
            if given_up.is_empty() {
                println!("no given-up mints in {mdir}/{}", mint_outbox::GAVE_UP_SUBDIR);
            } else {
                println!("\n{} given-up mint(s) in {mdir}/{}:\n", given_up.len(), mint_outbox::GAVE_UP_SUBDIR);
                for (path, r) in &given_up {
                    println!(
                        "  deposit {} output {} -> chain {}\n    waiting   {}d ({} attempts)\n    file      {}\n",
                        r.beldex_txid,
                        r.output_index,
                        r.chain_id,
                        r.age_secs(now) / 86_400,
                        r.attempts,
                        path.display()
                    );
                }
                println!(
                    "These were not minted within {} days of re-delivery. If the wBDX signer has rotated\n\
                     since, the payload can never mint: the deposit needs a fresh signature.",
                    mint_outbox::GIVE_UP_AFTER_SECS / 86_400
                );
            }
        return ExitCode::SUCCESS;
    }

    if matches!(subcommand.as_deref(), Some("protect-shares") | Some("new-share-key")) {
        let arg = std::env::args().nth(2);
        let r = if subcommand.as_deref() == Some("protect-shares") {
            run_protect_shares(arg)
        } else {
            run_new_share_key(arg)
        };
        return match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{}: {e}", subcommand.unwrap_or_default());
                ExitCode::FAILURE
            }
        };
    }

    if subcommand.as_deref() == Some("handover-submit") {
        return match run_handover_submit() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("handover-submit: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if subcommand.as_deref() == Some("relay-watch") {
        return match run_relay_watch_standalone() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("relay-watch: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let cfg = match Config::from_map(&config_map()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            eprintln!("set BRIDGE_SIGNER_<KEY> env vars (gateway_id, self_mn_pubkey, ...)");
            return ExitCode::FAILURE;
        }
    };

    match subcommand.as_deref() {
        Some("dkg") => match run_dkg(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("dkg: {e}");
                ExitCode::FAILURE
            }
        },
        Some("dkg-auto") => match run_dkg_auto(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("dkg-auto: {e}");
                ExitCode::FAILURE
            }
        },
        Some("sign") => match run_sign(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sign: {e}");
                ExitCode::FAILURE
            }
        },
        Some("watch-evm") => match run_watch_evm(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("watch-evm: {e}");
                ExitCode::FAILURE
            }
        },
        Some("serve") => match run_serve(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("serve: {e}");
                ExitCode::FAILURE
            }
        },
        // ("relay-watch" is dispatched before the config load — see the top of main.)
        _ => {
            print_status(&cfg);
            ExitCode::SUCCESS
        }
    }
}

#[cfg(all(test, feature = "live-dkg"))]
mod secret_file_tests {
    use super::*;

    /// The share directory is owner-only: other accounts on the host cannot list it.
    /// (Sealing, key handling and plaintext refusal are tested in `share_file`.)
    #[cfg(unix)]
    #[test]
    fn a_share_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bx-secret-{}", std::process::id()));
        let d = dir.to_str().unwrap();
        create_secret_dir(d).unwrap();
        let dmode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "share directory must not be listable by others");
        let _ = std::fs::remove_dir_all(d);
    }

    /// End to end with real FROST material: `dkg`'s writer seals the share and leaves the
    /// public package readable; the loader opens it and accepts the pair; a public package
    /// from another key put in its place is refused rather than trusted.
    #[test]
    fn pgw_material_is_sealed_and_its_public_package_must_match() {
        use frost_ed25519 as frost;
        let root = std::env::temp_dir().join(format!("bx-pgw-material-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("shares");
        let d = dir.to_str().unwrap();
        let key_file = root.join("share.key");
        std::fs::write(&key_file, "5a".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::env::set_var("BRIDGE_SIGNER_SHARE_KEY_FILE", &key_file);

        let deal = || {
            let (shares, pk) = frost::keys::generate_with_dealer(6, 4, frost::keys::IdentifierList::Default, &mut rand::rngs::OsRng)
                .unwrap();
            let kp = frost::keys::KeyPackage::try_from(shares.into_values().next().unwrap()).unwrap();
            (kp, pk)
        };
        let (kp, pk) = deal();
        let vk: [u8; 32] = pk.verifying_key().serialize().unwrap().try_into().unwrap();
        persist_pgw_material(d, 0, &kp.serialize().unwrap(), &pk.serialize().unwrap(), &vk).unwrap();

        let on_disk = std::fs::read(dir.join("pgw-0.keypackage")).unwrap();
        assert!(on_disk.starts_with(beldex_bridge_signer::share_file::MAGIC_V2), "the share is sealed");
        assert_eq!(std::fs::read(dir.join("pgw-0.groupvk")).unwrap(), vk, "public file readable");
        let (loaded, _) = load_pgw_material(d, 0).unwrap();
        assert_eq!(loaded.verifying_key(), kp.verifying_key());

        let (_, other) = deal();
        std::fs::write(dir.join("pgw-0.pubkeypackage"), other.serialize().unwrap()).unwrap();
        let e = load_pgw_material(d, 0).unwrap_err();
        assert!(e.contains("different group key"), "{e}");

        std::env::remove_var("BRIDGE_SIGNER_SHARE_KEY_FILE");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A burn naming an address the daemon cannot parse can never be paid, so retrying it
    /// forever only re-opens a session every few seconds for the life of the process. A
    /// daemon that is merely unreachable must still be retried.
    #[cfg(feature = "serve-live")]
    #[test]
    fn only_a_rejected_request_gives_up_on_a_release() {
        use beldex_bridge_signer::coordinator::BuildError;
        use beldex_bridge_signer::chain_registry::ChainId;
        use beldex_bridge_signer::watch::ReleaseEvent;

        let ev = ReleaseEvent {
            evm_txid: [0xd1; 32],
            log_index: 1,
            chain: ChainId(31337),
            amount: 1_000_000_000,
            beldex_recipient: b"not-a-real-beldex-address".to_vec(),
        };

        // The daemon's real answer for an address it cannot parse (core_rpc_server.cpp,
        // ERROR_WRONG_PARAM). Captured verbatim from a devnet burn to a junk address.
        let permanent = r#"gateway_create_transfer: rpc error {"code":-1,"message":"invalid destination address: not-a-real-beldex-address"}"#;
        assert!(
            matches!(
                classify_release_build_error(&ev, "not-a-real-beldex-address", permanent.into()),
                BuildError::Unactionable(_)
            ),
            "an address the daemon cannot parse can never become payable"
        );

        for transient in [
            "http://127.0.0.1:19191: Connection refused",
            r#"gateway_create_transfer: rpc error {"code":-32603,"message":"Internal error"}"#,
            "timed out",
            // Same error CODE as the address case, but this one can come good once a
            // deposit lands — classifying it by code would strand a payable release.
            r#"gateway_create_transfer: rpc error {"code":-1,"message":"insufficient gateway balance for withdrawal + fee"}"#,
            // Signer-built parameters: the daemon refusing one is our bug, not the user's,
            // and must stay loud rather than silently dropping the duty.
            r#"gateway_create_transfer: rpc error {"code":-1,"message":"ref_evm_txid must be 64-char hex"}"#,
        ] {
            assert!(
                matches!(
                    classify_release_build_error(&ev, "bxAlice", transient.into()),
                    BuildError::Transient(_)
                ),
                "{transient} is about right now, not about the request"
            );
        }
    }
}

#[cfg(all(test, feature = "live-dkg"))]
mod key_committee_tests {
    use super::*;

    fn cfg(self_mn_pubkey: &str) -> Config {
        let m: HashMap<String, String> = [
            ("beldexd_rpc_url", "http://127.0.0.1:1".to_string()),
            // Unreachable on purpose: a saved committee must never need the daemon.
            ("oxenmq_endpoint", "ipc:///nonexistent/beldexd.sock".to_string()),
            ("gateway_id", "11".repeat(32)),
            ("self_mn_pubkey", self_mn_pubkey.to_string()),
            ("bridge_epoch_blocks", "120".to_string()),
            ("committee_threshold", "2".to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        Config::from_map(&m).unwrap()
    }

    fn saved(dir: &str, self_index: i64) {
        let json = format!(
            r#"{{"epoch":3,"height":360,"threshold":2,"active":true,"self_index":{self_index},
               "members":["{a}","{b}","{c}"],"signer_keys":["{d}","{e}","{f}"]}}"#,
            a = "a1".repeat(32), b = "b2".repeat(32), c = "c3".repeat(32),
            d = "d4".repeat(32), e = "e5".repeat(32), f = "f6".repeat(32),
        );
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(format!("{dir}/{KEY_COMMITTEE_FILE}"), json).unwrap();
    }

    /// The committee that ran the DKG keeps signing with its key after consensus has
    /// selected another one — it has to, to sign the rotation that replaces it. So the
    /// share tree's own committee is used, and the daemon's current view is never asked.
    #[test]
    fn a_saved_key_committee_is_used_instead_of_the_current_one() {
        let dir = std::env::temp_dir().join(format!("bx-keycomm-{}", std::process::id()));
        let d = dir.to_str().unwrap();
        saved(d, 2);
        let (c, idx) = load_key_committee(&cfg(&"00".repeat(32)), d).unwrap();
        assert_eq!((c.epoch, c.size(), idx), (3, 3, 2));
        assert_eq!(c.signer_key(2), Some([0xf6; 32]));
        let _ = std::fs::remove_dir_all(d);
    }

    /// A node that holds no share of the saved committee's key must not start signing
    /// for it under some other index.
    #[test]
    fn a_node_outside_the_saved_committee_is_refused() {
        let dir = std::env::temp_dir().join(format!("bx-keycomm-out-{}", std::process::id()));
        let d = dir.to_str().unwrap();
        saved(d, -1);
        let err = load_key_committee(&cfg(&"00".repeat(32)), d).unwrap_err();
        assert!(err.contains("does not hold a share"), "got: {err}");
        // Matched by MN pubkey when the daemon's own index is absent.
        let (_, idx) = load_key_committee(&cfg(&"b2".repeat(32)), d).unwrap();
        assert_eq!(idx, 1);
        let _ = std::fs::remove_dir_all(d);
    }
}

#[cfg(all(test, feature = "serve-live"))]
mod status_board_tests {
    use super::StatusBoard;
    use std::time::Duration;

    #[test]
    fn health_reports_problems_and_a_job_that_stopped_beating() {
        let b = StatusBoard::start("test");
        b.set("key_epoch", 7u64);
        assert_eq!(b.answer("/health"), (200, "ok\n".to_string()));

        b.problem("acks", Some("unpaid for over 30 minutes".into()));
        let (code, body) = b.answer("/health");
        assert_eq!(code, 503);
        assert!(body.contains("acks: unpaid"), "{body}");
        b.problem("acks", None);
        assert_eq!(b.answer("/health").0, 200);

        // A heartbeat that is overdue is a problem by itself.
        b.beat(Duration::ZERO);
        std::thread::sleep(Duration::from_millis(1100));
        let (code, body) = b.answer("/health");
        assert_eq!(code, 503);
        assert!(body.contains("stalled"), "{body}");

        let (_, status) = b.answer("/status");
        let v: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(v["role"], "test");
        assert_eq!(v["key_epoch"], 7);
        assert!(v["problems"]["stalled"].is_string());
    }
}
