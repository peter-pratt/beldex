#!/usr/bin/env bash
# Run the signer tests that are #[ignore]d in a plain `cargo test`: the full cggmp21 MPC runs
# (keygen, aux-info, signing, DKG-to-sign, the rerun-with-stale-frames regression) and the
# tests that bind real ZMQ sockets on localhost. They take minutes, which is why they are
# not in the default run, but they are the only tests that exercise the protocols
# end to end, so CI runs them nightly (.github/workflows/bridge-rust.yml) and this script
# runs exactly the same set locally.
#
# Two ignored tests need things CI does not have, and are skipped by name:
#   fetches_live_committee   a running beldexd with an active bridge committee
#                            (BRIDGE_SIGNER_OXENMQ_ENDPOINT)
#   cpp_cross_check_vector   a cross-check vector that must be regenerated from beldexd
#                            for the current bridge-memo format
# Any other ignored test added later runs here automatically.
#
# Needs libzmq (with CURVE, i.e. built against libsodium) and pkg-config. Release build: the
# MPC tests are an order of magnitude slower unoptimised.
set -euo pipefail
cd "$(dirname "$0")"

cargo test --release --features live-pevm-dkg,serve-live,cggmp21-test-dealer --lib -- \
  --ignored \
  --skip fetches_live_committee \
  --skip cpp_cross_check_vector \
  "$@"
