# Vendored crates

## zmq-sys 0.12.0

`zmq-sys` 0.12.0 as published, with one change to `build/main.rs`. Upstream builds the
bundled libzmq with `with_libsodium(None)`, which in `zeromq-src` means "no libsodium",
and so builds libzmq **without CURVE**. The bridge signer's mesh needs CURVE: encrypted,
key-pinned channels, and the ZAP allow-list that admits only committee keys. Every signer
build therefore produced a binary that could not run its production mesh.

The patched build always enables CURVE against the system libsodium (`LIBSODIUM_INCLUDE_DIR`
/ `LIBSODIUM_LIB_DIR`, else `pkg-config libsodium`), and fails the build instead of
producing a libzmq without it. It also emits the libsodium link-search path itself:
`zeromq-src` prints that path with `{:?}`, which quotes it and leaves it unusable. Wired in with `[patch.crates-io]` in `bridge/signer/Cargo.toml`.

Drop this copy once an upstream `zmq-sys` release builds with libsodium.
