// Beldex bridge: patched build of zmq-sys 0.12.0 (see bridge/vendor/README.md).
//
// Upstream calls `zeromq_src::Build::new().with_libsodium(None).build()`, and in
// zeromq-src `None` means "no libsodium", which builds libzmq WITHOUT CURVE. The signer's
// mesh relies on CURVE (encrypted, key-pinned channels and the ZAP allow-list of committee
// keys), so every build silently produced a signer that could not run its production mesh.
//
// This build always enables CURVE, linking the system libsodium. It finds it from
// LIBSODIUM_INCLUDE_DIR / LIBSODIUM_LIB_DIR, else from `pkg-config libsodium`, and
// fails the build if neither works. A libzmq without CURVE is never produced in silence.
use std::path::PathBuf;
use std::process::Command;

fn pkg_config_var(var: &str) -> Option<PathBuf> {
    let out = Command::new("pkg-config").args([&format!("--variable={var}"), "libsodium"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then(|| PathBuf::from(s))
}

fn libsodium() -> zeromq_src::LibLocation {
    println!("cargo:rerun-if-env-changed=LIBSODIUM_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LIBSODIUM_LIB_DIR");
    let include = std::env::var_os("LIBSODIUM_INCLUDE_DIR").map(PathBuf::from).or_else(|| pkg_config_var("includedir"));
    let lib = std::env::var_os("LIBSODIUM_LIB_DIR").map(PathBuf::from).or_else(|| pkg_config_var("libdir"));
    match (include, lib) {
        (Some(include), Some(lib)) if include.join("sodium.h").exists() => {
            // zeromq-src prints this search path with `{:?}`, which quotes it and leaves it
            // unusable; give the linker the real one.
            println!("cargo:rustc-link-search=native={}", lib.display());
            zeromq_src::LibLocation::new(include, lib)
        }
        _ => panic!(
            "libsodium not found: libzmq must be built with CURVE for the bridge signer's mesh. \
             Install libsodium (e.g. libsodium-dev, which provides pkg-config libsodium and the \
             static libsodium.a), or set LIBSODIUM_INCLUDE_DIR and LIBSODIUM_LIB_DIR."
        ),
    }
}

pub fn configure() {
    println!("cargo:rerun-if-changed=build/main.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");
    zeromq_src::Build::new().with_libsodium(Some(libsodium())).build();
}

fn main() {
    configure()
}
