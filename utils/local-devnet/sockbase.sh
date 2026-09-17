# sockbase.sh — keep the devnet's unix socket paths inside the sun_path limit.
#
# A unix socket path is capped at 107 bytes by sockaddr_un. A checkout nested a few
# directories deep goes past that, and the failure is easy to misread: the daemon binds
# its socket with a path relative to its own datadir, so the socket FILE appears on disk
# and the devnet looks healthy over HTTP, while every signer dies on connect with
#
#   bridge.committee transport error: connect ipc://…/beldexd.sock: File name too long
#
# Sets SOCKBASE to a prefix that keeps the socket paths in range: $PWD when it already
# fits, otherwise a short symlink under TMPDIR pointing at it. The kernel resolves
# symlinks when connecting, so this is transparent to both ends.
#
# Source it from a directory that CONTAINS the beldex-127.0.0.1-*/ node dirs, then build
# paths as "$SOCKBASE/${d}devnet/beldexd.sock" instead of "$PWD/${d}devnet/beldexd.sock".

# Longest suffix appended to the base: "beldex-127.0.0.1-NNNNN/devnet/beldexd.sock".
_SOCK_SUFFIX_MAX=42

sockbase_init() {
  SOCKBASE="$PWD"
  [ $(( ${#SOCKBASE} + 1 + _SOCK_SUFFIX_MAX )) -le 107 ] && return 0

  local link="${TMPDIR:-/tmp}/bdx-devnet-$(id -u)"
  ln -sfn "$PWD" "$link" 2>/dev/null || {
    echo "!! socket paths under $PWD exceed the 107-byte unix limit and $link could not" >&2
    echo "   be created. Move the checkout somewhere shorter (e.g. ~/beldex)." >&2
    return 1
  }
  SOCKBASE="$link"
  if [ $(( ${#SOCKBASE} + 1 + _SOCK_SUFFIX_MAX )) -gt 107 ]; then
    echo "!! even $SOCKBASE leaves socket paths over the 107-byte unix limit." >&2
    return 1
  fi
  echo "   socket paths routed via $SOCKBASE (the real path is ${#PWD} bytes, over the 107-byte unix limit)"
  return 0
}
