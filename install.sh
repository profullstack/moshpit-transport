#!/bin/sh
# Install moshpit-transport.
#
#   curl -fsSL https://raw.githubusercontent.com/profullstack/moshpit-transport/main/install.sh | sh
#
# Installs to your home directory by default and needs no root. Set MOSHPIT_PREFIX
# and MOSHPIT_BIN to put it elsewhere; set MOSHPIT_REF to install a tag or commit
# rather than main.
#
# If piping a script from the internet into a shell makes you uneasy, good — read
# it first:
#
#   curl -fsSL .../install.sh -o install.sh && less install.sh && sh install.sh
#
set -eu

REPO="profullstack/moshpit-transport"
REF="${MOSHPIT_REF:-main}"
PREFIX="${MOSHPIT_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/moshpit-transport}"
BINDIR="${MOSHPIT_BIN:-$HOME/.local/bin}"
IDENTITY_NAME=""
ACTION="install"

RED=''; BOLD=''; DIM=''; OFF=''
if [ -t 2 ]; then RED=$(printf '\033[31m'); BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); OFF=$(printf '\033[0m'); fi

say()  { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$RED" "$OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall)     ACTION="uninstall" ;;
    --prefix)        PREFIX="${2:?--prefix needs a path}"; shift ;;
    --bin)           BINDIR="${2:?--bin needs a path}"; shift ;;
    --ref)           REF="${2:?--ref needs a git ref}"; shift ;;
    --with-identity) IDENTITY_NAME="${2:?--with-identity needs a name}"; shift ;;
    -h|--help)
      cat >&2 <<EOF
usage: install.sh [options]

  --uninstall              remove an existing install
  --prefix <dir>           where the code goes    (default: $PREFIX)
  --bin <dir>              where the shims go     (default: $BINDIR)
  --ref <tag|branch|sha>   what to install        (default: main)
  --with-identity <name>   also generate a server identity for <name>

environment: MOSHPIT_PREFIX, MOSHPIT_BIN, MOSHPIT_REF
EOF
      exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

if [ "$ACTION" = "uninstall" ]; then
  step "removing $PREFIX"
  rm -rf "$PREFIX"
  for shim in moshpit-transport moshpit-keygen; do
    # Only remove a shim that points at the prefix we just deleted, so a second
    # install elsewhere is not quietly broken by an uninstall here.
    if [ -f "$BINDIR/$shim" ] && grep -q "$PREFIX" "$BINDIR/$shim" 2>/dev/null; then
      rm -f "$BINDIR/$shim"
      say "removed $BINDIR/$shim"
    fi
  done
  say "identities in ~/.moshpit were left alone."
  exit 0
fi

# --- preflight ---------------------------------------------------------------
# Node is checked by capability rather than by version string. ML-KEM and ML-DSA
# need OpenSSL 3.5, and a Node 24 built against an older OpenSSL will pass a
# version check and then fail at the first handshake. Asking the runtime whether
# it can actually do the thing is the only check worth making.

step "checking prerequisites"

have tar || die "tar is required"
if have curl; then FETCH="curl -fsSL"
elif have wget; then FETCH="wget -qO-"
else die "curl or wget is required"
fi

have node || die "node is required, and must be version 24 or newer.
  Install one:  https://nodejs.org  ·  mise use -g node@24  ·  nvm install 24"

NODE="$(command -v node)"
NODE_MAJOR="$("$NODE" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
[ "$NODE_MAJOR" -ge 24 ] 2>/dev/null || die "node $("$NODE" -v 2>/dev/null) is too old; 24 or newer is required.
  mise use -g node@24   ·   nvm install 24"

if ! "$NODE" -e '
  const c = require("node:crypto");
  c.generateKeyPairSync("ml-kem-768");
  c.generateKeyPairSync("ml-dsa-65");
  if (typeof c.encapsulate !== "function") throw new Error("no KEM api");
' >/dev/null 2>&1; then
  die "this node cannot do ML-KEM-768 / ML-DSA-65.
  It is built against OpenSSL $("$NODE" -p 'process.versions.openssl' 2>/dev/null || echo '?'); 3.5 or newer is required.
  A stock Node 24 from nodejs.org has it."
fi

say "  node $("$NODE" -v), openssl $("$NODE" -p 'process.versions.openssl')"

# --- fetch -------------------------------------------------------------------

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

step "downloading $REPO@$REF"
$FETCH "https://codeload.github.com/$REPO/tar.gz/$REF" > "$TMP/src.tgz" \
  || die "download failed. Is '$REF' a real branch, tag or commit?"
tar -xzf "$TMP/src.tgz" -C "$TMP" --strip-components=1 \
  || die "could not unpack the archive"
[ -f "$TMP/lib/transport.ts" ] || die "archive did not contain what was expected"

# --- install -----------------------------------------------------------------

step "installing to $PREFIX"
# Staged then swapped, so an interrupted install cannot leave a half-replaced
# tree that still looks installed.
rm -rf "$PREFIX.new"
mkdir -p "$PREFIX.new"
for item in lib bin package.json README.md LICENSE NOTICE; do
  [ -e "$TMP/$item" ] && cp -R "$TMP/$item" "$PREFIX.new/"
done
rm -rf "$PREFIX.old"
[ -d "$PREFIX" ] && mv "$PREFIX" "$PREFIX.old"
mkdir -p "$(dirname "$PREFIX")"
mv "$PREFIX.new" "$PREFIX"
rm -rf "$PREFIX.old"

mkdir -p "$BINDIR"
for shim in moshpit-transport moshpit-keygen; do
  # The absolute node path is baked in on purpose: these get run from systemd
  # units and cron, where PATH is not the one you installed under.
  cat > "$BINDIR/$shim" <<EOF
#!/bin/sh
exec "$NODE" "$PREFIX/bin/$shim.ts" "\$@"
EOF
  chmod +x "$BINDIR/$shim"
done

"$BINDIR/moshpit-transport" >/dev/null 2>&1 || die "install verification failed"
say "  moshpit-transport, moshpit-keygen -> $BINDIR"

case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) warn "$BINDIR is not on your PATH. Add it:
    echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.profile" ;;
esac

# --- optional identity -------------------------------------------------------

if [ -n "$IDENTITY_NAME" ]; then
  step "generating an identity for $IDENTITY_NAME"
  "$BINDIR/moshpit-keygen" "$IDENTITY_NAME" || die "keygen failed"
  exit 0
fi

cat >&2 <<EOF

${BOLD}installed.${OFF}

  ${DIM}# generate this server's identity — prints the pin to publish${OFF}
  moshpit-keygen scrambled.eggs

  ${DIM}# expose a service you already run, over MTP/1${OFF}
  moshpit-transport serve --identity ~/.moshpit/identities/scrambled.eggs.json \\
    --forward 127.0.0.1:8080 --listen 0.0.0.0:9443

  ${DIM}# from a native client${OFF}
  moshpit-transport forward --to scrambled.eggs:9443 --pin <pin> --listen 127.0.0.1:1080

Publish the pin at https://app.moshcode.sh/pit/dns

${BOLD}Browsing Moshpit? You do not need any of this.${OFF}
  TronBrowser has built-in support — no DNS setup, no proxy, no root
  certificate. https://tronbrowser.dev
  This package is for servers and native clients.

Uninstall with: sh install.sh --uninstall
EOF
