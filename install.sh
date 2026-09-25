#!/bin/sh
# install.sh — Tethys installer for prebuilt release tarballs.
#
# Usage (pinned tag, the recommended form):
#
#   curl -fsSL https://raw.githubusercontent.com/jmhickman/tethys/vX.Y.Z/install.sh | sudo sh
#
# Local artifacts (no network needed):
#
#   sh install.sh --source dist/                          # directory of release assets
#   sh install.sh --source tethys-0.1.0-x86_64-unknown-linux-gnu.tar.gz
#   sh install.sh --source tethys-0.1.0-x86_64-unknown-linux-gnu/   # unpacked tree
#
# Modes:
#   (default)    full host deployment: install binaries to /usr/local/bin,
#                baseline + units to their system paths, seed config from
#                the shipped example (never clobbering an existing one),
#                then enable and start the systemd units. Requires root.
#   --stage      stage files only, for packaging and rootless installs:
#                place the release contents under --prefix (binaries in
#                $prefix/bin, deploy artifacts in $prefix/share/tethys)
#                without touching systemd or requiring privileges.
#
# Options:
#   --prefix PATH      install prefix for --stage mode (default: /usr/local)
#   --version TAG      release to install; required only for a URL source
#                      without --version, else taken from the artifact name
#   --source SRC       where the release comes from: a URL (default: the
#                      GitHub releases page of the project repo), a local
#                      .tar.gz, a directory holding release assets (as
#                      scripts/make-dist.sh lays them out in dist/), or an
#                      unpacked release tree. Local sources never touch
#                      the network.
#   --target NAME      override platform detection; NAME is the Rust target
#                      name, e.g. x86_64-unknown-linux-gnu
#   --no-verify        skip sha256 verification (NOT recommended)
#   --dry-run          print what would be done; change nothing
#   --yes              do not prompt before starting services
#
# Environment:
#   DESTDIR            staging root prepended to all paths (package builds)
#   TETHYS_VERSION     same as --version
#   TETHYS_REPO        OWNER/repo whose releases to fetch (default below)
set -eu

TETHYS_REPO="${TETHYS_REPO:-jmhickman/tethys}"
VERSION="${TETHYS_VERSION:-}"
PREFIX="/usr/local"
SOURCE=""
TARGET=""
VERIFY=1
DRY=0
ASSUME_YES=0
MODE=system

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# print_mcp_config [PATH] — the default MCP server stanza for the agent
# harness (mcp.json in Hermes, or the equivalent in any MCP client). Mirrors
# the MCP INTEGRATION section of docs/DEPLOYMENT.md. PATH is the tethys-mcp
# binary location (default: the system-mode install path).
print_mcp_config() {
    bin="${1:-/usr/local/bin/tethys-mcp}"
    say "==> register tethys-mcp with your agent harness — in mcp.json:"
    printf '{\n  "mcpServers": {\n    "tethys": { "command": "%s" }\n  }\n}\n' "$bin"
}

need_root() {
    [ "$(id -u)" -eq 0 ] || die "a host deployment needs root (try: sudo sh install.sh; or stage files without root via --stage)"
}

run() {
    if [ "$DRY" -eq 1 ]; then
        say "DRY: $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------- arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --stage)     MODE=stage ;;
        --prefix)    PREFIX="${2:?--prefix needs a value}"; shift ;;
        --version)   VERSION="${2:?--version needs a value}"; shift ;;
        --source)    SOURCE="${2:?--source needs a value}"; shift ;;
        --target)    TARGET="${2:?--target needs a value}"; shift ;;
        --no-verify) VERIFY=0 ;;
        --dry-run)   DRY=1 ;;
        --yes)       ASSUME_YES=1 ;;
        -h|--help)   sed -n '/^#!/d; /^[^#]/q; s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *)           die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

[ -n "$SOURCE" ] || SOURCE="https://github.com/${TETHYS_REPO}/releases"

# No --source but sitting inside an unpacked release tree (tar xzf'd, cd'd
# in, install.sh ships alongside bin/): use the surrounding directory.
if [ "$SOURCE" = "https://github.com/${TETHYS_REPO}/releases" ] \
    && [ -f "./bin/tethysd" ] && [ -f "./share/tethys/baseline.nft" ]; then
    SOURCE="."
fi

# ------------------------------------------------------------ platform detect
detect_target() {
    uname_s=$(uname -s)
    uname_m=$(uname -m)
    [ "$uname_s" = "Linux" ] || die "unsupported OS: $uname_s (Linux only)"
    case "$uname_m" in
        x86_64|amd64) TARGET="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
        *) die "unrecognized architecture: $uname_m (override with --target)" ;;
    esac
}
[ -n "$TARGET" ] || detect_target

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
need_cmd tar

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# infer_version NAME — set VERSION from an artifact named
# tethys-<version>-<target>{.tar.gz,} when the caller did not pass --version.
infer_version() {
    # resolve to an absolute path first so "." names the directory it lives in
    if [ -d "$1" ]; then
        abs=$(cd "$1" && pwd)
    else
        abs="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
    fi
    base=$(basename "$abs")
    base="${base%.tar.gz}"
    v="${base#tethys-}"
    v="${v%-${TARGET}}"
    case "$v" in
        ""|"$base") return 1 ;;
        *) VERSION="$v"; return 0 ;;
    esac
}

# verify_tarball TARBALL — sha256 against the adjacent .sha256 file.
verify_tarball() {
    tb="$1"
    sum="$tb.sha256"
    if [ ! -f "$sum" ]; then
        [ "$VERIFY" -eq 1 ] || return 0
        die "no checksum beside $tb (expected $(basename "$sum")); pass --no-verify to skip"
    fi
    need_cmd sha256sum
    ( cd "$(dirname "$tb")" && sha256sum -c "$(basename "$sum")" >/dev/null ) \
        || die "sha256 mismatch for $(basename "$tb") — refusing to install"
    say "==> sha256 verified"
}

# ------------------------------------------------------------------- acquire
# Four source shapes, tried by inspection. Local ones never touch the network.
SRC=""   # unpacked release tree; everything downstream installs from this
case "$SOURCE" in
    *://*)
        # URL: GitHub releases layout <url>/download/<tag>/<asset>
        need_cmd curl
        if [ -z "$VERSION" ]; then
            VERSION=$(curl -fsSL "https://api.github.com/repos/${TETHYS_REPO}/releases/latest" \
                | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1) \
                || true
            [ -n "$VERSION" ] || die "could not resolve the latest release tag; pass --version TAG"
        fi
        VER_NUM=$(printf '%s' "$VERSION" | sed 's/^v//')
        PKG="tethys-${VER_NUM}-${TARGET}"
        say "==> fetching ${PKG}.tar.gz (${VERSION})"
        curl -fsSL -o "$TMP/$PKG.tar.gz" "${SOURCE}/download/${VERSION}/${PKG}.tar.gz" \
            || die "could not fetch ${PKG}.tar.gz from ${SOURCE} (check --version/--target/--source)"
        curl -fsSL -o "$TMP/$PKG.tar.gz.sha256" "${SOURCE}/download/${VERSION}/${PKG}.tar.gz.sha256" \
            2>/dev/null || rm -f "$TMP/$PKG.tar.gz.sha256"
        verify_tarball "$TMP/$PKG.tar.gz"
        tar -xzf "$TMP/$PKG.tar.gz" -C "$TMP"
        SRC="$TMP/$PKG"
        ;;
    *)
        if [ -f "$SOURCE" ]; then
            case "$SOURCE" in
                *.tar.gz) TARBALL="$SOURCE" ;;
                *) die "--source file must be a release .tar.gz: $SOURCE" ;;
            esac
        elif [ -d "$SOURCE" ]; then
            if [ -f "$SOURCE/bin/tethysd" ]; then
                TREE="$SOURCE"                       # unpacked release tree
            else
                set -- "$SOURCE"/tethys-*-"$TARGET".tar.gz
                if [ -f "$1" ]; then
                    TARBALL="$1"                     # directory of release assets
                else
                    die "no ${TARGET} release found under $SOURCE (looked for tethys-*-${TARGET}.tar.gz, bin/tethysd); available: $(ls "$SOURCE" 2>/dev/null | tr '\n' ' ')"
                fi
            fi
        else
            die "--source does not exist: $SOURCE"
        fi
        if [ -n "${TREE:-}" ]; then
            infer_version "$TREE" || true
            [ -n "$VERSION" ] || die "cannot infer the version from $TREE; pass --version TAG"
            say "==> using unpacked release tree ${TREE} (${VERSION})"
            SRC="$TREE"
        else
            infer_version "$TARBALL" || true
            [ -n "$VERSION" ] || die "cannot infer the version from $(basename "$TARBALL"); pass --version TAG"
            VER_NUM=$(printf '%s' "$VERSION" | sed 's/^v//')
            PKG="tethys-${VER_NUM}-${TARGET}"
            say "==> installing from local artifact ${TARBALL} (${VERSION})"
            verify_tarball "$TARBALL"
            tar -xzf "$TARBALL" -C "$TMP"
            SRC="$TMP/$PKG"
        fi
        ;;
esac
[ -d "$SRC" ] || die "unexpected release layout: expected ${SRC}/ with bin/ and share/"

# ---------------------------------------------------------------- stage mode
if [ "$MODE" = "stage" ]; then
    say "==> staging files under ${DESTDIR:-}${PREFIX} (no system changes; this is not a host deployment)"
    run install -d "${DESTDIR:-}${PREFIX}/bin"
    run install -d "${DESTDIR:-}${PREFIX}/share/tethys"
    for b in tethysd tethys-mcp tethys; do
        [ -f "$SRC/bin/$b" ] || die "release missing bin/$b"
        run install -m 0755 "$SRC/bin/$b" "${DESTDIR:-}${PREFIX}/bin/$b"
    done
    for a in baseline.nft tethysd.service tethys-baseline.service config.example.toml; do
        [ -f "$SRC/share/tethys/$a" ] || die "release missing share/tethys/$a"
        run install -m 0644 "$SRC/share/tethys/$a" "${DESTDIR:-}${PREFIX}/share/tethys/$a"
    done
    say "==> done. binaries: ${PREFIX}/bin/{tethysd,tethys-mcp,tethys}"
    say "    deploy artifacts: ${PREFIX}/share/tethys/"
    print_mcp_config "${PREFIX}/bin/tethys-mcp"
    exit 0
fi

# ------------------------------------------------------------ system mode (default)
need_root
[ -d /run/systemd/system ] || die "systemd not detected on this host; stage the files (--stage --prefix ...) and wire up init yourself"
need_cmd install
need_cmd systemctl

say "==> installing binaries to /usr/local/bin"
for b in tethysd tethys-mcp tethys; do
    [ -f "$SRC/bin/$b" ] || die "release missing bin/$b"
    run install -m 0755 "$SRC/bin/$b" "/usr/local/bin/$b"
done

say "==> installing baseline ruleset and systemd units"
run install -d /etc/tethys
run install -m 0644 "$SRC/share/tethys/baseline.nft" /etc/tethys/baseline.nft
run install -m 0644 "$SRC/share/tethys/tethysd.service" /etc/systemd/system/tethysd.service
run install -m 0644 "$SRC/share/tethys/tethys-baseline.service" /etc/systemd/system/tethys-baseline.service

# config: seed from the example only when absent — never clobber edits
if [ -f /etc/tethys/config.toml ]; then
    say "==> keeping existing /etc/tethys/config.toml (example at /etc/tethys/config.example.toml)"
else
    say "==> seeding /etc/tethys/config.toml from the shipped example — REVIEW agent_user/admin_user/allow before starting"
    run install -m 0640 "$SRC/share/tethys/config.example.toml" /etc/tethys/config.toml
fi
run install -m 0644 "$SRC/share/tethys/config.example.toml" /etc/tethys/config.example.toml

say "==> daemon-reload + enable"
run systemctl daemon-reload
run systemctl enable tethys-baseline.service tethysd.service

if [ "$ASSUME_YES" -eq 0 ] && [ "$DRY" -eq 0 ]; then
    printf 'start enforcement now? [y/N] '
    read -r reply
else
    reply="${ASSUME_YES:+y}"
    reply="${reply:-n}"
fi
if [ "$reply" = "y" ] || [ "$reply" = "Y" ]; then
    # baseline first; the daemon requires its sets to exist (unit ordering
    # handles this on boot, but starting by hand must not race it)
    run systemctl start tethys-baseline.service
    run systemctl start tethysd.service
    say "==> status:"
    [ "$DRY" -eq 0 ] && systemctl --no-pager --full status tethysd.service tethys-baseline.service | sed -n '1,6p' || say "DRY: systemctl status ..."
else
    say "==> not started. when ready: systemctl start tethys-baseline && systemctl start tethysd"
fi

say "==> installed ${VERSION} (${TARGET}). config: /etc/tethys/config.toml — approver TUI: tethys"
print_mcp_config
