#!/bin/sh
# uninstall.sh — remove Tethys from a host installed by install.sh.
#
# Usage (root):
#
#   sh uninstall.sh [--purge] [options]
#
# What it does, in order: stops and disables tethysd.service and
# tethys-baseline.service, removes their unit files, deletes the nftables
# table (lifting egress enforcement), and removes the binaries. The
# baseline ruleset at /etc/tethys/baseline.nft goes too — leaving it
# behind would let a stale policy be reapplied by any leftover tooling.
#
# Configuration and state (/etc/tethys/config.toml, the SQLite ledger
# under /var/lib/tethys) are KEPT by default: an uninstall is often the
# first half of a reinstall, and the ledger is the audit trail. Pass
# --purge to remove them as well. The agent account itself is never
# touched — it belongs to the harness, not to Tethys.
#
# Options:
#   --purge      also remove configuration and the grant ledger
#   --dry-run    print what would be done; change nothing
#   --yes        do not prompt
set -eu

PURGE=0
DRY=0
ASSUME_YES=0

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

run() {
    if [ "$DRY" -eq 1 ]; then
        say "DRY: $*"
    else
        "$@"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)    PURGE=1 ;;
        --dry-run)  DRY=1 ;;
        --yes)      ASSUME_YES=1 ;;
        -h|--help)  sed -n '/^#!/d; /^[^#]/q; s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *)          die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || die "uninstall needs root (try: sudo sh uninstall.sh)"

# Refuse to half-uninstall a host that never had the systemd pair: this
# script's ordering guarantees assume an install.sh-shaped deployment.
if [ ! -e /etc/systemd/system/tethysd.service ] && [ ! -e /etc/systemd/system/tethys-baseline.service ]; then
    say "no tethys systemd units found; nothing to do (files under /etc/tethys or /var/lib/tethys, if any, are left for you to inspect)"
    exit 0
fi

say "==> this will stop enforcement and remove Tethys from this host."
if [ "$PURGE" -eq 0 ]; then
    say "    config (/etc/tethys/config.toml) and ledger (/var/lib/tethys) are kept; pass --purge to remove them."
else
    say "    --purge: config and ledger will be REMOVED."
fi
if [ "$ASSUME_YES" -eq 0 ] && [ "$DRY" -eq 0 ]; then
    printf 'proceed? [y/N] '
    read -r reply
else
    reply="${ASSUME_YES:+y}"
    reply="${reply:-n}"
fi
[ "$reply" = "y" ] || [ "$reply" = "Y" ] || { say "aborted"; exit 0; }

# 1. daemon first, baseline second: stopping the daemon before the table
#    goes means no reconcile racing us, and disabling both prevents a boot
#    re-applying anything mid-uninstall.
say "==> stopping and disabling units"
run systemctl disable --now tethysd.service tethys-baseline.service 2>/dev/null || true

# 2. lift enforcement: the table holds grants, counters, and the default-deny
#    hook; deleting it restores free egress for every uid.
say "==> deleting nftables table"
run nft delete table inet tethys 2>/dev/null || say "    (no inet tethys table present — nothing to delete)"

# 3. unit files and binaries
say "==> removing unit files"
run rm -f /etc/systemd/system/tethysd.service /etc/systemd/system/tethys-baseline.service
run systemctl daemon-reload

say "==> removing binaries"
run rm -f /usr/local/bin/tethysd /usr/local/bin/tethys-mcp /usr/local/bin/tethys

# 4. deployment files; config/state only under --purge (the runtime dir is
#    systemd-managed and vanishes with the units, but clean it if a stale
#    socket lingers). rmdir only succeeds when config.toml is already gone.
say "==> removing baseline ruleset"
run rm -f /etc/tethys/baseline.nft /etc/tethys/config.example.toml
run rmdir /etc/tethys 2>/dev/null || true
run rm -rf /run/tethys

if [ "$PURGE" -eq 1 ]; then
    say "==> purging config and ledger"
    run rm -f /etc/tethys/config.toml
    run rmdir /etc/tethys 2>/dev/null || true
    run rm -rf /var/lib/tethys
else
    if [ -f /etc/tethys/config.toml ] || [ -d /var/lib/tethys ]; then
        say "==> kept: /etc/tethys/config.toml and /var/lib/tethys (delete by hand, or rerun with --purge)"
    fi
fi

say "==> done. egress enforcement is lifted; the agent account and its home are untouched."
