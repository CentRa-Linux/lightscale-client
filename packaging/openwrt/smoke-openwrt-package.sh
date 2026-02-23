#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  smoke-openwrt-package.sh --package /path/to/lightscale-client-*.apk

Installs a native OpenWrt package in the current OpenWrt environment and runs
lightweight post-install checks (binary + procd installer path).
EOF
}

log() {
  printf '[owrt-smoke] %s\n' "$*"
}

die() {
  printf '[owrt-smoke] error: %s\n' "$*" >&2
  exit 1
}

PACKAGE_PATH=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --package)
      PACKAGE_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[ -n "${PACKAGE_PATH}" ] || die "--package is required"
[ -f "${PACKAGE_PATH}" ] || die "package not found: ${PACKAGE_PATH}"
[ -f /etc/openwrt_release ] || die "this smoke script expects an OpenWrt environment"
command -v apk >/dev/null 2>&1 || die "apk not found"

PACKAGE_PATH="$(cd "$(dirname "${PACKAGE_PATH}")" && pwd)/$(basename "${PACKAGE_PATH}")"

apk update
apk add --no-cache ca-certificates bash
apk add --no-cache --allow-untrusted "${PACKAGE_PATH}"

command -v lightscale-client >/dev/null 2>&1 || die "lightscale-client not found after install"
[ -x /usr/lib/lightscale/install-lightscale-client.sh ] || die "installer script missing"

log "running binary checks"
lightscale-client --help >/dev/null
lightscale-client platform --json >/dev/null

log "running procd installer checks"
/usr/lib/lightscale/install-lightscale-client.sh \
  --service-manager procd \
  --no-enable \
  --profile smoke-procd \
  --config /tmp/lightscale-openwrt-smoke.json \
  --state-dir /tmp/lightscale-openwrt-smoke \
  --control-url https://control.example.com \
  >/dev/null

[ -x /etc/init.d/lightscale-client-smoke-procd ] || die "procd init script missing"
grep -q '^USE_PROCD=1$' /etc/init.d/lightscale-client-smoke-procd || die "procd marker missing"
grep -q 'procd_set_param command' /etc/init.d/lightscale-client-smoke-procd || die "procd command missing"

log "openwrt package smoke passed"
