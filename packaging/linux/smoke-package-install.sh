#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  smoke-package-install.sh --format deb|rpm|apk --package /path/to/package [--check-procd]

Installs a generated lightscale-client package in the current environment and
runs lightweight post-install checks.
EOF
}

log() {
  printf '[pkg-smoke] %s\n' "$*"
}

die() {
  printf '[pkg-smoke] error: %s\n' "$*" >&2
  exit 1
}

FORMAT=""
PACKAGE_PATH=""
CHECK_PROCD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      FORMAT="$2"
      shift 2
      ;;
    --package)
      PACKAGE_PATH="$2"
      shift 2
      ;;
    --check-procd)
      CHECK_PROCD=1
      shift
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

[[ -n "${FORMAT}" ]] || die "--format is required"
[[ -n "${PACKAGE_PATH}" ]] || die "--package is required"
[[ -f "${PACKAGE_PATH}" ]] || die "package not found: ${PACKAGE_PATH}"
if [[ "${CHECK_PROCD}" == "1" && "${FORMAT}" != "apk" ]]; then
  die "--check-procd is only supported with --format apk"
fi

PACKAGE_PATH="$(cd "$(dirname "${PACKAGE_PATH}")" && pwd)/$(basename "${PACKAGE_PATH}")"

is_openwrt_apk_env() {
  [[ -f /etc/openwrt_release ]]
}

install_deb() {
  command -v apt-get >/dev/null 2>&1 || die "apt-get not found"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates iproute2 libmnl0 libnftnl11
  apt-get install -y "${PACKAGE_PATH}"
}

install_rpm() {
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y iproute libmnl libnftnl "${PACKAGE_PATH}"
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    yum install -y iproute libmnl libnftnl "${PACKAGE_PATH}"
    return
  fi
  die "dnf/yum not found"
}

install_apk() {
  command -v apk >/dev/null 2>&1 || die "apk not found"
  if is_openwrt_apk_env; then
    die "OpenWrt package install smoke is unsupported for fpm-generated apk packages (OpenWrt apk v3 feed package required)"
  fi
  apk update
  apk add --no-cache bash ca-certificates iproute2 libgcc libmnl libnftnl
  apk add --no-cache --allow-untrusted "${PACKAGE_PATH}"
}

case "${FORMAT}" in
  deb)
    install_deb
    ;;
  rpm)
    install_rpm
    ;;
  apk)
    install_apk
    ;;
  *)
    die "unsupported format: ${FORMAT}"
    ;;
esac

command -v lightscale-client >/dev/null 2>&1 || die "lightscale-client not found in PATH after install"
[[ -x /usr/lib/lightscale/install-lightscale-client.sh ]] || die "installer script missing"

log "running binary smoke checks"
lightscale-client --help >/dev/null
lightscale-client platform --json >/dev/null
/usr/lib/lightscale/install-lightscale-client.sh --help >/dev/null
/usr/lib/lightscale/install-lightscale-client.sh \
  --dry-run \
  --service-manager none \
  --profile smoke \
  --control-url https://control.example.com \
  >/dev/null

if [[ "${CHECK_PROCD}" == "1" ]]; then
  log "running procd smoke checks"
  /usr/lib/lightscale/install-lightscale-client.sh \
    --service-manager procd \
    --no-enable \
    --profile smoke-procd \
    --config /tmp/lightscale-smoke-procd.json \
    --state-dir /tmp/lightscale-smoke-procd \
    --control-url https://control.example.com \
    >/dev/null

  [[ -x /etc/init.d/lightscale-client-smoke-procd ]] || die "procd init script missing"
  grep -q '^USE_PROCD=1$' /etc/init.d/lightscale-client-smoke-procd || die "procd marker missing"
  grep -q 'procd_set_param command' /etc/init.d/lightscale-client-smoke-procd || die "procd command missing"
fi

log "smoke test passed for ${FORMAT}"
