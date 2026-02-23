#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build-packages.sh [options]

Build Linux packages for lightscale-client (.deb/.rpm/.apk) from a compiled binary.

Note:
  For --formats apk, provide an Alpine/musl-compatible binary.
  The generated apk package is for Alpine packaging; OpenWrt package feeds
  require a dedicated OpenWrt build pipeline.

Options:
  --bin-path PATH      Path to lightscale-client binary
                       (default: <repo>/target/release/lightscale-client)
  --out-dir PATH       Output directory for generated packages
                       (default: <repo>/dist/packages)
  --formats LIST       Comma-separated formats: deb,rpm,apk (default: deb,rpm,apk)
  --version VERSION    Package version (default: Cargo.toml version)
  --iteration N        Package release/iteration (default: 1)
  --name NAME          Package name (default: lightscale-client)
  --maintainer TEXT    Maintainer string (default: Lightscale Team <devnull@lightscale.local>)
  -h, --help           Show this help

Prerequisite:
  fpm must be installed
  rpmbuild is required only when --formats includes rpm
  (example on Ubuntu: apt-get install rpm && gem install --no-document fpm)
EOF
}

log() {
  printf '[pkg-build] %s\n' "$*"
}

die() {
  printf '[pkg-build] error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_PATH="${ROOT_DIR}/target/release/lightscale-client"
OUT_DIR="${ROOT_DIR}/dist/packages"
VERSION=""
ITERATION="1"
PKG_NAME="lightscale-client"
MAINTAINER="Lightscale Team <devnull@lightscale.local>"
FORMATS_RAW="deb,rpm,apk"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-path)
      BIN_PATH="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --formats)
      FORMATS_RAW="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --iteration)
      ITERATION="$2"
      shift 2
      ;;
    --name)
      PKG_NAME="$2"
      shift 2
      ;;
    --maintainer)
      MAINTAINER="$2"
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

if [[ -z "${VERSION}" ]]; then
  VERSION="$(
    sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT_DIR}/Cargo.toml" | head -n 1
  )"
fi
[[ -n "${VERSION}" ]] || die "failed to detect version from Cargo.toml"

need_cmd fpm
[[ -x "${BIN_PATH}" ]] || die "binary not found or not executable: ${BIN_PATH}"

IFS=',' read -r -a FORMATS <<<"${FORMATS_RAW}"
[[ "${#FORMATS[@]}" -gt 0 ]] || die "no formats selected"

needs_rpm=0
for format in "${FORMATS[@]}"; do
  case "${format}" in
    deb|rpm|apk)
      if [[ "${format}" == "rpm" ]]; then
        needs_rpm=1
      fi
      ;;
    *)
      die "unsupported format in --formats: ${format}"
      ;;
  esac
done
if [[ "${needs_rpm}" == "1" ]]; then
  need_cmd rpmbuild
fi

host_arch="$(uname -m)"

map_deb_arch() {
  case "$1" in
    x86_64) echo "amd64" ;;
    aarch64) echo "arm64" ;;
    armv7l) echo "armhf" ;;
    *) echo "$1" ;;
  esac
}

map_rpm_arch() {
  case "$1" in
    x86_64) echo "x86_64" ;;
    aarch64) echo "aarch64" ;;
    armv7l) echo "armv7hl" ;;
    *) echo "$1" ;;
  esac
}

map_apk_arch() {
  case "$1" in
    x86_64) echo "x86_64" ;;
    aarch64) echo "aarch64" ;;
    armv7l) echo "armv7" ;;
    *) echo "$1" ;;
  esac
}

DEB_ARCH="$(map_deb_arch "${host_arch}")"
RPM_ARCH="$(map_rpm_arch "${host_arch}")"
APK_ARCH="$(map_apk_arch "${host_arch}")"

stage_dir="$(mktemp -d)"
trap 'rm -rf "${stage_dir}"' EXIT

install -d -m 0755 "${stage_dir}/usr/bin"
install -d -m 0755 "${stage_dir}/usr/lib/lightscale"
install -d -m 0755 "${stage_dir}/etc/lightscale"
install -d -m 0755 "${stage_dir}/var/lib/lightscale-client"

install -m 0755 "${BIN_PATH}" "${stage_dir}/usr/bin/lightscale-client"
install -m 0755 \
  "${ROOT_DIR}/packaging/linux/install-lightscale-client.sh" \
  "${stage_dir}/usr/lib/lightscale/install-lightscale-client.sh"

mkdir -p "${OUT_DIR}"

build_pkg() {
  local format="$1"
  local arch="$2"
  local output="$3"
  shift 3
  log "building ${format}: ${output}"
  fpm \
    -s dir \
    -t "${format}" \
    --force \
    -n "${PKG_NAME}" \
    -v "${VERSION}" \
    --iteration "${ITERATION}" \
    -a "${arch}" \
    --maintainer "${MAINTAINER}" \
    --vendor "lightscale" \
    --url "https://github.com/lightscale/lightscale" \
    --license "Apache-2.0" \
    --category "net" \
    --description "Lightscale client CLI and daemon with one-touch registration support." \
    -C "${stage_dir}" \
    --package "${output}" \
    "$@" \
    .
}

for format in "${FORMATS[@]}"; do
  case "${format}" in
    deb)
      build_pkg \
        deb \
        "${DEB_ARCH}" \
        "${OUT_DIR}/${PKG_NAME}_${VERSION}-${ITERATION}_${DEB_ARCH}.deb" \
        --depends bash \
        --depends libgcc-s1 \
        --depends libmnl0 \
        --depends libnftnl11
      ;;
    rpm)
      build_pkg \
        rpm \
        "${RPM_ARCH}" \
        "${OUT_DIR}/${PKG_NAME}-${VERSION}-${ITERATION}.${RPM_ARCH}.rpm" \
        --depends bash \
        --depends libgcc \
        --depends libmnl \
        --depends libnftnl
      ;;
    apk)
      build_pkg \
        apk \
        "${APK_ARCH}" \
        "${OUT_DIR}/${PKG_NAME}-${VERSION}-r${ITERATION}.${APK_ARCH}.apk" \
        --depends bash \
        --depends libgcc \
        --depends libmnl \
        --depends libnftnl
      ;;
  esac
done

log "packages written to ${OUT_DIR}"
ls -1 "${OUT_DIR}"
