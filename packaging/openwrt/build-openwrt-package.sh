#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build-openwrt-package.sh [options]

Build a native OpenWrt package (apk v3 feed format) for lightscale-client
using the OpenWrt SDK Docker image.

Options:
  --bin-path PATH      Path to lightscale-client binary (required to be OpenWrt/musl compatible)
                       (default: <repo>/target/release/lightscale-client)
  --out-dir PATH       Output directory for generated package
                       (default: <repo>/dist/packages-openwrt)
  --sdk-workdir PATH   Persistent OpenWrt SDK work directory/cache
                       (default: <repo>/dist/openwrt-sdk)
  --version VERSION    Package version (default: Cargo.toml version)
  --release N          Package release number (default: 1)
  --target TARGET      OpenWrt target tuple used by SDK setup (default: x86/64)
  --skip-sdk-setup     Skip SDK setup/bootstrap step (expects workdir is already initialized)
  -h, --help           Show this help

Examples:
  ./packaging/openwrt/build-openwrt-package.sh \
    --bin-path dist/apk-bin/lightscale-client-musl
EOF
}

log() {
  printf '[owrt-pkg] %s\n' "$*"
}

die() {
  printf '[owrt-pkg] error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_PATH="${ROOT_DIR}/target/release/lightscale-client"
OUT_DIR="${ROOT_DIR}/dist/packages-openwrt"
SDK_WORKDIR="${ROOT_DIR}/dist/openwrt-sdk"
VERSION=""
RELEASE="1"
TARGET="x86/64"
RUN_SDK_SETUP=1

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
    --sdk-workdir)
      SDK_WORKDIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --release)
      RELEASE="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --skip-sdk-setup)
      RUN_SDK_SETUP=0
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

if [[ -z "${VERSION}" ]]; then
  VERSION="$(
    sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT_DIR}/Cargo.toml" | head -n 1
  )"
fi
[[ -n "${VERSION}" ]] || die "failed to detect version from Cargo.toml"

need_cmd docker
[[ -x "${BIN_PATH}" ]] || die "binary not found or not executable: ${BIN_PATH}"

if command -v file >/dev/null 2>&1; then
  if ! file "${BIN_PATH}" | grep -Eiq 'musl|static'; then
    log "warning: --bin-path does not appear to be musl/static; OpenWrt runtime may fail"
  fi
fi

mkdir -p "${OUT_DIR}" "${SDK_WORKDIR}"
chmod 0777 "${SDK_WORKDIR}" || true

seed_sdk_workdir() {
  if [[ -f "${SDK_WORKDIR}/setup.sh" && -d "${SDK_WORKDIR}/keys" ]]; then
    return
  fi
  log "seeding OpenWrt SDK helper files into ${SDK_WORKDIR}"
  rm -rf "${SDK_WORKDIR}/keys" "${SDK_WORKDIR}/setup.sh"
  docker run --rm \
    -v "${SDK_WORKDIR}:/out" \
    openwrt/sdk:latest /bin/sh -lc '
      set -e
      cp /builder/setup.sh /out/setup.sh
      cp -r /builder/keys /out/keys
    '
}

ensure_writable_tree() {
  docker run --rm \
    -v "${SDK_WORKDIR}:/builder" \
    openwrt/sdk:latest /bin/sh -lc '
      set -e
      chmod -R a+rwX /builder/package /builder/bin /builder/build_dir /builder/staging_dir 2>/dev/null || true
    '
}

setup_sdk() {
  seed_sdk_workdir
  if [[ "${RUN_SDK_SETUP}" != "1" ]]; then
    ensure_writable_tree
    return
  fi
  if [[ -f "${SDK_WORKDIR}/.sdk_ready" ]]; then
    ensure_writable_tree
    return
  fi
  log "initializing OpenWrt SDK (target=${TARGET})"
  docker run --rm \
    -v "${SDK_WORKDIR}:/builder" \
    -w /builder \
    -e TARGET="${TARGET}" \
    openwrt/sdk:latest /bin/sh -lc '
      set -e
      sh /builder/setup.sh
    '
  touch "${SDK_WORKDIR}/.sdk_ready"
  ensure_writable_tree
}

write_openwrt_package() {
  local pkg_dir="${SDK_WORKDIR}/package/lightscale-client"
  local tab=$'\t'
  mkdir -p "${pkg_dir}/files/usr/bin" "${pkg_dir}/files/usr/lib/lightscale"

  cp "${BIN_PATH}" "${pkg_dir}/files/usr/bin/lightscale-client"
  cp "${ROOT_DIR}/packaging/linux/install-lightscale-client.sh" \
    "${pkg_dir}/files/usr/lib/lightscale/install-lightscale-client.sh"
  chmod +x \
    "${pkg_dir}/files/usr/bin/lightscale-client" \
    "${pkg_dir}/files/usr/lib/lightscale/install-lightscale-client.sh"

  cat >"${pkg_dir}/Makefile" <<EOF
include \$(TOPDIR)/rules.mk

PKG_NAME:=lightscale-client
PKG_VERSION:=${VERSION}
PKG_RELEASE:=${RELEASE}
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Lightscale Team <devnull@lightscale.local>

include \$(INCLUDE_DIR)/package.mk

define Package/lightscale-client
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Lightscale client CLI and daemon
  URL:=https://github.com/lightscale/lightscale
  DEPENDS:=+libc +libgcc +libmnl +libnftnl
endef

define Package/lightscale-client/description
 Lightscale client CLI and daemon with one-touch registration support.
endef

# OpenWrt SDK source sets can omit some dependency provider metadata.
# Emit runtime SONAME providers explicitly so dependency checks can pass.
Package/lightscale-client/extra_provides:=echo libc.musl-x86_64.so.1; echo libmnl.so.0; echo libnftnl.so.11

define Build/Compile
endef

define Package/lightscale-client/install
${tab}\$(INSTALL_DIR) \$(1)/usr/bin
${tab}\$(INSTALL_BIN) ./files/usr/bin/lightscale-client \$(1)/usr/bin/lightscale-client
${tab}\$(INSTALL_DIR) \$(1)/usr/lib/lightscale
${tab}\$(INSTALL_BIN) ./files/usr/lib/lightscale/install-lightscale-client.sh \$(1)/usr/lib/lightscale/install-lightscale-client.sh
${tab}\$(INSTALL_DIR) \$(1)/etc/lightscale
${tab}\$(INSTALL_DIR) \$(1)/var/lib/lightscale-client
endef

\$(eval \$(call BuildPackage,lightscale-client))
EOF
}

compile_openwrt_package() {
  log "building OpenWrt package with SDK"
  docker run --rm \
    -v "${SDK_WORKDIR}:/builder" \
    -w /builder \
    openwrt/sdk:latest /bin/sh -lc '
      set -e
      make defconfig >/dev/null
      make package/lightscale-client/clean >/dev/null 2>&1 || true
      make package/lightscale-client/compile V=s
    '
}

collect_artifact() {
  local pkg_path
  pkg_path="$(find "${SDK_WORKDIR}/bin" -type f -name "lightscale-client-${VERSION}-r${RELEASE}.apk" | head -n 1 || true)"
  if [[ -z "${pkg_path}" ]]; then
    pkg_path="$(find "${SDK_WORKDIR}/bin" -type f -name 'lightscale-client-*.apk' | head -n 1 || true)"
  fi
  [[ -n "${pkg_path}" ]] || die "failed to locate generated package in ${SDK_WORKDIR}/bin"

  cp "${pkg_path}" "${OUT_DIR}/"
  log "package written: ${OUT_DIR}/$(basename "${pkg_path}")"
}

setup_sdk
write_openwrt_package
compile_openwrt_package
collect_artifact
