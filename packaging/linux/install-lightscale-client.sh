#!/bin/sh

if [ -z "${BASH_VERSION:-}" ]; then
  if command -v bash >/dev/null 2>&1; then
    exec bash "$0" "$@"
  fi
  printf '[install] error: bash is required to run this installer.\n' >&2
  printf '[install] error: install bash first (for OpenWrt: apk add bash).\n' >&2
  exit 1
fi

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  install-lightscale-client.sh [options]

Options:
  --bin-src PATH                 Source lightscale-client binary (default: `command -v lightscale-client`)
  --bin-dest PATH                Install path for binary (default: /usr/local/bin/lightscale-client)
  --profile NAME                 Profile name (default: default)
  --config PATH                  Config path (default: /etc/lightscale/config.json)
  --state-dir PATH               State directory (default: /var/lib/lightscale-client/<profile>)
  --control-url URL              Control URL (repeatable)
  --bootstrap-url URL            Bootstrap URL for first registration (optional)
  --service-manager NAME         auto|systemd|openrc|procd|none (default: auto)
  --agent-arg ARG                Extra daemon agent arg (repeatable)
  --register-url-network-id ID   Run register-url after install
  --register-token-file PATH     Run token-based register after install
  --register-node-name NAME      Node name for registration (default: hostname)
  --no-approve                   Do not add --approve for register-url
  --no-enable                    Install service but do not enable/start it
  --dry-run                      Print actions without writing files
  -h, --help                     Show this help

Examples:
  # systemd host: install + one-touch registration + start service
  sudo ./packaging/linux/install-lightscale-client.sh \
    --control-url https://vpn.example.com:8080 \
    --register-url-network-id net-xxxx

  # OpenWrt/procd host: install service only
  sudo ./packaging/linux/install-lightscale-client.sh \
    --service-manager procd \
    --control-url https://vpn.example.com:8080 \
    --no-enable
EOF
}

log() {
  printf '[install] %s\n' "$*"
}

die() {
  printf '[install] error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    return 0
  fi
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

default_node_name() {
  if command -v hostname >/dev/null 2>&1; then
    hostname
    return
  fi
  if [[ -r /proc/sys/kernel/hostname ]]; then
    tr -d '\r\n' </proc/sys/kernel/hostname
    return
  fi
  printf 'node\n'
}

BIN_SRC="${LIGHTSCALE_BIN_SRC:-}"
BIN_DEST="/usr/local/bin/lightscale-client"
PROFILE="default"
CONFIG_PATH="/etc/lightscale/config.json"
STATE_DIR=""
SERVICE_MANAGER="auto"
REGISTER_URL_NETWORK_ID=""
REGISTER_TOKEN_FILE=""
REGISTER_NODE_NAME="$(default_node_name)"
APPROVE=1
ENABLE_SERVICE=1
DRY_RUN=0
CONTROL_URLS=()
BOOTSTRAP_URL=""
AGENT_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-src)
      BIN_SRC="$2"
      shift 2
      ;;
    --bin-dest)
      BIN_DEST="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    --control-url)
      CONTROL_URLS+=("$2")
      shift 2
      ;;
    --bootstrap-url)
      BOOTSTRAP_URL="$2"
      shift 2
      ;;
    --service-manager)
      SERVICE_MANAGER="$2"
      shift 2
      ;;
    --agent-arg)
      AGENT_ARGS+=("$2")
      shift 2
      ;;
    --register-url-network-id)
      REGISTER_URL_NETWORK_ID="$2"
      shift 2
      ;;
    --register-token-file)
      REGISTER_TOKEN_FILE="$2"
      shift 2
      ;;
    --register-node-name)
      REGISTER_NODE_NAME="$2"
      shift 2
      ;;
    --no-approve)
      APPROVE=0
      shift
      ;;
    --no-enable)
      ENABLE_SERVICE=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
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

if [[ -z "$STATE_DIR" ]]; then
  STATE_DIR="/var/lib/lightscale-client/${PROFILE}"
fi

if [[ -z "$BIN_SRC" ]]; then
  BIN_SRC="$(command -v lightscale-client || true)"
fi
[[ -n "$BIN_SRC" ]] || die "--bin-src not set and lightscale-client not found in PATH"
[[ -x "$BIN_SRC" ]] || die "binary is not executable: $BIN_SRC"

if [[ -n "$REGISTER_URL_NETWORK_ID" && -n "$REGISTER_TOKEN_FILE" ]]; then
  die "set only one of --register-url-network-id or --register-token-file"
fi

if [[ ${#CONTROL_URLS[@]} -eq 0 ]]; then
  die "at least one --control-url is required"
fi

if [[ -z "$BOOTSTRAP_URL" ]]; then
  BOOTSTRAP_URL="${CONTROL_URLS[0]}"
fi

detect_service_manager() {
  if [[ "$SERVICE_MANAGER" != "auto" ]]; then
    printf '%s\n' "$SERVICE_MANAGER"
    return
  fi

  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    printf 'systemd\n'
    return
  fi
  if command -v rc-service >/dev/null 2>&1 && command -v openrc-run >/dev/null 2>&1; then
    printf 'openrc\n'
    return
  fi
  if [[ -x /sbin/procd || -f /etc/openwrt_release ]]; then
    printf 'procd\n'
    return
  fi
  printf 'none\n'
}

quote_join() {
  local out=""
  local arg
  for arg in "$@"; do
    if [[ -n "$out" ]]; then
      out+=" "
    fi
    out+="$(printf '%q' "$arg")"
  done
  printf '%s\n' "$out"
}

run_or_echo() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[dry-run] %s\n' "$(quote_join "$@")"
    return 0
  fi
  "$@"
}

write_file() {
  local path="$1"
  shift
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[dry-run] write %s\n' "$path"
    cat
    return 0
  fi
  cat >"$path"
}

ensure_dir() {
  run_or_echo mkdir -p "$1"
}

install_executable() {
  local src="$1"
  local dst="$2"
  if command -v install >/dev/null 2>&1; then
    run_or_echo install -m 0755 "$src" "$dst"
    return
  fi
  run_or_echo cp "$src" "$dst"
  run_or_echo chmod 0755 "$dst"
}

ensure_dir "$(dirname "$BIN_DEST")"
ensure_dir "$(dirname "$CONFIG_PATH")"
ensure_dir "$STATE_DIR"

log "install binary: $BIN_SRC -> $BIN_DEST"
install_executable "$BIN_SRC" "$BIN_DEST"

if [[ ! -f "$CONFIG_PATH" ]]; then
  log "write default config: $CONFIG_PATH"
  write_file "$CONFIG_PATH" <<EOF
{
  "profiles": {
    "${PROFILE}": {
      "control_urls": [$(printf '"%s"' "${CONTROL_URLS[0]}")]
    }
  }
}
EOF
fi

daemon_cmd=("$BIN_DEST" "--profile" "$PROFILE" "--config" "$CONFIG_PATH" "--state-dir" "$STATE_DIR")
for url in "${CONTROL_URLS[@]}"; do
  daemon_cmd+=("--control-url" "$url")
done
daemon_cmd+=("daemon" "--profiles" "$PROFILE")
for arg in "${AGENT_ARGS[@]}"; do
  daemon_cmd+=("--agent-arg" "$arg")
done

mgr="$(detect_service_manager)"
case "$mgr" in
  systemd)
    need_cmd systemctl
    unit_name="lightscale-client-${PROFILE}.service"
    unit_path="/etc/systemd/system/${unit_name}"
    log "install systemd unit: $unit_path"
    write_file "$unit_path" <<EOF
[Unit]
Description=Lightscale client (${PROFILE})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$(quote_join "${daemon_cmd[@]}")
Restart=on-failure
RestartSec=2
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    if [[ "$ENABLE_SERVICE" == "1" ]]; then
      run_or_echo systemctl daemon-reload
      run_or_echo systemctl enable --now "$unit_name"
    fi
    ;;
  openrc)
    need_cmd rc-service
    service_name="lightscale-client-${PROFILE}"
    service_path="/etc/init.d/${service_name}"
    log "install OpenRC service: $service_path"
    write_file "$service_path" <<EOF
#!/sbin/openrc-run
name="lightscale-client (${PROFILE})"
command="$(printf '%q' "$BIN_DEST")"
command_args="$(quote_join "${daemon_cmd[@]:1}")"
command_background="yes"
pidfile="/run/${service_name}.pid"
EOF
    run_or_echo chmod +x "$service_path"
    if [[ "$ENABLE_SERVICE" == "1" ]]; then
      run_or_echo rc-update add "$service_name" default
      run_or_echo rc-service "$service_name" start
    fi
    ;;
  procd)
    service_name="lightscale-client-${PROFILE}"
    service_path="/etc/init.d/${service_name}"
    log "install procd service: $service_path"
    write_file "$service_path" <<EOF
#!/bin/sh /etc/rc.common
START=95
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command $(quote_join "${daemon_cmd[@]}")
  procd_set_param respawn 5 10 0
  procd_close_instance
}
EOF
    run_or_echo chmod +x "$service_path"
    if [[ "$ENABLE_SERVICE" == "1" ]]; then
      run_or_echo "$service_path" enable
      run_or_echo "$service_path" start
    fi
    ;;
  none)
    log "no supported service manager detected; run daemon manually:"
    printf '%s\n' "$(quote_join "${daemon_cmd[@]}")"
    ;;
  *)
    die "unsupported service manager: $mgr"
    ;;
esac

run_registration=0
register_cmd=("$BIN_DEST" "--profile" "$PROFILE" "--config" "$CONFIG_PATH" "--state-dir" "$STATE_DIR" "--bootstrap-url" "$BOOTSTRAP_URL")

if [[ -n "$REGISTER_URL_NETWORK_ID" ]]; then
  register_cmd+=("register-url" "$REGISTER_URL_NETWORK_ID" "--node-name" "$REGISTER_NODE_NAME")
  if [[ "$APPROVE" == "1" ]]; then
    register_cmd+=("--approve")
  fi
  run_registration=1
fi

if [[ -n "$REGISTER_TOKEN_FILE" ]]; then
  [[ -r "$REGISTER_TOKEN_FILE" ]] || die "token file not readable: $REGISTER_TOKEN_FILE"
  token="$(tr -d '\r\n' <"$REGISTER_TOKEN_FILE")"
  [[ -n "$token" ]] || die "token file is empty: $REGISTER_TOKEN_FILE"
  register_cmd+=("register" "--node-name" "$REGISTER_NODE_NAME" "--" "$token")
  run_registration=1
fi

if [[ "$run_registration" == "1" ]]; then
  log "run first registration"
  run_or_echo "${register_cmd[@]}"
else
  log "skip registration (--register-url-network-id or --register-token-file not set)"
fi

log "done"
