# lightscale-client

Minimal control-plane client for Lightscale. It registers nodes, sends heartbeats, fetches
netmaps, and can manage the WireGuard data plane (kernel or userspace) with basic NAT traversal.

This client uses profile-scoped state files, and can run multiple profiles/networks at once with
the `daemon` command (no systemd-specific runtime required).

## Configure a profile

```sh
cargo run -- --profile default init http://127.0.0.1:8080
```

Multiple control URLs (failover):

```sh
cargo run -- --profile default init http://10.0.0.1:8080,http://10.0.0.1:8081
```

## Register a node

```sh
cargo run -- --profile default register <token> --node-name laptop
```

Register with fixed private keys:

```sh
cargo run -- --profile default register <token> --node-name laptop \
  --machine-private-key-file /etc/lightscale/keys/machine.key \
  --wg-private-key-file /etc/lightscale/keys/wg.key
```

First-time bootstrap with an explicit control URL:

```sh
cargo run -- --profile default --bootstrap-url http://127.0.0.1:8080 register <token> --node-name laptop
```

Register a node with an auth URL flow:

```sh
cargo run -- --profile default register-url <network_id> --node-name laptop
```

The command prints a one-time approval URL. Open it in a browser (or curl it) to approve the node.
Successful registration stores the resolved control URLs in the profile config for later runs.

If you use `lightscale-admin`, pass `--admin-url` to print a login+approval URL:

```sh
cargo run -- --profile default register-url <network_id> --node-name laptop \
  --admin-url https://admin.example.com/
```

That URL requires login first, then shows an explicit confirmation button by default.

If you want login-only approval (no extra button), add `--admin-auto-approve`:

```sh
cargo run -- --profile default register-url <network_id> --node-name laptop \
  --admin-url https://admin.example.com/ \
  --admin-auto-approve
```

Approve immediately in one command (no enrollment token file):

```sh
cargo run -- --profile default register-url <network_id> --node-name laptop --approve
```

Use fixed private keys (for declarative/static host provisioning):

```sh
cargo run -- --profile default register-url <network_id> --node-name laptop \
  --machine-private-key-file /etc/lightscale/keys/machine.key \
  --wg-private-key-file /etc/lightscale/keys/wg.key
```

`--machine-private-key-file` and `--wg-private-key-file` expect base64-encoded
32-byte private keys.

## Admin actions

Set an admin token when the control plane is protected (CLI flag or env var):

```sh
export LIGHTSCALE_ADMIN_TOKEN=<token>
```

List nodes in a network (use `--pending` to show only unapproved nodes):

```sh
cargo run -- --profile default admin nodes <network_id> --pending
```

Update a node's name or tags (admin):

```sh
cargo run -- --profile default admin node update <node_id> --name laptop --tags dev,lab
```

Clear tags:

```sh
cargo run -- --profile default admin node update <node_id> --clear-tags
```

Approve a node by ID:

```sh
cargo run -- --profile default admin approve <node_id>
```

Create an enrollment token:

```sh
cargo run -- --profile default admin token create <network_id> --ttl-seconds 3600 --uses 1 --tags lab
```

Revoke an enrollment token:

```sh
cargo run -- --profile default admin token revoke <token>
```

## Heartbeat

```sh
cargo run -- --profile default heartbeat \
  --endpoint 203.0.113.1:51820 \
  --route 192.168.10.0/24
```

Optionally include your WireGuard listen port so the server can add the observed
public endpoint from the heartbeat connection:

```sh
cargo run -- --profile default heartbeat --listen-port 51820
```

Use STUN to discover a public endpoint (best effort):

```sh
cargo run -- --profile default heartbeat --stun --stun-server stun.l.google.com:19302
```

Advertise exit node routes:

```sh
cargo run -- --profile default heartbeat --exit-node
```

## Fetch netmap

```sh
cargo run -- --profile default netmap
```

## Show status

```sh
cargo run -- --profile default status
```

Include WireGuard peer info (handshake age + endpoint):

```sh
cargo run -- --profile default status --wg
```

Inspect host platform support tiers:

```sh
cargo run -- platform
```

JSON output (for automation/CI checks):

```sh
cargo run -- platform --json
```

`wg-up`, `wg-down`, `agent`, `daemon`, and `router` are explicitly guarded as
Linux-only data-plane commands.

Official support tiers (Linux full client, desktop control-plane tier, mobile
integration contract) are documented in `../docs/platform-support.md`.

## Configure WireGuard (Linux)

Bring up an interface using the latest netmap:

```sh
sudo cargo run -- --profile default wg-up --listen-port 51820
```

Use boringtun (userspace WireGuard) instead of the kernel module:

```sh
sudo cargo run -- --profile default wg-up --listen-port 51820 --backend boringtun
```

This runs the userspace tunnel inside the client process. Keep the command
running (or use `agent`) to keep the tunnel alive.

Apply advertised subnet/exit routes at the same time:

```sh
sudo cargo run -- --profile default wg-up --listen-port 51820 --apply-routes --accept-exit-node
```

Optionally probe peers to trigger NAT traversal (UDP probe, no ICMP):

```sh
sudo cargo run -- --profile default wg-up --listen-port 51820 --probe-peers
```

Conflicting routes are skipped by default; use `--allow-route-conflicts` to force them.

Select a specific exit node by ID or name:

```sh
sudo cargo run -- --profile default wg-up --listen-port 51820 --apply-routes --accept-exit-node \
  --exit-node-id <peer_id>
```

Remove the interface:

```sh
sudo cargo run -- --profile default wg-down
```

If you used the boringtun backend, stop the process that created the tunnel
(for example `Ctrl+C` in the foreground or stopping the agent). The command
below attempts to remove the interface if needed.

```sh
sudo cargo run -- --profile default wg-down --backend boringtun
```

## Run the agent loop

Keep WireGuard and routes updated using long-polling + periodic heartbeats:

```sh
sudo cargo run -- --profile default agent --listen-port 51820 --apply-routes --accept-exit-node \
  --heartbeat-interval 30 --longpoll-timeout 30
```

Tune endpoint rotation (stale seconds + max rotations before relay fallback):

```sh
sudo cargo run -- --profile default agent --listen-port 51820 \
  --endpoint-stale-after 15 --endpoint-max-rotations 2
```

When relay is active, periodically re-probe direct paths and return to direct when it works:

```sh
sudo cargo run -- --profile default agent --listen-port 51820 --stream-relay \
  --relay-reprobe-after 60
```

Use boringtun backend in the agent:

```sh
sudo cargo run -- --profile default agent --listen-port 51820 --backend boringtun
```

Enable STUN discovery in the agent:

```sh
sudo cargo run -- --profile default agent --listen-port 51820 --stun \
  --stun-server stun.l.google.com:19302
```

Enable stream relay signaling (peer probe via relay):

```sh
sudo cargo run -- --profile default agent --listen-port 51820 --stream-relay
```

With `--stream-relay`, the agent also maintains local relay tunnels that can be
used as a fallback when direct endpoints stop handshaking.

Probe peers when netmap updates arrive (UDP probe to endpoints, no ICMP):

```sh
sudo cargo run -- --profile default agent --listen-port 51820 --probe-peers
```

## Run multiple profiles from config (daemon mode)

You can run multiple networks/profiles in one command:

```sh
sudo lightscale-client --config /etc/lightscale/config.json daemon
```

`daemon` profile selection order:

- Use `--profiles` when provided.
- Otherwise start all profiles with `autostart: true`.
- If none are marked `autostart`, fall back to `--profile` (default: `default`).

This keeps single-profile usage simple: after registration, plain `daemon` works
without `--profile` or `--state-dir` flags.

```sh
sudo lightscale-client daemon
```

You can also target specific profiles:

```sh
sudo lightscale-client --config /etc/lightscale/config.json daemon --profiles infra,lab
```

If a selected profile has no `agent_args`, you can provide fallback runtime args from CLI:

```sh
sudo lightscale-client daemon --profiles infra --agent-arg=--listen-port --agent-arg=51820
```

Example config (all runtime flags live in config, including multi-network setup):

```json
{
  "profiles": {
    "infra": {
      "control_urls": ["https://cp1.example.com", "https://cp2.example.com"],
      "tls_pinned_sha256": "....",
      "autostart": true,
      "state_dir": "/var/lib/lightscale-client/infra",
      "agent_args": [
        "--listen-port", "51820",
        "--apply-routes",
        "--stun",
        "--stream-relay",
        "--probe-peers"
      ]
    },
    "lab": {
      "control_urls": ["https://lab-cp.example.com"],
      "autostart": true,
      "state_dir": "/var/lib/lightscale-client/lab",
      "agent_args": [
        "--listen-port", "51821",
        "--apply-routes"
      ]
    }
  }
}
```

## Linux installer script (systemd/OpenRC/procd)

For non-NixOS Linux and embedded distros, use the repository installer:

```sh
sudo ./packaging/linux/install-lightscale-client.sh \
  --control-url https://vpn.example.com:8080 \
  --register-url-network-id <network-id>
```

The script detects `systemd`, `OpenRC`, or `procd` (`--service-manager auto`)
and installs a matching service file. Use `--dry-run` to preview generated files.
The installer is a Bash script. `.deb`/`.rpm`/Alpine `.apk` package metadata
includes a `bash` runtime dependency. For OpenWrt native packages, install
`bash` before running the installer helper script.

## Build distro packages (.deb/.rpm/.apk)

Build release packages from an already-compiled binary:

```sh
cargo build --release
# prerequisite: fpm + rpmbuild
./packaging/linux/build-packages.sh
```

Build only selected formats:

```sh
./packaging/linux/build-packages.sh --formats deb,rpm
./packaging/linux/build-packages.sh --formats apk
```

For `apk` (Alpine), use a musl-compatible binary
(for example built on Alpine with `RUSTFLAGS="-C target-feature=-crt-static"`),
then pass it via `--bin-path`.

Note: `build-packages.sh` emits Alpine-format `.apk` packages. OpenWrt requires
its own feed package format (`apk` v3), so OpenWrt package artifacts are tracked
separately.

## Build OpenWrt native package (apk v3 feed format)

Use the OpenWrt SDK packager with an OpenWrt-compatible (musl) binary:

```sh
./packaging/openwrt/build-openwrt-package.sh \
  --bin-path dist/apk-bin/lightscale-client-musl
```

Outputs are written to `dist/packages-openwrt/` (for example
`lightscale-client-<version>-r<release>.apk`).

Run OpenWrt install smoke checks inside an OpenWrt environment:

```sh
./packaging/openwrt/smoke-openwrt-package.sh \
  --package dist/packages-openwrt/<file>.apk
```

The OpenWrt package ships the installer helper at
`/usr/lib/lightscale/install-lightscale-client.sh`; this helper requires `bash`.

## Smoke test distro packages (.deb/.rpm/.apk)

Outputs are written to `dist/packages/`:

- `lightscale-client_*.deb`
- `lightscale-client-*.rpm`
- `lightscale-client-*.apk`

Run install smoke tests inside target distro environments:

```sh
./packaging/linux/smoke-package-install.sh --format deb --package dist/packages/<file>.deb
./packaging/linux/smoke-package-install.sh --format rpm --package dist/packages/<file>.rpm
./packaging/linux/smoke-package-install.sh --format apk --package dist/packages/<file>.apk
```

## Systemd-less Linux / OpenWrt-style runtime

`lightscale-client` does not require systemd. After initial `init` + registration, run
the daemon directly and supervise it with your distro init (or a shell script).

OpenWrt (no-systemd) can run the same client binary and use the `procd` service
generation path. Build/copy a musl binary first, then run:

```sh
cp ./lightscale-client /usr/local/bin/lightscale-client
./packaging/linux/install-lightscale-client.sh \
  --bin-src /usr/local/bin/lightscale-client \
  --bin-dest /usr/local/bin/lightscale-client \
  --service-manager procd \
  --control-url https://vpn.example.com:8080 \
  --register-url-network-id <network-id>
```

Single-profile example:

```sh
lightscale-client --profile edge --config /etc/lightscale/config.json \
  --state-dir /var/lib/lightscale/edge \
  daemon --profiles edge \
  --agent-arg=--listen-port --agent-arg=51820 \
  --agent-arg=--heartbeat-interval --agent-arg=10 \
  --agent-arg=--longpoll-timeout --agent-arg=10 \
  --agent-arg=--stream-relay
```

One-command URL approval bootstrap without enrollment token file:

```sh
lightscale-client --profile edge --config /etc/lightscale/config.json \
  --state-dir /var/lib/lightscale/edge \
  --bootstrap-url https://vpn.example.com:8080 \
  register-url <network-id> --approve
```

## Enable subnet/exit routing (Linux)

Configure IP forwarding and (optionally) SNAT for a subnet router or exit node.
This uses nftables via `libmnl`/`libnftnl` (the Nix dev shell installs them):

```sh
sudo cargo run -- --profile default router enable --interface ls-default --out-interface eth0
```

Disable SNAT to require return routes on the LAN:

```sh
sudo cargo run -- --profile default router enable --interface ls-default --out-interface eth0 --no-snat
```

Remove forwarding/NAT rules:

```sh
sudo cargo run -- --profile default router disable --interface ls-default --out-interface eth0
```

## DNS and relay info

Export host-style DNS entries:

```sh
cargo run -- --profile default dns
```

Export DNS info as JSON (debug output):

```sh
cargo run -- --profile default dns --format json --output /tmp/lightscale-dns.json
```

Show relay configuration (STUN/TURN/stream relay/UDP relay):

```sh
cargo run -- --profile default relay
```

## UDP relay (best effort)

Send a test message via the UDP relay:

```sh
cargo run -- --profile default relay-udp send <peer-id> "hello"
```

Listen for relay messages:

```sh
cargo run -- --profile default relay-udp listen
```

## Stream relay (best effort)

Send a test message via the stream relay:

```sh
cargo run -- --profile default relay-stream send <peer-id> "hello"
```

Listen for relay messages:

```sh
cargo run -- --profile default relay-stream listen
```
