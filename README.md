# lightscale-client

Minimal control-plane client for Lightscale. It registers nodes, sends heartbeats, fetches
netmaps, and can manage the WireGuard data plane (kernel or userspace) with basic NAT traversal.

This client already uses profile-scoped state files so multiple networks can be supported later by
running separate profiles.

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

Register a node with an auth URL flow:

```sh
cargo run -- --profile default register-url <network_id> --node-name laptop
```

The command prints a one-time approval URL. Open it in a browser (or curl it) to approve the node.

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
