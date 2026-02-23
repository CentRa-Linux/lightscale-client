mod config;
mod control;
mod data_plane;
mod dns_server;
mod firewall;
mod keys;
mod l2_relay;
mod model;
mod netlink;
mod platform;
mod relay_tunnel;
mod resource_guard;
mod router;
mod routes;
mod state;
mod stream_relay;
mod stun;
mod turn;
mod udp_relay;
#[cfg(target_os = "linux")]
mod wg;
#[cfg(not(target_os = "linux"))]
#[path = "wg_portable.rs"]
mod wg;

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use config::{default_config_path, load_config, save_config, ClientConfig, ProfileConfig};
use control::ControlClient;
use ipnet::IpNet;
use model::{HeartbeatRequest, Route, RouteKind};
use sha2::{Digest, Sha256};
use state::{default_state_dir, load_state, save_state, state_path, ClientState};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command as TokioCommand;
use tokio::time::sleep;

#[derive(Parser, Debug)]
#[command(name = "lightscale-client")]
struct Args {
    #[arg(long, default_value = "default")]
    profile: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(
        long,
        alias = "bootstrap-url",
        value_name = "URL",
        value_delimiter = ',',
        action = ArgAction::Append
    )]
    control_url: Vec<String>,
    #[arg(long)]
    tls_pin: Option<String>,
    #[arg(long, env = "LIGHTSCALE_ADMIN_TOKEN")]
    admin_token: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init {
        #[arg(value_name = "URL", value_delimiter = ',')]
        control_url: Vec<String>,
    },
    Pin {
        #[arg(long)]
        force: bool,
    },
    Register {
        token: String,
        #[arg(long)]
        node_name: Option<String>,
        #[arg(long, value_name = "PATH")]
        machine_private_key_file: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        wg_private_key_file: Option<PathBuf>,
    },
    RegisterUrl {
        network_id: String,
        #[arg(long)]
        node_name: Option<String>,
        #[arg(long, value_name = "PATH")]
        machine_private_key_file: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        wg_private_key_file: Option<PathBuf>,
        #[arg(long)]
        ttl_seconds: Option<u64>,
        #[arg(long)]
        admin_url: Option<String>,
        #[arg(long)]
        admin_auto_approve: bool,
        #[arg(long)]
        approve: bool,
    },
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Heartbeat {
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Vec<String>,
        #[arg(long)]
        listen_port: Option<u16>,
        #[arg(long, value_name = "PREFIX")]
        route: Vec<String>,
        #[arg(long, value_name = "REAL=MAPPED")]
        route_map: Vec<String>,
        #[arg(long)]
        exit_node: bool,
        #[arg(long)]
        stun: bool,
        #[arg(long, value_name = "HOST:PORT", value_delimiter = ',')]
        stun_server: Vec<String>,
        #[arg(long)]
        stun_port: Option<u16>,
        #[arg(long, default_value_t = 3)]
        stun_timeout: u64,
    },
    Netmap,
    Status {
        #[arg(long)]
        wg: bool,
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, value_enum, default_value = "kernel")]
        backend: WgBackend,
    },
    RotateKeys {
        #[arg(long)]
        machine: bool,
        #[arg(long)]
        wg: bool,
    },
    WgUp {
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value_t = 51820)]
        listen_port: u16,
        #[arg(long, value_enum, default_value = "kernel")]
        backend: WgBackend,
        #[arg(long)]
        apply_routes: bool,
        #[arg(long)]
        accept_exit_node: bool,
        #[arg(long)]
        exit_node_id: Option<String>,
        #[arg(long)]
        exit_node_name: Option<String>,
        #[arg(long, value_enum, default_value = "first")]
        exit_node_policy: ExitNodePolicyArg,
        #[arg(long)]
        exit_node_tag: Option<String>,
        #[arg(long)]
        exit_node_metric_base: Option<u32>,
        #[arg(long, value_name = "UID_OR_RANGE")]
        exit_node_uid_range: Option<String>,
        #[arg(long)]
        allow_route_conflicts: bool,
        #[arg(long)]
        route_table: Option<u32>,
        #[arg(long)]
        probe_peers: bool,
        #[arg(long, default_value_t = 1)]
        probe_timeout: u64,
    },
    WgDown {
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, value_enum, default_value = "kernel")]
        backend: WgBackend,
    },
    Agent {
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value_t = 51820)]
        listen_port: u16,
        #[arg(long)]
        apply_routes: bool,
        #[arg(long)]
        accept_exit_node: bool,
        #[arg(long)]
        exit_node_id: Option<String>,
        #[arg(long)]
        exit_node_name: Option<String>,
        #[arg(long, value_enum, default_value = "first")]
        exit_node_policy: ExitNodePolicyArg,
        #[arg(long)]
        exit_node_tag: Option<String>,
        #[arg(long)]
        exit_node_metric_base: Option<u32>,
        #[arg(long, value_name = "UID_OR_RANGE")]
        exit_node_uid_range: Option<String>,
        #[arg(long)]
        allow_route_conflicts: bool,
        #[arg(long)]
        route_table: Option<u32>,
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Vec<String>,
        #[arg(long, value_name = "PREFIX")]
        advertise_route: Vec<String>,
        #[arg(long, value_name = "REAL=MAPPED")]
        advertise_map: Vec<String>,
        #[arg(long)]
        advertise_exit_node: bool,
        #[arg(long, default_value_t = 30)]
        heartbeat_interval: u64,
        #[arg(long, default_value_t = 30)]
        longpoll_timeout: u64,
        #[arg(long, value_enum, default_value = "kernel")]
        backend: WgBackend,
        #[arg(long)]
        stun: bool,
        #[arg(long, value_name = "HOST:PORT", value_delimiter = ',')]
        stun_server: Vec<String>,
        #[arg(long)]
        stun_port: Option<u16>,
        #[arg(long, default_value_t = 3)]
        stun_timeout: u64,
        #[arg(long)]
        probe_peers: bool,
        #[arg(long, default_value_t = 1)]
        probe_timeout: u64,
        #[arg(long)]
        stream_relay: bool,
        #[arg(long, value_name = "HOST:PORT", value_delimiter = ',')]
        stream_relay_server: Vec<String>,
        #[arg(long, default_value_t = 15)]
        endpoint_stale_after: u64,
        #[arg(long, default_value_t = 2)]
        endpoint_max_rotations: u64,
        #[arg(long, default_value_t = 60)]
        relay_reprobe_after: u64,
        #[arg(long)]
        dns_hosts_path: Option<PathBuf>,
        #[arg(long)]
        dns_serve: bool,
        #[arg(long)]
        dns_listen: Option<String>,
        #[arg(long)]
        dns_apply_resolver: bool,
        #[arg(long)]
        l2_relay: bool,
        #[arg(long, help = "Clean up existing resources before starting")]
        cleanup_before_start: bool,
        #[arg(long, value_name = "PATH", help = "PID file path for single-instance enforcement")]
        pid_file: Option<PathBuf>,
    },
    Daemon {
        #[arg(long, value_delimiter = ',')]
        profiles: Vec<String>,
        #[arg(
            long = "agent-arg",
            action = ArgAction::Append,
            value_name = "ARG",
            allow_hyphen_values = true
        )]
        agent_arg: Vec<String>,
    },
    Router {
        #[command(subcommand)]
        command: RouterCommand,
    },
    RelayUdp {
        #[command(subcommand)]
        command: RelayUdpCommand,
    },
    RelayStream {
        #[command(subcommand)]
        command: RelayStreamCommand,
    },
    RelayTurn {
        #[command(subcommand)]
        command: RelayTurnCommand,
    },
    Platform {
        #[arg(long)]
        json: bool,
    },
    Dns {
        #[arg(long, value_enum, default_value = "hosts")]
        format: DnsFormat,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        apply_hosts: bool,
        #[arg(long)]
        hosts_path: Option<PathBuf>,
    },
    DnsServe {
        #[arg(long, default_value = "127.0.0.1:53")]
        listen: String,
        #[arg(long)]
        apply_resolver: bool,
        #[arg(long)]
        interface: Option<String>,
    },
    Relay,
}

#[derive(clap::ValueEnum, Debug, Clone)]
enum DnsFormat {
    Hosts,
    Json,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum WgBackend {
    Kernel,
    Boringtun,
}

impl From<WgBackend> for wg::Backend {
    fn from(value: WgBackend) -> Self {
        match value {
            WgBackend::Kernel => wg::Backend::Kernel,
            WgBackend::Boringtun => wg::Backend::Boringtun,
        }
    }
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum ExitNodePolicyArg {
    First,
    Latest,
    Multi,
}

impl From<ExitNodePolicyArg> for routes::ExitNodePolicy {
    fn from(value: ExitNodePolicyArg) -> Self {
        match value {
            ExitNodePolicyArg::First => routes::ExitNodePolicy::First,
            ExitNodePolicyArg::Latest => routes::ExitNodePolicy::Latest,
            ExitNodePolicyArg::Multi => routes::ExitNodePolicy::Multi,
        }
    }
}

#[derive(Subcommand, Debug)]
enum RouterCommand {
    Enable {
        #[arg(long)]
        interface: Option<String>,
        #[arg(long)]
        out_interface: Option<String>,
        #[arg(long, value_name = "REAL=MAPPED")]
        map: Vec<String>,
        #[arg(long)]
        no_snat: bool,
    },
    Disable {
        #[arg(long)]
        interface: Option<String>,
        #[arg(long)]
        out_interface: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RelayUdpCommand {
    Send {
        peer_id: String,
        message: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long, default_value_t = 3)]
        timeout: u64,
    },
    Listen {
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RelayStreamCommand {
    Send {
        peer_id: String,
        message: String,
        #[arg(long)]
        server: Option<String>,
    },
    Listen {
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RelayTurnCommand {
    Send {
        peer_addr: String,
        message: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = 3)]
        timeout: u64,
    },
    Listen {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        peer_addr: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AdminCommand {
    Node {
        #[command(subcommand)]
        command: AdminNodeCommand,
    },
    Nodes {
        network_id: String,
        #[arg(long)]
        pending: bool,
    },
    Approve {
        node_id: String,
    },
    Token {
        #[command(subcommand)]
        command: AdminTokenCommand,
    },
    Acl {
        #[command(subcommand)]
        command: AdminAclCommand,
    },
    KeyPolicy {
        #[command(subcommand)]
        command: AdminKeyPolicyCommand,
    },
    Keys {
        #[command(subcommand)]
        command: AdminKeysCommand,
    },
    Audit {
        #[arg(long)]
        network_id: Option<String>,
        #[arg(long)]
        node_id: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Subcommand, Debug)]
enum AdminTokenCommand {
    Create {
        network_id: String,
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: u64,
        #[arg(long, default_value_t = 1)]
        uses: u32,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    Revoke {
        token: String,
    },
}

#[derive(Subcommand, Debug)]
enum AdminNodeCommand {
    Update {
        node_id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        clear_tags: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AdminAclCommand {
    Get {
        network_id: String,
    },
    Set {
        network_id: String,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        json: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AdminKeyPolicyCommand {
    Get {
        network_id: String,
    },
    Set {
        network_id: String,
        #[arg(long)]
        max_age_seconds: Option<u64>,
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AdminKeysCommand {
    Rotate {
        node_id: String,
        #[arg(long)]
        machine_public_key: Option<String>,
        #[arg(long)]
        wg_public_key: Option<String>,
    },
    History {
        node_id: String,
    },
    Revoke {
        node_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let data_plane = data_plane::for_current_platform();

    match &args.command {
        Command::Init { control_url } => {
            let config_path = resolve_config_path(&args)?;
            let mut config = load_config(&config_path)?;
            let control_urls = normalize_control_urls(control_url.clone());
            if control_urls.is_empty() {
                return Err(anyhow!("control URL not set; provide at least one URL"));
            }
            config.profiles.insert(
                args.profile.clone(),
                ProfileConfig {
                    control_urls,
                    tls_pinned_sha256: None,
                    ..ProfileConfig::default()
                },
            );
            save_config(&config_path, &config)?;
            println!("saved config for profile {}", args.profile);
        }
        Command::Pin { force } => {
            let config_path = resolve_config_path(&args)?;
            let mut config = load_config(&config_path)?;
            let control_urls = resolve_control_urls(&args, Some(&config))?;
            let profile = config
                .profiles
                .entry(args.profile.clone())
                .or_insert(ProfileConfig {
                    control_urls: control_urls.clone(),
                    tls_pinned_sha256: None,
                    ..ProfileConfig::default()
                });
            profile.control_urls = control_urls.clone();
            if profile.tls_pinned_sha256.is_some() && !*force {
                return Err(anyhow!("tls pin already set; use --force to overwrite"));
            }
            let pin = fetch_server_fingerprint_any(&control_urls).await?;
            profile.tls_pinned_sha256 = Some(pin.clone());
            save_config(&config_path, &config)?;
            println!("tls pin saved: {}", pin);
        }
        Command::Register {
            token,
            node_name,
            machine_private_key_file,
            wg_private_key_file,
        } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let admin_token = resolve_admin_token(&args);
            let state_path = resolve_state_path(&args)?;

            if load_state(&state_path)?.is_some() {
                return Err(anyhow!("state already exists for profile {}", args.profile));
            }

            let machine_keys = resolve_machine_keys(machine_private_key_file.as_ref())?;
            let wg_keys = resolve_wg_keys(wg_private_key_file.as_ref())?;
            let node_name = node_name.clone().unwrap_or_else(default_node_name);

            let client =
                ControlClient::new(control_urls.clone(), tls_pin.clone(), None, admin_token)?;
            let response = client
                .register(model::RegisterRequest {
                    token: token.clone(),
                    node_name: node_name.clone(),
                    machine_public_key: machine_keys.public_key.clone(),
                    wg_public_key: wg_keys.public_key.clone(),
                })
                .await
                .context("register failed")?;

            let now = now_unix();
            let netmap = response.netmap;
            let state = ClientState {
                profile: args.profile.clone(),
                network_id: netmap.network.id.clone(),
                node_id: netmap.node.id.clone(),
                node_name,
                machine_private_key: machine_keys.private_key,
                machine_public_key: machine_keys.public_key,
                wg_private_key: wg_keys.private_key,
                wg_public_key: wg_keys.public_key,
                node_token: Some(response.node_token),
                ipv4: netmap.node.ipv4.clone(),
                ipv6: netmap.node.ipv6.clone(),
                last_netmap: Some(netmap),
                updated_at: now,
            };

            save_state(&state_path, &state)?;
            persist_profile_control_urls(&args, &control_urls, tls_pin.as_deref())?;
            if state
                .last_netmap
                .as_ref()
                .map(|netmap| netmap.node.approved)
                .unwrap_or(false)
            {
                println!(
                    "registered node {} on network {}",
                    state.node_id, state.network_id
                );
            } else {
                println!(
                    "registered node {} on network {} (pending approval)",
                    state.node_id, state.network_id
                );
            }
        }
        Command::RegisterUrl {
            network_id,
            node_name,
            machine_private_key_file,
            wg_private_key_file,
            ttl_seconds,
            admin_url,
            admin_auto_approve,
            approve,
        } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let admin_token = resolve_admin_token(&args);
            let state_path = resolve_state_path(&args)?;

            if load_state(&state_path)?.is_some() {
                return Err(anyhow!("state already exists for profile {}", args.profile));
            }
            if *admin_auto_approve && admin_url.is_none() {
                return Err(anyhow!("--admin-auto-approve requires --admin-url"));
            }

            let machine_keys = resolve_machine_keys(machine_private_key_file.as_ref())?;
            let wg_keys = resolve_wg_keys(wg_private_key_file.as_ref())?;
            let node_name = node_name.clone().unwrap_or_else(default_node_name);

            let client = ControlClient::new(
                control_urls.clone(),
                tls_pin.clone(),
                None,
                admin_token.clone(),
            )?;
            let response = client
                .register_url(model::RegisterUrlRequest {
                    network_id: network_id.clone(),
                    node_name: node_name.clone(),
                    machine_public_key: machine_keys.public_key.clone(),
                    wg_public_key: wg_keys.public_key.clone(),
                    ttl_seconds: *ttl_seconds,
                })
                .await
                .context("register-url failed")?;

            let now = now_unix();
            let mut state = ClientState {
                profile: args.profile.clone(),
                network_id: response.network_id.clone(),
                node_id: response.node_id.clone(),
                node_name,
                machine_private_key: machine_keys.private_key,
                machine_public_key: machine_keys.public_key,
                wg_private_key: wg_keys.private_key,
                wg_public_key: wg_keys.public_key,
                node_token: Some(response.node_token.clone()),
                ipv4: response.ipv4.clone(),
                ipv6: response.ipv6.clone(),
                last_netmap: None,
                updated_at: now,
            };

            save_state(&state_path, &state)?;
            persist_profile_control_urls(&args, &control_urls, tls_pin.as_deref())?;
            let auth_urls: Vec<String> = control_urls
                .iter()
                .map(|base| format!("{}{}", base.trim_end_matches('/'), response.auth_path))
                .collect();
            println!("registered node {} (pending approval)", response.node_id);
            if let Some(admin_url) = admin_url {
                let login_approval_url = build_admin_login_approval_url(
                    admin_url,
                    &response.network_id,
                    &response.auth_path,
                    *admin_auto_approve,
                )?;
                if *admin_auto_approve {
                    println!(
                        "open this URL to login in lightscale-admin; approval runs automatically after authentication:"
                    );
                } else {
                    println!("open this URL to login and approve in lightscale-admin:");
                }
                println!("  {}", login_approval_url);
                if auth_urls.len() == 1 {
                    println!("direct control-plane approval URL:");
                    println!("  {}", auth_urls[0]);
                } else {
                    println!("direct control-plane approval URLs (fallback):");
                    for url in auth_urls {
                        println!("  {}", url);
                    }
                }
            } else if auth_urls.len() == 1 {
                println!("open this URL to approve: {}", auth_urls[0]);
            } else {
                println!("open one of these URLs to approve:");
                for url in auth_urls {
                    println!("  {}", url);
                }
            }
            if *approve {
                let approval = client
                    .approve_with_auth_path(&response.auth_path)
                    .await
                    .context("register-url auto-approve failed")?;
                println!(
                    "node {} approved={} approved_at={}",
                    approval.node_id,
                    approval.approved,
                    approval
                        .approved_at
                        .map(|ts| ts.to_string())
                        .unwrap_or_else(|| "none".to_string())
                );
                let refresh_client = ControlClient::new(
                    control_urls.clone(),
                    tls_pin.clone(),
                    Some(response.node_token.clone()),
                    admin_token.clone(),
                )?;
                let node_id = state.node_id.clone();
                let mut approved_synced = false;
                let mut last_netmap_err: Option<anyhow::Error> = None;
                for _ in 0..20 {
                    match refresh_client.netmap(&node_id).await {
                        Ok(netmap) => {
                            let approved = netmap.node.approved;
                            state.ipv4 = netmap.node.ipv4.clone();
                            state.ipv6 = netmap.node.ipv6.clone();
                            state.last_netmap = Some(netmap);
                            state.updated_at = now_unix();
                            save_state(&state_path, &state)?;
                            if approved {
                                approved_synced = true;
                                break;
                            }
                        }
                        Err(err) => {
                            last_netmap_err = Some(err);
                        }
                    }
                    sleep(Duration::from_millis(500)).await;
                }
                if !approved_synced {
                    if let Some(err) = last_netmap_err {
                        return Err(err).context("approval succeeded but netmap refresh failed");
                    }
                    return Err(anyhow!(
                        "node {} approval not visible in netmap after auto-approve",
                        state.node_id
                    ));
                }
                println!("local state updated: approved=true");
            }
        }
        Command::Admin { command } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let admin_token = resolve_admin_token(&args);
            let client =
                ControlClient::new(control_urls.clone(), tls_pin.clone(), None, admin_token)?;
            match command {
                AdminCommand::Node { command } => match command {
                    AdminNodeCommand::Update {
                        node_id,
                        name,
                        tags,
                        clear_tags,
                    } => {
                        let tags = if *clear_tags {
                            Some(Vec::new())
                        } else if !tags.is_empty() {
                            Some(tags.clone())
                        } else {
                            None
                        };
                        if name.is_none() && tags.is_none() {
                            return Err(anyhow!(
                                "no fields specified; use --name, --tags, or --clear-tags"
                            ));
                        }
                        let response = client
                            .update_node(
                                node_id,
                                model::UpdateNodeRequest {
                                    name: name.clone(),
                                    tags,
                                },
                            )
                            .await
                            .context("update node failed")?;
                        let node = response.node;
                        println!("node {} name={} tags={:?}", node.id, node.name, node.tags);
                    }
                },
                AdminCommand::Nodes {
                    network_id,
                    pending,
                } => {
                    let response = client
                        .admin_nodes(network_id)
                        .await
                        .context("admin nodes failed")?;
                    let now = now_unix();
                    for node in response.nodes {
                        if *pending && node.approved {
                            continue;
                        }
                        let age = now.saturating_sub(node.last_seen);
                        println!(
                            "node {} name={} approved={} last_seen={}s",
                            node.id, node.name, node.approved, age
                        );
                    }
                }
                AdminCommand::Approve { node_id } => {
                    let response = client
                        .approve_node(node_id)
                        .await
                        .context("approve node failed")?;
                    println!(
                        "node {} approved={} approved_at={}",
                        response.node_id,
                        response.approved,
                        response
                            .approved_at
                            .map(|ts| ts.to_string())
                            .unwrap_or_else(|| "none".to_string())
                    );
                }
                AdminCommand::Token { command } => match command {
                    AdminTokenCommand::Create {
                        network_id,
                        ttl_seconds,
                        uses,
                        tags,
                    } => {
                        let response = client
                            .create_token(
                                network_id,
                                model::CreateTokenRequest {
                                    ttl_seconds: *ttl_seconds,
                                    uses: *uses,
                                    tags: tags.clone(),
                                },
                            )
                            .await
                            .context("create token failed")?;
                        println!("token: {}", response.token.token);
                        println!("expires_at: {}", response.token.expires_at);
                        println!("uses_left: {}", response.token.uses_left);
                        if !response.token.tags.is_empty() {
                            println!("tags: {}", response.token.tags.join(","));
                        }
                    }
                    AdminTokenCommand::Revoke { token } => {
                        let response = client
                            .revoke_token(token)
                            .await
                            .context("revoke token failed")?;
                        println!("token: {}", response.token);
                        println!(
                            "revoked_at: {}",
                            response
                                .revoked_at
                                .map(|ts| ts.to_string())
                                .unwrap_or_else(|| "none".to_string())
                        );
                    }
                },
                AdminCommand::Acl { command } => match command {
                    AdminAclCommand::Get { network_id } => {
                        let policy = client
                            .get_acl(network_id)
                            .await
                            .context("fetch acl policy failed")?;
                        println!("{}", serde_json::to_string_pretty(&policy)?);
                    }
                    AdminAclCommand::Set {
                        network_id,
                        file,
                        json,
                    } => {
                        let policy = load_acl_policy(file.as_ref(), json.as_ref())?;
                        let response = client
                            .update_acl(network_id, model::UpdateAclRequest { policy })
                            .await
                            .context("update acl policy failed")?;
                        println!("{}", serde_json::to_string_pretty(&response.policy)?);
                    }
                },
                AdminCommand::KeyPolicy { command } => match command {
                    AdminKeyPolicyCommand::Get { network_id } => {
                        let response = client
                            .get_key_policy(network_id)
                            .await
                            .context("fetch key policy failed")?;
                        println!("{}", serde_json::to_string_pretty(&response.policy)?);
                    }
                    AdminKeyPolicyCommand::Set {
                        network_id,
                        max_age_seconds,
                        clear,
                    } => {
                        let policy = if *clear {
                            model::KeyRotationPolicy {
                                max_age_seconds: None,
                            }
                        } else {
                            model::KeyRotationPolicy {
                                max_age_seconds: *max_age_seconds,
                            }
                        };
                        let response = client
                            .update_key_policy(network_id, policy)
                            .await
                            .context("update key policy failed")?;
                        println!("{}", serde_json::to_string_pretty(&response.policy)?);
                    }
                },
                AdminCommand::Keys { command } => match command {
                    AdminKeysCommand::Rotate {
                        node_id,
                        machine_public_key,
                        wg_public_key,
                    } => {
                        let response = client
                            .rotate_keys(
                                node_id,
                                model::KeyRotationRequest {
                                    machine_public_key: machine_public_key.clone(),
                                    wg_public_key: wg_public_key.clone(),
                                },
                            )
                            .await
                            .context("rotate keys failed")?;
                        println!("node_id: {}", response.node_id);
                        println!("machine_public_key: {}", response.machine_public_key);
                        println!("wg_public_key: {}", response.wg_public_key);
                    }
                    AdminKeysCommand::History { node_id } => {
                        let response = client
                            .node_keys(node_id)
                            .await
                            .context("fetch key history failed")?;
                        println!("{}", serde_json::to_string_pretty(&response.keys)?);
                    }
                    AdminKeysCommand::Revoke { node_id } => {
                        let response = client
                            .revoke_node(node_id)
                            .await
                            .context("revoke node failed")?;
                        println!(
                            "node {} revoked_at={}",
                            response.node_id,
                            response
                                .revoked_at
                                .map(|ts| ts.to_string())
                                .unwrap_or_else(|| "none".to_string())
                        );
                    }
                },
                AdminCommand::Audit {
                    network_id,
                    node_id,
                    limit,
                } => {
                    let response = client
                        .audit_log(network_id.as_deref(), node_id.as_deref(), *limit)
                        .await
                        .context("fetch audit log failed")?;
                    println!("{}", serde_json::to_string_pretty(&response.entries)?);
                }
            }
        }
        Command::Heartbeat {
            endpoint,
            listen_port,
            route,
            route_map,
            exit_node,
            stun,
            stun_server,
            stun_port,
            stun_timeout,
        } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;
            let admin_token = resolve_admin_token(&args);

            let mut endpoints = endpoint.clone();
            if *stun {
                let stun_servers = gather_stun_servers(
                    &control_urls,
                    tls_pin.clone(),
                    &mut state,
                    &state_path,
                    stun_server,
                )
                .await?;
                if let Some(stun_endpoint) = maybe_stun_endpoint(
                    &stun_servers,
                    stun_port.or(Some(0)),
                    Duration::from_secs(*stun_timeout),
                )
                .await?
                {
                    endpoints.push(stun_endpoint);
                }
            }

            let route_maps = parse_route_maps(route_map)?;
            let routes = build_routes(route.clone(), route_maps, *exit_node);
            let client = ControlClient::new(
                control_urls.clone(),
                tls_pin.clone(),
                state.node_token.clone(),
                admin_token,
            )?;
            let response = client
                .heartbeat(HeartbeatRequest {
                    node_id: state.node_id.clone(),
                    endpoints,
                    listen_port: *listen_port,
                    routes,
                    probe: None,
                })
                .await
                .context("heartbeat failed")?;

            state.last_netmap = Some(response.netmap);
            state.updated_at = now_unix();
            save_state(&state_path, &state)?;
            println!("heartbeat ok for node {}", state.node_id);
        }
        Command::Netmap => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;

            let admin_token = resolve_admin_token(&args);
            let client = ControlClient::new(
                control_urls.clone(),
                tls_pin.clone(),
                state.node_token.clone(),
                admin_token,
            )?;
            let netmap = client
                .netmap(&state.node_id)
                .await
                .context("netmap fetch failed")?;

            state.last_netmap = Some(netmap.clone());
            state.updated_at = now_unix();
            save_state(&state_path, &state)?;

            println!("network: {}", netmap.network.name);
            println!("approved: {}", netmap.node.approved);
            if netmap.node.key_rotation_required {
                println!("key_rotation_required: true");
            }
            if netmap.node.revoked {
                println!("revoked: true");
            }
            println!("peers: {}", netmap.peers.len());
        }
        Command::Status {
            wg,
            interface,
            backend,
        } => {
            #[cfg(not(target_os = "linux"))]
            let _ = interface;

            if *wg {
                platform::require_linux_data_plane("status --wg")?;
            }
            let state_path = resolve_state_path(&args)?;
            let state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;
            println!("profile: {}", state.profile);
            println!("network: {}", state.network_id);
            println!("node: {}", state.node_id);
            println!("ipv4: {}", state.ipv4);
            println!("ipv6: {}", state.ipv6);
            if let Some(netmap) = state.last_netmap.as_ref() {
                println!("approved: {}", netmap.node.approved);
                if netmap.node.key_rotation_required {
                    println!("key_rotation_required: true");
                }
                if netmap.node.revoked {
                    println!("revoked: true");
                }
                println!("peers: {}", netmap.peers.len());
            }
            if *wg {
                #[cfg(target_os = "linux")]
                {
                    let iface = interface
                        .clone()
                        .unwrap_or_else(|| default_interface_name(&args.profile));
                    let backend = match backend {
                        WgBackend::Kernel => wireguard_control::Backend::Kernel,
                        WgBackend::Boringtun => wireguard_control::Backend::Userspace,
                    };
                    match iface.parse::<wireguard_control::InterfaceName>() {
                        Ok(iface_name) => match wireguard_control::Device::get(&iface_name, backend) {
                            Ok(device) => {
                                println!("wg interface: {}", iface);
                                let mut peers_by_key = HashMap::new();
                                if let Some(netmap) = state.last_netmap.as_ref() {
                                    for peer in &netmap.peers {
                                        peers_by_key.insert(peer.wg_public_key.clone(), peer);
                                    }
                                }
                                for peer in device.peers {
                                    let key = peer.config.public_key.to_base64();
                                    let name = peers_by_key
                                        .get(&key)
                                        .map(|peer| peer.name.as_str())
                                        .unwrap_or("<unknown>");
                                    let endpoint = peer
                                        .config
                                        .endpoint
                                        .map(|ep| ep.to_string())
                                        .unwrap_or_else(|| "none".to_string());
                                    let handshake =
                                        format_handshake_age(peer.stats.last_handshake_time);
                                    let allowed_ips = if peer.config.allowed_ips.is_empty() {
                                        "none".to_string()
                                    } else {
                                        peer.config
                                            .allowed_ips
                                            .iter()
                                            .map(|ip| format!("{}/{}", ip.address, ip.cidr))
                                            .collect::<Vec<_>>()
                                            .join(",")
                                    };
                                    println!(
                                        "peer {} {} handshake={} endpoint={} rx={} tx={} allowed_ips={}",
                                        name,
                                        key,
                                        handshake,
                                        endpoint,
                                        peer.stats.rx_bytes,
                                        peer.stats.tx_bytes,
                                        allowed_ips
                                    );
                                }
                            }
                            Err(err) => {
                                eprintln!("wg status unavailable for {}: {}", iface, err);
                            }
                        },
                        Err(err) => {
                            eprintln!("invalid interface name {}: {}", iface, err);
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = backend;
                    eprintln!("status --wg is only available on linux");
                }
            }
        }
        Command::RotateKeys { machine, wg } => {
            let rotate_machine = *machine || (!*machine && !*wg);
            let rotate_wg = *wg || (!*machine && !*wg);
            if !rotate_machine && !rotate_wg {
                return Err(anyhow!("no keys selected for rotation"));
            }
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;
            let admin_token = resolve_admin_token(&args);

            let mut machine_keys: Option<keys::KeyPair> = None;
            let mut wg_keys: Option<keys::KeyPair> = None;
            let request = model::KeyRotationRequest {
                machine_public_key: if rotate_machine {
                    let keys = keys::generate_machine_keys();
                    let public_key = keys.public_key.clone();
                    machine_keys = Some(keys);
                    Some(public_key)
                } else {
                    None
                },
                wg_public_key: if rotate_wg {
                    let keys = keys::generate_wg_keys();
                    let public_key = keys.public_key.clone();
                    wg_keys = Some(keys);
                    Some(public_key)
                } else {
                    None
                },
            };

            let client =
                ControlClient::new(control_urls, tls_pin, state.node_token.clone(), admin_token)?;
            let response = client
                .rotate_keys(&state.node_id, request)
                .await
                .context("rotate keys failed")?;

            if let Some(keys) = machine_keys {
                state.machine_private_key = keys.private_key;
                state.machine_public_key = keys.public_key;
            }
            if let Some(keys) = wg_keys {
                state.wg_private_key = keys.private_key;
                state.wg_public_key = keys.public_key;
            }
            state.updated_at = now_unix();
            save_state(&state_path, &state)?;

            println!("rotated keys for node {}", response.node_id);
        }
        Command::WgUp {
            interface,
            listen_port,
            backend,
            apply_routes,
            accept_exit_node,
            exit_node_id,
            exit_node_name,
            exit_node_policy,
            exit_node_tag,
            exit_node_metric_base,
            exit_node_uid_range,
            allow_route_conflicts,
            route_table,
            probe_peers,
            probe_timeout,
        } => {
            platform::require_data_plane("wg-up")?;
            if *apply_routes {
                data_plane::require_advertised_routes(data_plane.as_ref(), "wg-up --apply-routes")?;
            }
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;
            let admin_token = resolve_admin_token(&args);

            let client =
                ControlClient::new(control_urls, tls_pin, state.node_token.clone(), admin_token)?;
            let netmap = client
                .netmap(&state.node_id)
                .await
                .context("netmap fetch failed")?;

            state.last_netmap = Some(netmap.clone());
            state.updated_at = now_unix();
            save_state(&state_path, &state)?;

            let iface = interface
                .clone()
                .unwrap_or_else(|| default_interface_name(&args.profile));
            let cfg = wg::WgConfig {
                interface: iface.clone(),
                listen_port: *listen_port,
                backend: (*backend).into(),
            };
            let routes_cfg = if *apply_routes {
                let uid_range = parse_uid_range(exit_node_uid_range.as_ref())?;
                let route_table = resolve_route_table(*route_table, &args.profile);
                let (route_rule_priority, exit_rule_priority, exit_uid_rule_priority) =
                    default_rule_priorities(&args.profile);
                let exit_metric_base =
                    resolve_exit_metric_base(*exit_node_metric_base, &args.profile);
                Some(routes::RouteApplyConfig {
                    interface: iface.clone(),
                    accept_exit_node: *accept_exit_node,
                    exit_node_id: exit_node_id.clone(),
                    exit_node_name: exit_node_name.clone(),
                    exit_node_policy: (*exit_node_policy).into(),
                    exit_node_tag: exit_node_tag.clone(),
                    exit_node_metric_base: exit_metric_base,
                    exit_node_uid_range: uid_range,
                    allow_conflicts: *allow_route_conflicts,
                    route_table,
                    route_rule_priority,
                    exit_rule_priority,
                    exit_uid_rule_priority,
                })
            } else {
                None
            };
            data_plane
                .wg_apply(&netmap, &state, &cfg, routes_cfg.as_ref())
                .await?;
            if let Some(routes_cfg) = routes_cfg.as_ref() {
                data_plane.apply_advertised_routes(&netmap, routes_cfg).await?;
            }
            if *probe_peers {
                data_plane.wg_probe_peers(&netmap, *probe_timeout)?;
            }
            println!("configured wireguard interface {}", iface);
            #[cfg(target_os = "linux")]
            if matches!(*backend, WgBackend::Boringtun) {
                println!("boringtun backend running in foreground; press Ctrl+C to stop");
                tokio::signal::ctrl_c().await?;
            }
        }
        Command::WgDown { interface, backend } => {
            platform::require_data_plane("wg-down")?;
            let iface = interface
                .clone()
                .unwrap_or_else(|| default_interface_name(&args.profile));
            data_plane.wg_remove(&iface, (*backend).into()).await?;
            println!("removed wireguard interface {}", iface);
        }
        Command::Agent {
            interface,
            listen_port,
            apply_routes,
            accept_exit_node,
            exit_node_id,
            exit_node_name,
            exit_node_policy,
            exit_node_tag,
            exit_node_metric_base,
            exit_node_uid_range,
            allow_route_conflicts,
            route_table,
            endpoint,
            advertise_route,
            advertise_map,
            advertise_exit_node,
            heartbeat_interval,
            longpoll_timeout,
            backend,
            stun,
            stun_server,
            stun_port,
            stun_timeout,
            probe_peers,
            probe_timeout,
            stream_relay,
            stream_relay_server,
            endpoint_stale_after,
            endpoint_max_rotations,
            relay_reprobe_after,
            dns_hosts_path,
            dns_serve,
            dns_listen,
            dns_apply_resolver,
            l2_relay,
            cleanup_before_start,
            pid_file,
        } => {
            platform::require_data_plane("agent")?;
            if *apply_routes {
                data_plane::require_advertised_routes(data_plane.as_ref(), "agent --apply-routes")?;
            }
            if *heartbeat_interval == 0 {
                return Err(anyhow!("heartbeat_interval must be > 0"));
            }
            if *longpoll_timeout == 0 {
                return Err(anyhow!("longpoll_timeout must be > 0"));
            }
            if *endpoint_stale_after == 0 {
                return Err(anyhow!("endpoint_stale_after must be > 0"));
            }
            if *endpoint_max_rotations == 0 {
                return Err(anyhow!("endpoint_max_rotations must be > 0"));
            }
            if *relay_reprobe_after == 0 {
                return Err(anyhow!("relay_reprobe_after must be > 0"));
            }
            let resolver_integration_enabled = if *dns_apply_resolver {
                match data_plane.capabilities().dns_resolver_integration {
                    platform::SupportLevel::Unsupported => {
                        eprintln!(
                            "dns resolver integration requested but unsupported on this platform; continuing without resolver apply"
                        );
                        false
                    }
                    _ => true,
                }
            } else {
                false
            };

            // PID file check for single-instance enforcement.
            // Keep the guard alive for the full agent lifetime.
            let _pid_file_guard = if let Some(pid_path) = pid_file {
                match resource_guard::PidFileGuard::acquire(pid_path) {
                    Ok(Some(guard)) => {
                        println!("acquired PID file lock at {}", pid_path.display());
                        Some(guard)
                    }
                    Ok(None) => {
                        return Err(anyhow!(
                            "another instance is already running (PID file locked at {})",
                            pid_path.display()
                        ));
                    }
                    Err(e) => {
                        eprintln!("warning: failed to acquire PID file: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;

            let iface = interface
                .clone()
                .unwrap_or_else(|| default_interface_name(&args.profile));

            // Pre-start cleanup of existing resources
            if *cleanup_before_start {
                eprintln!("cleaning up existing resources before start...");
                // Clean up the specific interface first
                resource_guard::cleanup_existing_resources(Some(&iface)).await?;
                // Then clean up all other ls-* interfaces (leftovers from crashes, etc.)
                if let Err(e) = resource_guard::cleanup_all_lightscale_interfaces(Some(&iface)).await {
                    eprintln!("pre-start: warning - failed to cleanup all interfaces: {}", e);
                }
            }

            // Create resource guard for automatic cleanup on panic/unexpected exit
            let resource_guard = resource_guard::AsyncManagedResources::new();
            resource_guard.set_interface(iface.clone(), (*backend).into()).await;
            resource_guard.set_nftables_enabled(true).await;
            let admin_token = resolve_admin_token(&args);
            let profile = args.profile.clone();
            let stun_servers = gather_stun_servers(
                &control_urls,
                tls_pin.clone(),
                &mut state,
                &state_path,
                stun_server,
            )
            .await?;
            let stream_servers = if *stream_relay {
                if !stream_relay_server.is_empty() {
                    stream_relay_server.clone()
                } else {
                    gather_stream_relay_servers(
                        &control_urls,
                        tls_pin.clone(),
                        &mut state,
                        &state_path,
                    )
                    .await?
                }
            } else {
                Vec::new()
            };
            if *stream_relay && stream_servers.is_empty() {
                eprintln!("stream relay enabled but no servers configured");
            }
            if *stream_relay {
                if let Err(err) = enable_route_localnet() {
                    eprintln!("failed to enable route_localnet: {}", err);
                }
            }
            let mut endpoint_tracker = wg::EndpointTracker::default();
            let relay_ip = select_relay_ip(endpoint);
            let mut relay_manager = if *stream_relay && !stream_servers.is_empty() {
                Some(relay_tunnel::RelayTunnelManager::new(
                    state.node_id.clone(),
                    stream_servers.clone(),
                    *listen_port,
                    relay_ip,
                ))
            } else {
                None
            };
            let endpoint_stale_after = Duration::from_secs(*endpoint_stale_after);
            let endpoint_max_rotations = (*endpoint_max_rotations) as usize;
            let relay_reprobe_after = Duration::from_secs(*relay_reprobe_after);

            // Note: iface is already defined above for resource_guard
            let client = ControlClient::new(
                control_urls.clone(),
                tls_pin.clone(),
                state.node_token.clone(),
                admin_token,
            )?;
            let wg_cfg = wg::WgConfig {
                interface: iface.clone(),
                listen_port: *listen_port,
                backend: (*backend).into(),
            };
            let uid_range = parse_uid_range(exit_node_uid_range.as_ref())?;
            let route_table = resolve_route_table(*route_table, &args.profile);
            let (route_rule_priority, exit_rule_priority, exit_uid_rule_priority) =
                default_rule_priorities(&args.profile);
            let exit_metric_base = resolve_exit_metric_base(*exit_node_metric_base, &args.profile);
            let routes_cfg = routes::RouteApplyConfig {
                interface: iface.clone(),
                accept_exit_node: *accept_exit_node,
                exit_node_id: exit_node_id.clone(),
                exit_node_name: exit_node_name.clone(),
                exit_node_policy: (*exit_node_policy).into(),
                exit_node_tag: exit_node_tag.clone(),
                exit_node_metric_base: exit_metric_base,
                exit_node_uid_range: uid_range,
                allow_conflicts: *allow_route_conflicts,
                route_table,
                route_rule_priority,
                exit_rule_priority,
                exit_uid_rule_priority,
            };
            let advertise_maps = parse_route_maps(advertise_map)?;
            let advertise_routes = build_routes(
                advertise_route.clone(),
                advertise_maps,
                *advertise_exit_node,
            );
            let mut dns_state: Option<std::sync::Arc<std::sync::Mutex<model::NetMap>>> = None;
            let mut dns_listen_addr: Option<SocketAddr> = None;
            let mut l2_state: Option<std::sync::Arc<std::sync::Mutex<model::NetMap>>> = None;
            if *dns_serve {
                let listen = dns_listen
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:53".to_string());
                let listen_addr: SocketAddr =
                    listen.parse().context("invalid dns listen address")?;
                let netmap =
                    ensure_netmap(&control_urls, tls_pin.clone(), &mut state, &state_path).await?;
                dns_state = Some(data_plane.dns_spawn(listen_addr, netmap.clone())?);
                dns_listen_addr = Some(listen_addr);
                if resolver_integration_enabled {
                    if listen_addr.port() != 53 {
                        eprintln!("dns listen port must be 53 to apply resolver");
                    } else if let Err(err) = data_plane.dns_apply_resolver(
                        &iface,
                        &netmap.network.dns_domain,
                        listen_addr.ip(),
                    ) {
                        eprintln!("failed to apply dns resolver: {}", err);
                    }
                }
                println!("dns server listening on {}", listen_addr);
            }
            let startup_netmap = if let Some(netmap) = state.last_netmap.clone() {
                netmap
            } else {
                ensure_netmap(&control_urls, tls_pin.clone(), &mut state, &state_path).await?
            };
            apply_netmap_update(
                data_plane.as_ref(),
                &state_path,
                &mut state,
                startup_netmap.clone(),
                &wg_cfg,
                *apply_routes,
                &routes_cfg,
                *probe_peers,
                *probe_timeout,
                &profile,
                dns_hosts_path.as_ref(),
            )
            .await?;
            let mut last_revision = startup_netmap.revision;

            let mut interval = tokio::time::interval(Duration::from_secs(*heartbeat_interval));
            let mut shutdown =
                Box::pin(wait_for_shutdown_signal(matches!(*backend, WgBackend::Kernel)));
            println!(
                "agent running for node {} on network {}",
                state.node_id, state.network_id
            );

            loop {
                tokio::select! {
                    _ = &mut shutdown => {
                        println!("shutdown signal received, stopping agent");
                        break;
                    }
                    _ = interval.tick() => {
                        let mut endpoints = endpoint.clone();
                        if *stun {
                            if let Some(stun_endpoint) = maybe_stun_endpoint(
                                &stun_servers,
                                stun_port.or(Some(0)),
                                Duration::from_secs(*stun_timeout),
                            )
                            .await?
                            {
                                endpoints.push(stun_endpoint);
                            }
                        }
                        let response = match client
                            .heartbeat(HeartbeatRequest {
                                node_id: state.node_id.clone(),
                                endpoints,
                                listen_port: Some(*listen_port),
                                routes: advertise_routes.clone(),
                                probe: Some(*stream_relay),
                            })
                            .await
                        {
                            Ok(response) => response,
                            Err(err) => {
                                eprintln!("heartbeat failed: {}", err);
                                continue;
                            }
                        };
                        let netmap = response.netmap;
                        if let Err(err) = handle_probe_requests(&netmap).await {
                            eprintln!("probe request handling failed: {}", err);
                        }
                        if netmap.revision > last_revision {
                            last_revision = netmap.revision;
                            apply_netmap_update(
                                data_plane.as_ref(),
                                &state_path,
                                &mut state,
                                netmap.clone(),
                                &wg_cfg,
                                *apply_routes,
                                &routes_cfg,
                                *probe_peers,
                                *probe_timeout,
                                &profile,
                                dns_hosts_path.as_ref(),
                            )
                            .await?;
                            if let Some(state_handle) = dns_state.as_ref() {
                                if let Ok(mut guard) = state_handle.lock() {
                                    *guard = netmap.clone();
                                }
                            }
                            if resolver_integration_enabled {
                                if let Some(listen_addr) = dns_listen_addr.as_ref() {
                                    if listen_addr.port() == 53 {
                                        if let Err(err) = data_plane.dns_apply_resolver(
                                            &iface,
                                            &netmap.network.dns_domain,
                                            listen_addr.ip(),
                                        ) {
                                            eprintln!("failed to apply dns resolver: {}", err);
                                        }
                                    }
                                }
                            }
                            if *l2_relay {
                                match netmap.node.ipv4.parse() {
                                    Ok(wg_ipv4) => {
                                        if let Some(state_handle) = l2_state.as_ref() {
                                            if let Ok(mut guard) = state_handle.lock() {
                                                *guard = netmap.clone();
                                            }
                                        } else {
                                            match l2_relay::spawn(wg_ipv4, netmap.clone()) {
                                                Ok(state_handle) => {
                                                    l2_state = Some(state_handle);
                                                    println!("l2 relay enabled");
                                                }
                                                Err(err) => {
                                                    eprintln!("l2 relay failed: {}", err);
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        eprintln!("l2 relay skipped: invalid node ipv4");
                                    }
                                }
                            }
                        }
                        let relay_endpoints = if let Some(manager) = relay_manager.as_mut() {
                            match manager.ensure_for_peers(&netmap.peers).await {
                                Ok(map) => map,
                                Err(err) => {
                                    eprintln!("stream relay tunnel init failed: {}", err);
                                    HashMap::new()
                                }
                            }
                        } else {
                            HashMap::new()
                        };
                        if let Err(err) = data_plane.wg_refresh_peer_endpoints(
                            &netmap,
                            &wg_cfg,
                            &mut endpoint_tracker,
                            &relay_endpoints,
                            endpoint_stale_after,
                            endpoint_max_rotations,
                            relay_reprobe_after,
                        ) {
                            eprintln!("endpoint refresh failed: {}", err);
                        }
                    }
                    result = client.netmap_longpoll(&state.node_id, last_revision, *longpoll_timeout) => {
                        let netmap = match result {
                            Ok(netmap) => netmap,
                            Err(err) => {
                                eprintln!("netmap longpoll failed: {}", err);
                                sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                        };
                        if let Err(err) = handle_probe_requests(&netmap).await {
                            eprintln!("probe request handling failed: {}", err);
                        }
                        if netmap.revision > last_revision {
                            last_revision = netmap.revision;
                            apply_netmap_update(
                                data_plane.as_ref(),
                                &state_path,
                                &mut state,
                                netmap.clone(),
                                &wg_cfg,
                                *apply_routes,
                                &routes_cfg,
                                *probe_peers,
                                *probe_timeout,
                                &profile,
                                dns_hosts_path.as_ref(),
                            )
                            .await?;
                        }
                        let relay_endpoints = if let Some(manager) = relay_manager.as_mut() {
                            match manager.ensure_for_peers(&netmap.peers).await {
                                Ok(map) => map,
                                Err(err) => {
                                    eprintln!("stream relay tunnel init failed: {}", err);
                                    HashMap::new()
                                }
                            }
                        } else {
                            HashMap::new()
                        };
                        if let Err(err) = data_plane.wg_refresh_peer_endpoints(
                            &netmap,
                            &wg_cfg,
                            &mut endpoint_tracker,
                            &relay_endpoints,
                            endpoint_stale_after,
                            endpoint_max_rotations,
                            relay_reprobe_after,
                        ) {
                            eprintln!("endpoint refresh failed: {}", err);
                        }
                    }
                }
            }

            if resolver_integration_enabled {
                if let Err(err) = data_plane.dns_clear_resolver(&iface) {
                    eprintln!("failed to clear dns resolver: {}", err);
                }
            }
            // Disable automatic cleanup since we're doing clean shutdown
            resource_guard.disable_cleanup().await;
            if let Err(err) = data_plane.wg_remove(&iface, (*backend).into()).await {
                eprintln!("wireguard cleanup failed: {}", err);
            }
            println!("agent stopped");
        }
        Command::Daemon {
            profiles,
            agent_arg,
        } => {
            data_plane::require_daemon_supervision(data_plane.as_ref(), "daemon")?;
            run_daemon(&args, profiles, agent_arg).await?;
        }
        Command::Router { command } => {
            data_plane::require_router_mode(data_plane.as_ref(), "router")?;
            match command {
                RouterCommand::Enable {
                    interface,
                    out_interface,
                    map,
                    no_snat,
                } => {
                    let iface = interface
                        .clone()
                        .unwrap_or_else(|| default_interface_name(&args.profile));
                    let out_iface = router::resolve_out_interface(out_interface.clone()).await?;
                    router::enable_forwarding(&iface, &out_iface, !*no_snat).await?;
                    if !map.is_empty() {
                        let maps = parse_route_maps(map)?;
                        router::apply_route_maps(&iface, &out_iface, &maps).await?;
                    }

                    if *no_snat {
                        let config = load_optional_config(&args)?;
                        let control_urls = resolve_control_urls(&args, config.as_ref())?;
                        let tls_pin = resolve_tls_pin(&args, &config);
                        let state_path = resolve_state_path(&args)?;
                        let mut state = load_state(&state_path)?.ok_or_else(|| {
                            anyhow!("state not found for profile {}", args.profile)
                        })?;
                        let netmap =
                            ensure_netmap(&control_urls, tls_pin, &mut state, &state_path).await?;
                        let (lan_v4, lan_v6) = router::interface_ips(&out_iface).await?;
                        print_return_route_guidance(&netmap, &iface, &out_iface, lan_v4, lan_v6);
                    }

                    println!("forwarding enabled for {} -> {}", iface, out_iface);
                }
                RouterCommand::Disable {
                    interface,
                    out_interface,
                } => {
                    let iface = interface
                        .clone()
                        .unwrap_or_else(|| default_interface_name(&args.profile));
                    let out_iface = router::resolve_out_interface(out_interface.clone()).await?;
                    router::disable_forwarding(&iface, &out_iface).await?;
                    println!("forwarding disabled for {} -> {}", iface, out_iface);
                }
            }
        }
        Command::RelayUdp { command } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;
            let servers =
                gather_udp_relay_servers(&control_urls, tls_pin, &mut state, &state_path).await?;

            match command {
                RelayUdpCommand::Send {
                    peer_id,
                    message,
                    server,
                    timeout,
                } => {
                    let server = server
                        .clone()
                        .or_else(|| servers.first().cloned())
                        .ok_or_else(|| anyhow!("no udp relay server configured"))?;
                    relay_udp_send(&state, &server, &peer_id, &message, *timeout).await?;
                    println!("relay message sent to {}", peer_id);
                }
                RelayUdpCommand::Listen { server } => {
                    let server = server
                        .clone()
                        .or_else(|| servers.first().cloned())
                        .ok_or_else(|| anyhow!("no udp relay server configured"))?;
                    relay_udp_listen(&state, &server).await?;
                }
            }
        }
        Command::RelayStream { command } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;
            let servers =
                gather_stream_relay_servers(&control_urls, tls_pin, &mut state, &state_path)
                    .await?;

            match command {
                RelayStreamCommand::Send {
                    peer_id,
                    message,
                    server,
                } => {
                    if let Some(server) = server.clone() {
                        relay_stream_send(&state, &server, &peer_id, &message).await?;
                    } else {
                        relay_stream_send_raw_any(&state, &servers, &peer_id, message.as_bytes())
                            .await?;
                    }
                    println!("stream relay message sent to {}", peer_id);
                }
                RelayStreamCommand::Listen { server } => {
                    if let Some(server) = server.clone() {
                        relay_stream_listen(&state, &server).await?;
                    } else {
                        relay_stream_listen_any(&state, &servers).await?;
                    }
                }
            }
        }
        Command::RelayTurn { command } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;
            let servers =
                gather_turn_servers(&control_urls, tls_pin, &mut state, &state_path).await?;
            let creds = build_turn_credentials(&command)?;

            match command {
                RelayTurnCommand::Send {
                    peer_addr,
                    message,
                    server,
                    timeout,
                    ..
                } => {
                    let server = server
                        .clone()
                        .or_else(|| servers.first().cloned())
                        .ok_or_else(|| anyhow!("no turn server configured"))?;
                    let peer: SocketAddr = peer_addr.parse().context("invalid peer addr")?;
                    let mut allocation =
                        turn::allocate(&server, creds.as_ref(), Duration::from_secs(*timeout))
                            .await?;
                    turn::create_permission(&mut allocation, peer, Duration::from_secs(*timeout))
                        .await?;
                    turn::send_data(&mut allocation, peer, message.as_bytes()).await?;
                    println!("turn relay message sent to {}", peer);
                }
                RelayTurnCommand::Listen {
                    server, peer_addr, ..
                } => {
                    let server = server
                        .clone()
                        .or_else(|| servers.first().cloned())
                        .ok_or_else(|| anyhow!("no turn server configured"))?;
                    let mut allocation =
                        turn::allocate(&server, creds.as_ref(), Duration::from_secs(3)).await?;
                    if let Some(peer_addr) = peer_addr {
                        let peer: SocketAddr = peer_addr.parse().context("invalid peer addr")?;
                        turn::create_permission(&mut allocation, peer, Duration::from_secs(3))
                            .await?;
                    } else {
                        eprintln!("turn listen without --peer-addr may not receive traffic");
                    }
                    println!("listening on turn relay {}", allocation.relay_addr);
                    loop {
                        if let Some((from, payload)) =
                            turn::recv_data(&mut allocation, None).await?
                        {
                            let text = String::from_utf8_lossy(&payload);
                            println!("from {}: {}", from, text);
                        }
                    }
                }
            }
        }
        Command::Platform { json } => {
            let profile = platform::current();
            let data_plane_caps = data_plane.capabilities();
            let service_manager = data_plane.service_manager();
            let daemon_supervision = service_manager.daemon_supervision();
            let os_service_integration = service_manager.os_service_integration();
            if *json {
                let payload = serde_json::json!({
                    "os": profile.os,
                    "arch": profile.arch,
                    "control_plane": profile.control_plane.as_str(),
                    "data_plane": profile.data_plane.as_str(),
                    "service_integration": profile.service_integration.as_str(),
                    "service_managers": profile.service_managers,
                    "note": profile.note,
                    "data_plane_capabilities": {
                        "wireguard": data_plane_caps.wireguard.as_str(),
                        "advertised_routes": data_plane_caps.advertised_routes.as_str(),
                        "advanced_route_policy": data_plane_caps.advanced_route_policy.as_str(),
                        "router_mode": data_plane_caps.router_mode.as_str(),
                        "dns_local_server": data_plane_caps.dns_local_server.as_str(),
                        "dns_resolver_integration": data_plane_caps.dns_resolver_integration.as_str(),
                        "daemon_supervision": daemon_supervision.as_str(),
                        "os_service_integration": os_service_integration.as_str(),
                        "note": data_plane_caps.note,
                    },
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                println!("platform: {}-{}", profile.os, profile.arch);
                println!("control_plane: {}", profile.control_plane.as_str());
                println!("data_plane: {}", profile.data_plane.as_str());
                println!(
                    "service_integration: {}",
                    profile.service_integration.as_str()
                );
                println!("service_managers: {}", profile.service_managers.join(", "));
                println!("note: {}", profile.note);
                println!("feature.wireguard: {}", data_plane_caps.wireguard.as_str());
                println!(
                    "feature.advertised_routes: {}",
                    data_plane_caps.advertised_routes.as_str()
                );
                println!(
                    "feature.advanced_route_policy: {}",
                    data_plane_caps.advanced_route_policy.as_str()
                );
                println!("feature.router_mode: {}", data_plane_caps.router_mode.as_str());
                println!(
                    "feature.dns_local_server: {}",
                    data_plane_caps.dns_local_server.as_str()
                );
                println!(
                    "feature.dns_resolver_integration: {}",
                    data_plane_caps.dns_resolver_integration.as_str()
                );
                println!(
                    "feature.daemon_supervision: {}",
                    daemon_supervision.as_str()
                );
                println!(
                    "feature.os_service_integration: {}",
                    os_service_integration.as_str()
                );
                println!("feature.note: {}", data_plane_caps.note);
            }
        }
        Command::Dns {
            format,
            output,
            apply_hosts,
            hosts_path,
        } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;

            let admin_token = resolve_admin_token(&args);
            let client =
                ControlClient::new(control_urls, tls_pin, state.node_token.clone(), admin_token)?;
            let netmap = client
                .netmap(&state.node_id)
                .await
                .context("netmap fetch failed")?;

            state.last_netmap = Some(netmap.clone());
            state.updated_at = now_unix();
            save_state(&state_path, &state)?;

            let text = match format {
                DnsFormat::Hosts => format_dns_hosts(&netmap),
                DnsFormat::Json => format_dns_json(&netmap),
            };
            if let Some(path) = output {
                std::fs::write(path, text)?;
            } else {
                print!("{}", text);
            }
            if *apply_hosts {
                let path = hosts_path.clone().unwrap_or_else(default_hosts_path);
                apply_hosts_file(&path, &args.profile, &netmap)?;
                println!("updated hosts file {}", path.display());
            }
        }
        Command::DnsServe {
            listen,
            apply_resolver,
            interface,
        } => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;

            let admin_token = resolve_admin_token(&args);
            let client =
                ControlClient::new(control_urls, tls_pin, state.node_token.clone(), admin_token)?;
            let netmap = client
                .netmap(&state.node_id)
                .await
                .context("netmap fetch failed")?;

            state.last_netmap = Some(netmap.clone());
            state.updated_at = now_unix();
            save_state(&state_path, &state)?;

            let listen_addr: SocketAddr = listen.parse().context("invalid listen address")?;
            let _state = data_plane.dns_spawn(listen_addr, netmap.clone())?;
            if *apply_resolver {
                data_plane::require_dns_resolver_integration(
                    data_plane.as_ref(),
                    "dns-serve --apply-resolver",
                )?;
                if listen_addr.port() != 53 {
                    return Err(anyhow!("dns listen port must be 53 to apply resolver"));
                }
                let iface = interface
                    .clone()
                    .unwrap_or_else(|| default_interface_name(&args.profile));
                data_plane.dns_apply_resolver(&iface, &netmap.network.dns_domain, listen_addr.ip())?;
            }
            println!("dns server listening on {}", listen_addr);
            tokio::signal::ctrl_c().await?;
        }
        Command::Relay => {
            let config = load_optional_config(&args)?;
            let control_urls = resolve_control_urls(&args, config.as_ref())?;
            let tls_pin = resolve_tls_pin(&args, &config);
            let state_path = resolve_state_path(&args)?;
            let mut state = load_state(&state_path)?
                .ok_or_else(|| anyhow!("state not found for profile {}", args.profile))?;

            let admin_token = resolve_admin_token(&args);
            let client =
                ControlClient::new(control_urls, tls_pin, state.node_token.clone(), admin_token)?;
            let netmap = client
                .netmap(&state.node_id)
                .await
                .context("netmap fetch failed")?;

            state.last_netmap = Some(netmap.clone());
            state.updated_at = now_unix();
            save_state(&state_path, &state)?;

            print_relay_config(&netmap);
        }
    }

    Ok(())
}

fn resolve_config_path(args: &Args) -> Result<PathBuf> {
    resolve_config_path_optional(args).ok_or_else(|| anyhow!("no default config path available"))
}

fn resolve_config_path_optional(args: &Args) -> Option<PathBuf> {
    args.config.clone().or_else(default_config_path)
}

fn load_optional_config(args: &Args) -> Result<Option<ClientConfig>> {
    let config_path = match resolve_config_path_optional(args) {
        Some(path) => path,
        None => return Ok(None),
    };

    Ok(Some(load_config(&config_path)?))
}

fn persist_profile_control_urls(
    args: &Args,
    control_urls: &[String],
    tls_pin: Option<&str>,
) -> Result<()> {
    let config_path = match resolve_config_path_optional(args) {
        Some(path) => path,
        None => return Ok(()),
    };
    let mut config = load_config(&config_path)?;
    let profile = config
        .profiles
        .entry(args.profile.clone())
        .or_insert(ProfileConfig {
            control_urls: Vec::new(),
            tls_pinned_sha256: None,
            ..ProfileConfig::default()
        });
    let urls = normalize_control_urls(control_urls.to_vec());
    if !urls.is_empty() {
        profile.control_urls = urls;
    }
    if let Some(pin) = tls_pin {
        profile.tls_pinned_sha256 = Some(pin.to_string());
    }
    save_config(&config_path, &config)?;
    Ok(())
}

fn resolve_control_urls(args: &Args, config: Option<&ClientConfig>) -> Result<Vec<String>> {
    if !args.control_url.is_empty() {
        let urls = normalize_control_urls(args.control_url.clone());
        if !urls.is_empty() {
            return Ok(urls);
        }
    }

    if let Some(config) = config {
        if let Some(profile) = config.profiles.get(&args.profile) {
            let urls = normalize_control_urls(profile.control_urls.clone());
            if !urls.is_empty() {
                return Ok(urls);
            }
        }
    }

    Err(anyhow!(
        "control URL not set; use --control-url/--bootstrap-url or init the profile"
    ))
}

fn normalize_control_urls(urls: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for url in urls {
        let trimmed = url.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if !unique.contains(&trimmed) {
            unique.push(trimmed);
        }
    }
    unique
}

fn resolve_tls_pin(args: &Args, config: &Option<ClientConfig>) -> Option<String> {
    if let Some(pin) = &args.tls_pin {
        return Some(pin.clone());
    }
    if let Some(config) = config {
        if let Some(profile) = config.profiles.get(&args.profile) {
            return profile.tls_pinned_sha256.clone();
        }
    }
    None
}

fn resolve_admin_token(args: &Args) -> Option<String> {
    args.admin_token.clone()
}

fn resolve_state_path(args: &Args) -> Result<PathBuf> {
    let base = if let Some(dir) = &args.state_dir {
        dir.clone()
    } else {
        default_state_dir(&args.profile).ok_or_else(|| anyhow!("no default state dir available"))?
    };
    Ok(state_path(&base))
}

async fn wait_for_shutdown_signal(handle_sigterm: bool) {
    #[cfg(not(unix))]
    let _ = handle_sigterm;

    #[cfg(unix)]
    if handle_sigterm {
        use tokio::signal::unix::{signal, SignalKind};

        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
            return;
        }
    }

    let _ = tokio::signal::ctrl_c().await;
}

async fn run_daemon(
    args: &Args,
    requested_profiles: &[String],
    default_agent_args: &[String],
) -> Result<()> {
    let config_path = resolve_config_path(args)?;
    let config = load_config(&config_path)?;

    let mut profile_names = if !requested_profiles.is_empty() {
        requested_profiles.to_vec()
    } else {
        let mut names: Vec<String> = config
            .profiles
            .iter()
            .filter_map(|(name, profile)| {
                if profile.autostart {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect();
        // Keep single-profile UX simple: daemon defaults to the selected profile
        // (default: "default") when no autostart profiles are configured.
        if names.is_empty() {
            names.push(args.profile.clone());
        }
        names.sort();
        names
    };
    profile_names.sort();
    profile_names.dedup();

    if profile_names.is_empty() {
        return Err(anyhow!(
            "no profiles selected; pass --profiles or set --profile"
        ));
    }

    struct DaemonProfile {
        name: String,
        state_dir: PathBuf,
        agent_args: Vec<String>,
        child: Option<tokio::process::Child>,
        waiting_logged: bool,
    }

    let exe = std::env::current_exe().context("failed to resolve current executable path")?;
    let mut profiles: Vec<DaemonProfile> = Vec::new();

    for profile_name in profile_names {
        let profile_cfg = config.profiles.get(&profile_name);

        let state_dir = profile_cfg
            .and_then(|profile| profile.state_dir.clone())
            .or_else(|| args.state_dir.clone())
            .or_else(|| default_state_dir(&profile_name))
            .ok_or_else(|| anyhow!("no state dir available for profile {}", profile_name))?;
        let agent_args = profile_cfg
            .map(|profile| profile.agent_args.clone())
            .unwrap_or_default();
        let agent_args = if agent_args.is_empty() {
            default_agent_args.to_vec()
        } else {
            agent_args
        };

        profiles.push(DaemonProfile {
            name: profile_name,
            state_dir,
            agent_args,
            child: None,
            waiting_logged: false,
        });
    }

    if profiles.is_empty() {
        return Err(anyhow!("no profile selected"));
    }

    println!("daemon managing {} profile(s)", profiles.len());
    let mut shutdown = Box::pin(wait_for_shutdown_signal(true));
    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                println!("shutdown signal received, stopping daemon");
                break;
            }
            _ = ticker.tick() => {
                for profile in &mut profiles {
                    if let Some(child) = profile.child.as_mut() {
                        match child
                            .try_wait()
                            .with_context(|| format!("failed to poll agent process for profile {}", profile.name))?
                        {
                            Some(status) => {
                                eprintln!("agent for profile {} exited: {}", profile.name, status);
                                profile.child = None;
                            }
                            None => {}
                        }
                    }

                    if profile.child.is_none() {
                        let state_file = state_path(&profile.state_dir);
                        if state_file.is_file() {
                            let mut command = TokioCommand::new(&exe);
                            command
                                .arg("--profile")
                                .arg(&profile.name)
                                .arg("--config")
                                .arg(&config_path)
                                .arg("--state-dir")
                                .arg(&profile.state_dir);

                            for control_url in &args.control_url {
                                command.arg("--control-url").arg(control_url);
                            }
                            if let Some(tls_pin) = args.tls_pin.as_ref() {
                                command.arg("--tls-pin").arg(tls_pin);
                            }
                            if let Some(admin_token) = args.admin_token.as_ref() {
                                command.arg("--admin-token").arg(admin_token);
                            }

                            command.arg("agent");
                            for token in &profile.agent_args {
                                command.arg(token);
                            }

                            command
                                .stdin(Stdio::null())
                                .stdout(Stdio::inherit())
                                .stderr(Stdio::inherit());

                            let child = command
                                .spawn()
                                .with_context(|| format!("failed to start agent for profile {}", profile.name))?;
                            let pid = child.id().unwrap_or(0);
                            println!("started profile {} (pid {})", profile.name, pid);
                            profile.child = Some(child);
                            profile.waiting_logged = false;
                        } else if !profile.waiting_logged {
                            println!(
                                "profile {} waiting for state at {}",
                                profile.name,
                                state_file.display()
                            );
                            profile.waiting_logged = true;
                        }
                    }
                }
            }
        }
    }

    for profile in &mut profiles {
        if let Some(child) = profile.child.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(err) = child.kill().await {
                        eprintln!("failed to stop profile {}: {}", profile.name, err);
                    }
                }
                Err(err) => {
                    eprintln!("failed to poll profile {} before stop: {}", profile.name, err);
                }
            }
        }
    }

    for profile in &mut profiles {
        if let Some(child) = profile.child.as_mut() {
            if let Err(err) = child.wait().await {
                eprintln!("failed to wait for profile {}: {}", profile.name, err);
            }
        }
    }

    println!("daemon stopped");
    Ok(())
}

fn load_acl_policy(file: Option<&PathBuf>, json: Option<&String>) -> Result<model::AclPolicy> {
    if let Some(json) = json {
        return Ok(serde_json::from_str(json)?);
    }
    if let Some(path) = file {
        let contents = std::fs::read_to_string(path)?;
        return Ok(serde_json::from_str(&contents)?);
    }
    Err(anyhow!("provide --file or --json for acl policy"))
}

fn build_turn_credentials(command: &RelayTurnCommand) -> Result<Option<turn::TurnCredentials>> {
    let (username, password) = match command {
        RelayTurnCommand::Send {
            username, password, ..
        } => (username, password),
        RelayTurnCommand::Listen {
            username, password, ..
        } => (username, password),
    };
    match (username, password) {
        (Some(user), Some(pass)) => Ok(Some(turn::TurnCredentials {
            username: user.clone(),
            password: pass.clone(),
        })),
        (None, None) => Ok(None),
        _ => Err(anyhow!("turn username and password must be set together")),
    }
}

fn parse_route_maps(entries: &[String]) -> Result<Vec<(String, String)>> {
    let mut maps = Vec::new();
    let mut seen_real = HashMap::new();
    let mut seen_mapped = HashMap::new();
    for entry in entries {
        let (real, mapped) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("route map must be REAL=MAPPED (got {})", entry))?;
        let real = real.trim();
        let mapped = mapped.trim();
        if real.is_empty() || mapped.is_empty() {
            return Err(anyhow!("route map must be REAL=MAPPED (got {})", entry));
        }
        let real_net: IpNet = real
            .parse()
            .with_context(|| format!("route map real prefix invalid: {}", real))?;
        let mapped_net: IpNet = mapped
            .parse()
            .with_context(|| format!("route map mapped prefix invalid: {}", mapped))?;
        let real_v4 = matches!(real_net, IpNet::V4(_));
        let mapped_v4 = matches!(mapped_net, IpNet::V4(_));
        if real_v4 != mapped_v4 {
            return Err(anyhow!(
                "route map ip versions must match ({} vs {})",
                real,
                mapped
            ));
        }
        if real_net.prefix_len() != mapped_net.prefix_len() {
            return Err(anyhow!(
                "route map prefix lengths must match ({} vs {})",
                real,
                mapped
            ));
        }
        if let Some(existing) = seen_real.get(real) {
            if existing != mapped {
                return Err(anyhow!(
                    "route map for {} already set to {}",
                    real,
                    existing
                ));
            }
            continue;
        }
        if let Some(existing) = seen_mapped.get(mapped) {
            if existing != real {
                return Err(anyhow!(
                    "route map {} already mapped from {}",
                    mapped,
                    existing
                ));
            }
            continue;
        }
        seen_real.insert(real.to_string(), mapped.to_string());
        seen_mapped.insert(mapped.to_string(), real.to_string());
        maps.push((real.to_string(), mapped.to_string()));
    }
    Ok(maps)
}

fn parse_uid_range(value: Option<&String>) -> Result<Option<routes::UidRange>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let (start, end) = if let Some((start, end)) = raw.split_once('-') {
        let start: u32 = start.trim().parse().context("invalid uid range start")?;
        let end: u32 = end.trim().parse().context("invalid uid range end")?;
        if end < start {
            return Err(anyhow!("uid range end before start"));
        }
        (start, end)
    } else {
        let uid: u32 = raw.parse().context("invalid uid")?;
        (uid, uid)
    };
    Ok(Some(routes::UidRange { start, end }))
}

fn resolve_route_table(route_table: Option<u32>, _profile: &str) -> Option<u32> {
    match route_table {
        Some(0) => None,
        Some(value) => Some(value),
        None => None,
    }
}

fn resolve_exit_metric_base(metric: Option<u32>, profile: &str) -> u32 {
    metric.unwrap_or_else(|| 10 + (profile_hash(profile) % 10) as u32)
}

fn default_rule_priorities(profile: &str) -> (u32, u32, u32) {
    let offset = (profile_hash(profile) % 100) as u32;
    let route_priority = 1000 + offset;
    let exit_priority = 1100 + offset;
    let exit_uid_priority = 900 + offset;
    (route_priority, exit_priority, exit_uid_priority)
}

fn profile_hash(profile: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    profile.hash(&mut hasher);
    hasher.finish()
}

fn build_routes(prefixes: Vec<String>, maps: Vec<(String, String)>, exit_node: bool) -> Vec<Route> {
    let mut routes: Vec<Route> = prefixes
        .into_iter()
        .map(|prefix| Route {
            prefix,
            kind: RouteKind::Subnet,
            enabled: true,
            mapped_prefix: None,
        })
        .collect();

    for (real, mapped) in maps {
        if let Some(route) = routes
            .iter_mut()
            .find(|route| route.prefix == real && matches!(route.kind, RouteKind::Subnet))
        {
            route.mapped_prefix = Some(mapped);
        } else {
            routes.push(Route {
                prefix: real,
                kind: RouteKind::Subnet,
                enabled: true,
                mapped_prefix: Some(mapped),
            });
        }
    }

    if exit_node {
        routes.push(Route {
            prefix: "0.0.0.0/0".to_string(),
            kind: RouteKind::Exit,
            enabled: true,
            mapped_prefix: None,
        });
        routes.push(Route {
            prefix: "::/0".to_string(),
            kind: RouteKind::Exit,
            enabled: true,
            mapped_prefix: None,
        });
    }

    routes
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "node".to_string())
}

fn resolve_machine_keys(machine_private_key_file: Option<&PathBuf>) -> Result<keys::KeyPair> {
    if let Some(path) = machine_private_key_file {
        let private = keys::read_private_key_file(path)?;
        let key_pair = keys::machine_keys_from_private_base64(&private)
            .with_context(|| format!("invalid machine key file {}", path.display()))?;
        return Ok(key_pair);
    }
    Ok(keys::generate_machine_keys())
}

fn resolve_wg_keys(wg_private_key_file: Option<&PathBuf>) -> Result<keys::KeyPair> {
    if let Some(path) = wg_private_key_file {
        let private = keys::read_private_key_file(path)?;
        let key_pair = keys::wg_keys_from_private_base64(&private)
            .with_context(|| format!("invalid wireguard key file {}", path.display()))?;
        return Ok(key_pair);
    }
    Ok(keys::generate_wg_keys())
}

fn default_interface_name(profile: &str) -> String {
    let mut name = format!("ls-{}", profile);
    if name.len() > 15 {
        name.truncate(15);
    }
    name
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn build_admin_login_approval_url(
    admin_url: &str,
    network_id: &str,
    auth_path: &str,
    auto_approve: bool,
) -> Result<String> {
    let mut url = url::Url::parse(admin_url)
        .with_context(|| format!("invalid --admin-url: {}", admin_url))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("ls_join", "1");
        pairs.append_pair("network_id", network_id);
        pairs.append_pair("auth_path", auth_path);
        if auto_approve {
            pairs.append_pair("ls_auto_approve", "1");
        }
    }
    Ok(url.to_string())
}

fn format_handshake_age(when: Option<SystemTime>) -> String {
    match when {
        Some(time) => match time.elapsed() {
            Ok(age) => format!("{}s", age.as_secs()),
            Err(_) => "unknown".to_string(),
        },
        None => "never".to_string(),
    }
}

fn select_relay_ip(endpoints: &[String]) -> Option<IpAddr> {
    endpoints
        .iter()
        .filter_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
        .map(|addr| addr.ip())
        .next()
}

async fn fetch_server_fingerprint_any(control_urls: &[String]) -> Result<String> {
    if control_urls.is_empty() {
        return Err(anyhow!("no control URL configured"));
    }
    let mut last_err: Option<anyhow::Error> = None;
    for control_url in control_urls {
        match fetch_server_fingerprint(control_url).await {
            Ok(pin) => return Ok(pin),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no control URL reachable")))
}

async fn fetch_server_fingerprint(control_url: &str) -> Result<String> {
    let url = url::Url::parse(control_url).context("invalid control URL")?;
    if url.scheme() != "https" {
        return Err(anyhow!("tls pin requires https control URL"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("control URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addr = format!("{}:{}", host, port);

    let stream = TcpStream::connect(addr).await?;
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerify));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| anyhow!("invalid server name"))?;
    let stream = connector.connect(server_name, stream).await?;
    let (_, session) = stream.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| anyhow!("server did not provide certificates"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("server did not provide certificates"))?;
    let mut hasher = Sha256::new();
    hasher.update(leaf.as_ref());
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(target_os = "linux")]
fn enable_route_localnet() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/conf/all/route_localnet", "1\n")?;
    std::fs::write("/proc/sys/net/ipv4/conf/lo/route_localnet", "1\n")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enable_route_localnet() -> Result<()> {
    Ok(())
}

fn format_dns_hosts(netmap: &model::NetMap) -> String {
    let mut text = String::new();
    text.push_str(&format!(
        "# {} {}\n",
        netmap.network.name, netmap.network.dns_domain
    ));
    text.push_str(&format!("{} {}\n", netmap.node.ipv4, netmap.node.dns_name));
    text.push_str(&format!("{} {}\n", netmap.node.ipv6, netmap.node.dns_name));
    for peer in &netmap.peers {
        text.push_str(&format!("{} {}\n", peer.ipv4, peer.dns_name));
        text.push_str(&format!("{} {}\n", peer.ipv6, peer.dns_name));
    }
    text
}

fn format_dns_json(netmap: &model::NetMap) -> String {
    let mut records = Vec::new();
    records.push(serde_json::json!({
        "name": netmap.node.dns_name,
        "node_id": netmap.node.id,
        "ipv4": netmap.node.ipv4,
        "ipv6": netmap.node.ipv6,
    }));
    for peer in &netmap.peers {
        records.push(serde_json::json!({
            "name": peer.dns_name,
            "node_id": peer.id,
            "ipv4": peer.ipv4,
            "ipv6": peer.ipv6,
        }));
    }

    serde_json::to_string_pretty(&serde_json::json!({
        "network": {
            "id": netmap.network.id,
            "name": netmap.network.name,
            "dns_domain": netmap.network.dns_domain,
        },
        "generated_at": netmap.generated_at,
        "records": records,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn default_hosts_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

fn apply_hosts_file(path: &PathBuf, profile: &str, netmap: &model::NetMap) -> Result<()> {
    let start = format!("# lightscale:{} begin", profile);
    let end = format!("# lightscale:{} end", profile);
    let contents = std::fs::read_to_string(path).unwrap_or_default();
    let mut output = String::new();
    let mut in_block = false;
    for line in contents.lines() {
        if line.trim() == start {
            in_block = true;
            continue;
        }
        if line.trim() == end {
            in_block = false;
            continue;
        }
        if !in_block {
            output.push_str(line);
            output.push('\n');
        }
    }
    output.push_str(&start);
    output.push('\n');
    output.push_str(&format!(
        "# {} {}\n",
        netmap.network.name, netmap.network.dns_domain
    ));
    output.push_str(&format!("{} {}\n", netmap.node.ipv4, netmap.node.dns_name));
    output.push_str(&format!("{} {}\n", netmap.node.ipv6, netmap.node.dns_name));
    for peer in &netmap.peers {
        output.push_str(&format!("{} {}\n", peer.ipv4, peer.dns_name));
        output.push_str(&format!("{} {}\n", peer.ipv6, peer.dns_name));
    }
    output.push_str(&end);
    output.push('\n');
    std::fs::write(path, output)?;
    Ok(())
}

fn print_relay_config(netmap: &model::NetMap) {
    let mut output = String::new();
    if let Some(relay) = &netmap.relay {
        output.push_str(&format!("stun: {}\n", relay.stun_servers.join(", ")));
        output.push_str(&format!("turn: {}\n", relay.turn_servers.join(", ")));
        output.push_str(&format!(
            "stream-relay: {}\n",
            relay.stream_relay_servers.join(", ")
        ));
        output.push_str(&format!(
            "udp-relay: {}\n",
            relay.udp_relay_servers.join(", ")
        ));
    } else {
        output.push_str("relay: none\n");
    }
    write_stdout_best_effort(&output);
}

fn write_stdout_best_effort(text: &str) {
    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout.write_all(text.as_bytes()) {
        if err.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("failed writing output: {}", err);
        }
    }
}

async fn apply_netmap_update(
    data_plane: &dyn data_plane::DataPlane,
    state_path: &PathBuf,
    state: &mut ClientState,
    netmap: model::NetMap,
    wg_cfg: &wg::WgConfig,
    apply_routes: bool,
    routes_cfg: &routes::RouteApplyConfig,
    probe_peers: bool,
    probe_timeout: u64,
    profile: &str,
    dns_hosts_path: Option<&PathBuf>,
) -> Result<()> {
    state.ipv4 = netmap.node.ipv4.clone();
    state.ipv6 = netmap.node.ipv6.clone();
    state.last_netmap = Some(netmap.clone());
    state.updated_at = now_unix();
    save_state(state_path, state)?;

    if !netmap.node.approved {
        if netmap.node.revoked {
            println!("node {} revoked", state.node_id);
            return Ok(());
        }
        if netmap.node.key_rotation_required {
            println!("node {} requires key rotation", state.node_id);
            return Ok(());
        }
        println!("node {} pending approval", state.node_id);
        return Ok(());
    }

    let wg_routes_cfg = if apply_routes { Some(routes_cfg) } else { None };
    data_plane.wg_apply(&netmap, state, wg_cfg, wg_routes_cfg).await?;
    if apply_routes {
        data_plane.apply_advertised_routes(&netmap, routes_cfg).await?;
    }
    if probe_peers {
        data_plane.wg_probe_peers(&netmap, probe_timeout)?;
    }
    if let Some(path) = dns_hosts_path {
        apply_hosts_file(path, profile, &netmap)?;
    }
    Ok(())
}

async fn gather_stun_servers(
    control_urls: &[String],
    tls_pin: Option<String>,
    state: &mut ClientState,
    state_path: &PathBuf,
    overrides: &[String],
) -> Result<Vec<String>> {
    if !overrides.is_empty() {
        return Ok(overrides.to_vec());
    }

    if let Some(netmap) = state.last_netmap.as_ref() {
        if let Some(relay) = &netmap.relay {
            if !relay.stun_servers.is_empty() {
                return Ok(relay.stun_servers.clone());
            }
        }
    }

    let netmap = ensure_netmap(control_urls, tls_pin, state, state_path).await?;
    if let Some(relay) = netmap.relay {
        if !relay.stun_servers.is_empty() {
            return Ok(relay.stun_servers);
        }
    }

    Ok(Vec::new())
}

async fn gather_udp_relay_servers(
    control_urls: &[String],
    tls_pin: Option<String>,
    state: &mut ClientState,
    state_path: &PathBuf,
) -> Result<Vec<String>> {
    if let Some(netmap) = state.last_netmap.as_ref() {
        if let Some(relay) = &netmap.relay {
            if !relay.udp_relay_servers.is_empty() {
                return Ok(relay.udp_relay_servers.clone());
            }
        }
    }

    let netmap = ensure_netmap(control_urls, tls_pin, state, state_path).await?;
    if let Some(relay) = netmap.relay {
        if !relay.udp_relay_servers.is_empty() {
            return Ok(relay.udp_relay_servers);
        }
    }

    Ok(Vec::new())
}

async fn gather_stream_relay_servers(
    control_urls: &[String],
    tls_pin: Option<String>,
    state: &mut ClientState,
    state_path: &PathBuf,
) -> Result<Vec<String>> {
    if let Some(netmap) = state.last_netmap.as_ref() {
        if let Some(relay) = &netmap.relay {
            if !relay.stream_relay_servers.is_empty() {
                return Ok(relay.stream_relay_servers.clone());
            }
        }
    }

    let netmap = ensure_netmap(control_urls, tls_pin, state, state_path).await?;
    if let Some(relay) = netmap.relay {
        if !relay.stream_relay_servers.is_empty() {
            return Ok(relay.stream_relay_servers);
        }
    }

    Ok(Vec::new())
}

async fn gather_turn_servers(
    control_urls: &[String],
    tls_pin: Option<String>,
    state: &mut ClientState,
    state_path: &PathBuf,
) -> Result<Vec<String>> {
    if let Some(netmap) = state.last_netmap.as_ref() {
        if let Some(relay) = &netmap.relay {
            if !relay.turn_servers.is_empty() {
                return Ok(relay.turn_servers.clone());
            }
        }
    }

    let netmap = ensure_netmap(control_urls, tls_pin, state, state_path).await?;
    if let Some(relay) = netmap.relay {
        if !relay.turn_servers.is_empty() {
            return Ok(relay.turn_servers);
        }
    }

    Ok(Vec::new())
}

async fn maybe_stun_endpoint(
    servers: &[String],
    bind_port: Option<u16>,
    timeout: Duration,
) -> Result<Option<String>> {
    if servers.is_empty() {
        eprintln!("stun: no servers configured");
        return Ok(None);
    }

    let servers = servers.to_vec();
    let port = bind_port.unwrap_or(0);
    let result =
        tokio::task::spawn_blocking(move || stun::discover_endpoint(&servers, port, timeout))
            .await
            .map_err(|err| anyhow!("stun task failed: {}", err))?;

    match result {
        Ok(addr) => Ok(Some(addr.to_string())),
        Err(err) => {
            eprintln!("stun failed: {}", err);
            Ok(None)
        }
    }
}

async fn relay_udp_send(
    state: &ClientState,
    server: &str,
    peer_id: &str,
    message: &str,
    _timeout: u64,
) -> Result<()> {
    let server_addr = udp_relay::resolve_server(server)?;
    let bind_addr = udp_relay::bind_addr_for(&server_addr);
    let socket = UdpSocket::bind(bind_addr).await?;

    let register = udp_relay::build_register(&state.node_id)?;
    socket.send_to(&register, server_addr).await?;

    let payload = message.as_bytes();
    let send = udp_relay::build_send(&state.node_id, peer_id, payload)?;
    socket.send_to(&send, server_addr).await?;
    Ok(())
}

async fn relay_udp_listen(state: &ClientState, server: &str) -> Result<()> {
    let server_addr = udp_relay::resolve_server(server)?;
    let bind_addr = udp_relay::bind_addr_for(&server_addr);
    let socket = UdpSocket::bind(bind_addr).await?;

    let register = udp_relay::build_register(&state.node_id)?;
    socket.send_to(&register, server_addr).await?;

    let mut buf = vec![0u8; 2048];
    println!("listening on udp relay {} as {}", server, state.node_id);
    loop {
        let (len, _) = socket.recv_from(&mut buf).await?;
        if let Some((from, payload)) = udp_relay::parse_deliver(&buf[..len]) {
            let text = String::from_utf8_lossy(&payload);
            println!("from {}: {}", from, text);
        }
    }
}

async fn relay_stream_send(
    state: &ClientState,
    server: &str,
    peer_id: &str,
    message: &str,
) -> Result<()> {
    relay_stream_send_raw(state, server, peer_id, message.as_bytes()).await
}

async fn relay_stream_listen(state: &ClientState, server: &str) -> Result<()> {
    let mut stream = TcpStream::connect(server).await?;
    stream_relay::write_register(&mut stream, &state.node_id).await?;
    println!("listening on stream relay {} as {}", server, state.node_id);
    loop {
        match stream_relay::read_deliver(&mut stream).await? {
            Some((from, payload)) => {
                let text = String::from_utf8_lossy(&payload);
                println!("from {}: {}", from, text);
            }
            None => {}
        }
    }
}

async fn relay_stream_listen_any(state: &ClientState, servers: &[String]) -> Result<()> {
    if servers.is_empty() {
        return Err(anyhow!("no stream relay server configured"));
    }
    let mut last_err = None;
    for server in servers {
        match relay_stream_listen(state, server).await {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no stream relay server configured")))
}

async fn relay_stream_send_raw(
    state: &ClientState,
    server: &str,
    peer_id: &str,
    payload: &[u8],
) -> Result<()> {
    let mut stream = TcpStream::connect(server).await?;
    stream_relay::write_register(&mut stream, &state.node_id).await?;
    stream_relay::write_send(&mut stream, &state.node_id, peer_id, payload).await?;
    Ok(())
}

async fn relay_stream_send_raw_any(
    state: &ClientState,
    servers: &[String],
    peer_id: &str,
    payload: &[u8],
) -> Result<()> {
    if servers.is_empty() {
        return Err(anyhow!("no stream relay server configured"));
    }
    let mut last_err = None;
    for server in servers {
        match relay_stream_send_raw(state, server, peer_id, payload).await {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no stream relay server configured")))
}

async fn handle_probe_requests(netmap: &model::NetMap) -> Result<()> {
    if netmap.probe_requests.is_empty() {
        return Ok(());
    }
    let mut v4_socket: Option<UdpSocket> = None;
    let mut v6_socket: Option<UdpSocket> = None;
    for request in &netmap.probe_requests {
        if request.endpoints.is_empty() {
            probe_ip(&mut v4_socket, &mut v6_socket, &request.ipv4).await;
            probe_ip(&mut v4_socket, &mut v6_socket, &request.ipv6).await;
            continue;
        }
        for endpoint in &request.endpoints {
            let addr: SocketAddr = match endpoint.parse() {
                Ok(addr) => addr,
                Err(_) => {
                    eprintln!(
                        "probe request from {} had invalid endpoint {}",
                        request.peer_id, endpoint
                    );
                    continue;
                }
            };
            probe_addr(&mut v4_socket, &mut v6_socket, addr).await?;
        }
    }
    Ok(())
}

async fn probe_ip(
    v4_socket: &mut Option<UdpSocket>,
    v6_socket: &mut Option<UdpSocket>,
    address: &str,
) {
    let ip: IpAddr = match address.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("probe request skipped invalid address {}", address);
            return;
        }
    };
    let target = SocketAddr::new(ip, 9);
    if let Err(err) = probe_addr(v4_socket, v6_socket, target).await {
        eprintln!("probe request failed for {}: {}", target, err);
    }
}

async fn probe_addr(
    v4_socket: &mut Option<UdpSocket>,
    v6_socket: &mut Option<UdpSocket>,
    target: SocketAddr,
) -> Result<()> {
    let socket = match target {
        SocketAddr::V4(_) => {
            if v4_socket.is_none() {
                *v4_socket = Some(UdpSocket::bind("0.0.0.0:0").await?);
            }
            v4_socket.as_ref().unwrap()
        }
        SocketAddr::V6(_) => {
            if v6_socket.is_none() {
                *v6_socket = Some(UdpSocket::bind("[::]:0").await?);
            }
            v6_socket.as_ref().unwrap()
        }
    };
    let _ = socket.send_to(b"lightscale-probe", target).await;
    Ok(())
}

async fn ensure_netmap(
    control_urls: &[String],
    tls_pin: Option<String>,
    state: &mut ClientState,
    state_path: &PathBuf,
) -> Result<model::NetMap> {
    if let Some(netmap) = state.last_netmap.clone() {
        return Ok(netmap);
    }
    let client = ControlClient::new(
        control_urls.to_vec(),
        tls_pin,
        state.node_token.clone(),
        None,
    )?;
    let netmap = client
        .netmap(&state.node_id)
        .await
        .context("netmap fetch failed")?;
    state.last_netmap = Some(netmap.clone());
    state.updated_at = now_unix();
    save_state(state_path, state)?;
    Ok(netmap)
}

fn print_return_route_guidance(
    netmap: &model::NetMap,
    wg_interface: &str,
    out_interface: &str,
    lan_v4: Option<String>,
    lan_v6: Option<String>,
) {
    println!("snat disabled; ensure return routes exist on the LAN:");
    if let Some(lan_v4) = lan_v4 {
        println!("  {} -> {}", netmap.network.overlay_v4, lan_v4);
    } else {
        println!("  {} -> <router-ip>", netmap.network.overlay_v4);
    }

    if let Some(lan_v6) = lan_v6 {
        println!("  {} -> {}", netmap.network.overlay_v6, lan_v6);
    } else {
        println!("  {} -> <router-ip>", netmap.network.overlay_v6);
    }
    println!(
        "  # traffic from {} will be forwarded out {}",
        wg_interface, out_interface
    );
}

#[cfg(test)]
mod tests {
    use super::{build_admin_login_approval_url, resolve_machine_keys, resolve_wg_keys};
    use anyhow::Result;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn build_admin_login_approval_url_sets_expected_query_params() -> Result<()> {
        let url = build_admin_login_approval_url(
            "https://admin.example.com/",
            "net-123",
            "/v1/register/approve/node-1/secret-1",
            false,
        )?;
        let parsed = url::Url::parse(&url)?;
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("admin.example.com"));
        let params: std::collections::HashMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params.get("ls_join"), Some(&"1".to_string()));
        assert_eq!(params.get("network_id"), Some(&"net-123".to_string()));
        assert_eq!(
            params.get("auth_path"),
            Some(&"/v1/register/approve/node-1/secret-1".to_string())
        );
        assert_eq!(params.get("ls_auto_approve"), None);
        Ok(())
    }

    #[test]
    fn build_admin_login_approval_url_can_enable_auto_approve() -> Result<()> {
        let url = build_admin_login_approval_url(
            "https://admin.example.com/",
            "net-123",
            "/v1/register/approve/node-1/secret-1",
            true,
        )?;
        let parsed = url::Url::parse(&url)?;
        let params: std::collections::HashMap<String, String> =
            parsed.query_pairs().into_owned().collect();
        assert_eq!(params.get("ls_join"), Some(&"1".to_string()));
        assert_eq!(params.get("ls_auto_approve"), Some(&"1".to_string()));
        Ok(())
    }

    #[test]
    fn build_admin_login_approval_url_rejects_invalid_admin_url() {
        let result = build_admin_login_approval_url(
            "not-a-url",
            "net-123",
            "/v1/register/approve/node-1/secret-1",
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn resolve_machine_keys_reads_private_key_file() -> Result<()> {
        let private = STANDARD.encode([3u8; 32]);
        let path = write_temp_key_file("machine", &private)?;
        let pair = resolve_machine_keys(Some(&path))?;
        assert_eq!(pair.private_key, private);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn resolve_wg_keys_reads_private_key_file() -> Result<()> {
        let private = STANDARD.encode([5u8; 32]);
        let path = write_temp_key_file("wg", &private)?;
        let pair = resolve_wg_keys(Some(&path))?;
        assert_eq!(pair.private_key, private);
        std::fs::remove_file(path)?;
        Ok(())
    }

    fn write_temp_key_file(prefix: &str, private: &str) -> Result<PathBuf> {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos();
        path.push(format!("lightscale-{}-{}.key", prefix, nonce));
        std::fs::write(&path, private)?;
        Ok(path)
    }
}
