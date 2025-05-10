use std::{
    cmp::Ordering,
    collections::HashSet,
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
    vec,
};

use ipnetwork::Ipv4Network;
use postgres_types::{FromSql, ToSql};
use rand::{Rng, distr::Alphanumeric};
use serde::Deserialize;
use serde_json::Value;
use string::{read_string, write_string};
use tokio::{
    fs::{self, File},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc,
    time::timeout,
};
use tokio_postgres::{Client, NoTls};
use tokio_socks::tcp::Socks5Stream;
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt};
use u16::write_u16;
use uuid::Uuid;
use varint::{read_var_int, write_var_int};

mod string;
mod u16;
mod varint;

#[derive(Deserialize, Clone)]
struct Settings {
    cidr: String,
    exclude_file: String,
    worker_count: usize,
    connection_timeout_secs: u64,
    use_tor: bool,
    validate: bool,
    validate_worker_count: usize,
}

async fn read_exclude_list(path: &str) -> Result<Vec<(u32, u32)>> {
    let mut ranges = Vec::new();
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((start_str, end_str)) = line.split_once('-') {
            if let (Ok(start), Ok(end)) =
                (start_str.parse::<Ipv4Addr>(), end_str.parse::<Ipv4Addr>())
            {
                let start_u32 = u32::from(start);
                let end_u32 = u32::from(end);
                if start_u32 <= end_u32 {
                    ranges.push((start_u32, end_u32));
                }
            }
        } else if let Ok(network) = line.parse::<Ipv4Network>() {
            let start = u32::from(network.network());
            let size = network.size();
            let end = start + (size - 1);
            ranges.push((start, end));
        } else {
            error!("Invalid network format: {}", line);
        }
    }

    merge_ranges(&mut ranges);
    Ok(ranges)
}

fn merge_ranges(ranges: &mut Vec<(u32, u32)>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable_by_key(|&(start, _)| start);

    let mut merged = vec![ranges[0]];
    for &(start, end) in &ranges[1..] {
        let last = merged.last_mut().unwrap();
        if start <= last.1.saturating_add(1) {
            if end > last.1 {
                last.1 = end;
            }
        } else {
            merged.push((start, end));
        }
    }

    *ranges = merged;
}

fn ip_in_excludes(ip: Ipv4Addr, ranges: &[(u32, u32)]) -> bool {
    let ip_u32 = u32::from(ip);
    ranges
        .binary_search_by(|&(start, end)| {
            if ip_u32 < start {
                Ordering::Greater
            } else if ip_u32 > end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::registry().with(fmt::layer().with_ansi(true));

    tracing::subscriber::set_global_default(subscriber).ok();

    // Load settings
    let settings = match load_settings("settings.json").await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to load settings: {}", e);
            return;
        }
    };

    let last_ip_path = "last_ip.txt";
    let last_ip = read_last_ip(last_ip_path).await;

    // Parse CIDR
    let network: Ipv4Network = match settings.cidr.parse() {
        Ok(net) => net,
        Err(_) => {
            error!("Invalid CIDR: {}", settings.cidr);
            return;
        }
    };

    // Read exclude ranges
    let exclude_ranges = match read_exclude_list(&settings.exclude_file).await {
        Ok(ranges) => ranges,
        Err(e) => {
            error!("Failed to read exclude file: {}", e);
            Vec::new()
        }
    };
    let exclude_ranges = Arc::new(exclude_ranges);

    // Create a bounded channel
    let (tx, rx) = mpsc::channel::<Ipv4Addr>(settings.worker_count * 2);

    // Producer task
    let exclude_ranges_clone = Arc::clone(&exclude_ranges);
    let producer_handle = tokio::spawn(async move {
        let skip = last_ip.map(u32::from);
        let network_start = u32::from(network.network());
        let network_end = network_start + network.size() as u32 - 1;

        let mut ip = network_start;

        loop {
            if let Some(skip_to) = skip {
                if ip < skip_to {
                    ip += 1;
                    continue;
                }
            }
            if ip_in_excludes(Ipv4Addr::from(ip), &exclude_ranges_clone) {
                ip += 1;
                continue;
            }
            if tx.send(Ipv4Addr::from(ip)).await.is_err() {
                break;
            }

            // Increment IP for the next iteration
            if ip == network_end {
                ip = network_start - 1; // Reset to the start if we've reached the end
            } else {
                ip += 1;
            }
        }
    });

    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=mcscanner_user dbname=mcscanner password=pwd",
        NoTls,
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("Connection error: {}", e);
        }
    });

    let client = Arc::new(client);

    // Consumer (worker) tasks
    let worker_handle = {
        let settings = settings.clone();
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let mut handles = Vec::new();
            let rx = Arc::new(tokio::sync::Mutex::new(rx)); // share receiver safely

            for _ in 0..settings.worker_count {
                let rx = Arc::clone(&rx);
                let settings = settings.clone();
                let client = Arc::clone(&client);
                let handle = tokio::spawn(async move {
                    loop {
                        let ip = {
                            let mut guard = rx.lock().await;
                            guard.recv().await
                        };
                        match ip {
                            Some(ip) => {
                                check_ip(ip, &settings, &client).await.unwrap_or_else(|e| {
                                    error!("Error checking IP {}: {}", ip, e);
                                });
                            }
                            None => break,
                        }
                    }
                });
                handles.push(handle);
            }

            // Wait for all worker tasks
            for h in handles {
                let _ = h.await;
            }
        })
    };

    if settings.validate {
        let client = Arc::clone(&client);
        let validate_handles = tokio::spawn(async move {
            let mut handles = Vec::new();
            for i in 0..settings.validate_worker_count {
                let s = settings.clone();
                handles.push(tokio::spawn(validate_worker(
                    i,
                    s.validate_worker_count,
                    s,
                    client.clone(),
                )));
            }
            for h in handles {
                let _ = h.await;
            }
        });
        let _ = validate_handles.await;
    }

    // Wait for both tasks
    let _ = producer_handle.await;
    let _ = worker_handle.await;
}

async fn check_ip(
    ip: Ipv4Addr,
    settings: &Settings,
    client: &tokio_postgres::Client,
) -> Result<()> {
    let addr = format!("{}:25565", ip);
    info!("Connecting to {}", addr);
    let timeout_dur = Duration::from_secs(settings.connection_timeout_secs);
    write_last_ip("last_ip.txt", ip).await;
    let mut stream = connect(ip, 25565, settings.use_tor, timeout_dur).await?;

    let handshake = create_handshake_packet(757, &ip.to_string(), 25565, 1).await;
    stream.write_all(&handshake).await?;

    let status = create_status_request().await;
    stream.write_all(&status).await?;

    let len = varint::read_var_int_from_stream(&mut stream).await?;
    let mut buffer = vec![0; len as usize];
    stream.read_exact(&mut buffer).await?;

    let mut index = 0;
    let code = read_var_int(&buffer, Some(&mut index));
    let response = read_string(&buffer, &mut index);
    info!("{}: Code {:?}, Response {:?}", addr, code, response);

    save_json(&addr, &response.unwrap_or_default(), client).await
}

async fn validate_worker(
    id: usize,
    total: usize,
    settings: Settings,
    client: Arc<tokio_postgres::Client>,
) {
    loop {
        let dir = match fs::read_dir("res").await {
            Ok(d) => d,
            Err(e) => {
                error!("Validator {} failed to read ./res: {}", id, e);
                return;
            }
        };

        tokio::pin!(dir);
        while let Some(entry) = dir.next_entry().await.unwrap_or(None) {
            info!(
                "Validator {}: checking {}",
                id,
                entry.file_name().to_string_lossy()
            );
            let folder = entry.file_name().to_string_lossy().into_owned();

            let sum: usize = folder.bytes().map(|b| b as usize).sum();
            if sum % total != id {
                continue;
            }

            let ip = *folder.split(":").collect::<Vec<&str>>().first().unwrap();
            let ip: Ipv4Addr = match ip.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    error!("Validator {}: invalid IP {}: {}", id, ip, e);
                    continue;
                }
            };

            check_ip(ip, &settings, &client)
                .await
                .unwrap_or_else(|e: Error| {
                    error!("Validator {}: error checking IP {}: {}", id, folder, e);
                });
        }
    }
}

#[derive(ToSql, FromSql, Debug, Clone, PartialEq, Eq)]
#[postgres(name = "version")]
struct Version {
    name: Option<String>,
    protocol: Option<i32>,
}

#[derive(ToSql, FromSql, Debug, Clone, PartialEq, Eq)]
#[postgres(name = "players")]
struct Players {
    max: Option<i32>,
    online: Option<i32>,
    sample: Option<Vec<Player>>,
}

#[derive(ToSql, FromSql, Debug, Clone, PartialEq, Eq)]
#[postgres(name = "player")]
struct Player {
    name: Option<String>,
    id: Option<String>,
}

#[derive(Debug, ToSql, FromSql)]
#[postgres(name = "action_type")]
pub enum ActionType {
    #[postgres(name = "JOINED")]
    Joined,
    #[postgres(name = "LEFT")]
    Left,
    #[postgres(name = "INIT")]
    Init,
}

pub async fn save_json(
    addr: &str,
    json_str: &str,
    client: &tokio_postgres::Client,
) -> std::io::Result<()> {
    use serde_json::Value;
    use std::io::{Error, ErrorKind};

    let json_str = json_str.replace("\\u0000", "").replace("\u{0000}", "");
    let mut json: Value = serde_json::from_str(&json_str)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Invalid JSON: {}", e)))?;

    let description = json.get("description").cloned();
    json.as_object_mut().map(|obj| obj.remove("description"));

    let parsed_description = parse_description(&description.clone().unwrap_or_default());

    let enforces_secure_chat = json.get("enforcesSecureChat").and_then(|v| v.as_bool());
    json.as_object_mut()
        .map(|obj| obj.remove("enforcesSecureChat"));

    let favicon = json
        .get("favicon")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    json.as_object_mut().map(|obj| obj.remove("favicon"));

    let players = json.get("players").map(parse_players);
    json.as_object_mut().map(|obj| obj.remove("players"));
    let version = json.get("version").map(parse_version);
    json.as_object_mut().map(|obj| obj.remove("version"));

    let extra = json;
    let extra_json = serde_json::to_value(extra)?;

    let row = client
        .query_opt(
            "SELECT description, raw_description, players, version, favicon, enforces_secure_chat, extra 
            FROM servers WHERE ip = $1 ORDER BY id DESC LIMIT 1;",
            &[&addr],
        )
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    if let Some(r) = row.clone() {
        let current_description: String = r.get("description");
        let current_raw_description: Option<Value> = r.get("raw_description");
        let current_players: Option<Players> = r.get("players");
        let current_version: Option<Version> = r.get("version");
        let current_favicon: Option<String> = r.get("favicon");
        let current_enforces_secure_chat: Option<bool> = r.get("enforces_secure_chat");
        let current_extra: Value = r.get("extra");

        if current_description == parsed_description.clone()
            && current_raw_description == description
            && current_players == players.clone()
            && current_version == version.clone()
            && current_favicon == favicon
            && current_enforces_secure_chat == enforces_secure_chat
            && current_extra == extra_json.clone()
        {
            info!("{}: No changes detected, skipping insert", addr);
            return Ok(());
        }
    };

    let row_server = client
        .query_one(
            "
        INSERT INTO servers (
            ip,
            description,
            raw_description,
            players, 
            version, 
            favicon, 
            enforces_secure_chat, 
            extra
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        ",
            &[
                &addr,
                &parsed_description,
                &description,
                &players,
                &version,
                &favicon,
                &enforces_secure_chat,
                &extra_json,
            ],
        )
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    let server_id: i32 = row_server.get("id");

    if let Some(players) = &players {
        if let Some(sample) = &players.sample {
            for player in sample {
                if player.name.is_none() || player.id.is_none() {
                    continue;
                }
                let id = get_user_id(
                    &client,
                    &player.name.clone().unwrap(),
                    &player.id.clone().unwrap(),
                )
                .await;
                if id.is_some() {
                    continue;
                }

                let player_row = client
                    .query_one(
                        "
                    INSERT INTO player_list (name, uuid, cracked)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (uuid, name) DO NOTHING
                    RETURNING id
                    ",
                        &[
                            &player.name,
                            &player.id,
                            &(name_to_uuid(&player.clone().name.unwrap())
                                == player.clone().id.unwrap()),
                        ],
                    )
                    .await
                    .unwrap();
                if row.is_none() {
                    let player_id: i32 = player_row.get("id");
                    client
                        .execute(
                            "
                        INSERT INTO player_actions (user_id, server_id, action)
                        VALUES ($1, $2, $3)
                        ",
                            &[&player_id, &server_id, &ActionType::Init],
                        )
                        .await
                        .unwrap();
                }
            }
        }
    }

    if let Some(r) = row {
        let current_players: Option<Players> = r.get("players");

        if current_players != players {
            let old_players = extract_players(current_players.clone());
            let new_players = extract_players(players.clone());

            let old_set: HashSet<_> = old_players.iter().collect();
            let new_set: HashSet<_> = new_players.iter().collect();

            let joined = new_set.difference(&old_set);
            let left = old_set.difference(&new_set);

            for (name, uuid) in joined.cloned() {
                let mut user_id = get_user_id(client, &name, &uuid).await;
                if user_id.is_none() {
                    client.execute(
                        "INSERT INTO player_list (name, uuid, cracked) VALUES ($1, $2, $3) ON CONFLICT (uuid, name) DO NOTHING",
                        &[&name, &uuid, &(name_to_uuid(name) == *uuid)],
                    ).await.unwrap();

                    user_id = get_user_id(client, &name, &uuid).await;
                }

                client.execute(
                    "INSERT INTO player_action (user_id, server_id, action) VALUES ($1, $2, $3)",
                    &[&user_id, &server_id,  &ActionType::Joined],
                ).await.unwrap();
            }

            for (name, uuid) in left.cloned() {
                let mut user_id = get_user_id(client, &name, &uuid).await;
                if user_id.is_none() {
                    client.execute(
                        "INSERT INTO player_list (name, uuid, cracked) VALUES ($1, $2, $3) ON CONFLICT (uuid, name) DO NOTHING",
                        &[&name, &uuid, &(name_to_uuid(name) == *uuid)],
                    ).await.unwrap();

                    user_id = get_user_id(client, &name, &uuid).await;
                }

                if let Some(_) = user_id {
                    client.execute(
                        "INSERT INTO player_action (user_id, server_id, action) VALUES ($1, $2, $3)",
                        &[&user_id, &server_id,  &ActionType::Left],
                    ).await.unwrap();
                }
            }
        }
    };

    Ok(())
}

fn extract_players(players: Option<Players>) -> Vec<(String, String)> {
    players
        .and_then(|p| p.sample)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| Some((p.name.clone()?, p.id.clone()?)))
        .collect()
}

pub async fn get_user_id(client: &Client, name: &str, uuid: &str) -> Option<String> {
    let row = client
        .query_opt(
            "SELECT id FROM player_list WHERE name = $1 AND uuid = $2",
            &[&name, &uuid],
        )
        .await
        .unwrap();

    if let Some(row) = row {
        let id: i32 = row.get("id");
        return Some(id.to_string());
    }
    None
}

fn parse_description(desc: &Value) -> String {
    match desc {
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let mut result = String::new();
            for item in arr {
                if let Some(Value::String(text)) = item.get("text") {
                    result.push_str(text);
                }
            }
            result
        }
        Value::Object(map) => {
            let mut result = String::new();

            if let Some(Value::String(text)) = map.get("text") {
                result.push_str(text);
            }

            if let Some(Value::Array(extra)) = map.get("extra") {
                for item in extra {
                    if let Some(Value::String(text)) = item.get("text") {
                        result.push_str(text);
                    }
                }
            }

            result
        }
        _ => "".to_string(),
    }
}

fn parse_players(players: &Value) -> Players {
    let max = players
        .get("max")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let online = players
        .get("online")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let sample = players.get("sample").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .map(|item| Player {
                name: item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                id: item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            })
            .collect()
    });

    Players {
        max,
        online,
        sample,
    }
}

fn parse_version(version: &Value) -> Version {
    let mut name = None;
    let mut protocol = None;

    if let Some(Value::String(v)) = version.get("name") {
        name = Some(v.clone());
    }

    if let Some(Value::Number(v)) = version.get("protocol") {
        protocol = v.as_i64().map(|v| v as i32);
    }

    Version { name, protocol }
}

async fn create_handshake_packet(
    protocol_version: i32,
    server_address: &str,
    server_port: u16,
    next_state: i32,
) -> Vec<u8> {
    let mut outer = Vec::new();
    let mut inner = Vec::new();
    write_var_int(&mut inner, &0x0);
    write_var_int(&mut inner, &protocol_version);
    write_string(&mut inner, server_address);
    write_u16(&mut inner, server_port);
    write_var_int(&mut inner, &next_state);
    write_var_int(&mut outer, &(inner.len() as i32));
    outer.extend_from_slice(&inner);
    outer
}

async fn create_status_request() -> Vec<u8> {
    let mut outer = Vec::new();
    let mut inner = Vec::new();
    write_var_int(&mut inner, &0x0);
    write_var_int(&mut outer, &(inner.len() as i32));
    outer.extend_from_slice(&inner);
    outer
}

async fn connect(
    ip: Ipv4Addr,
    port: u16,
    via_tor: bool,
    timeout_dur: Duration,
) -> Result<TcpStream> {
    let addr = format!("{}:{}", ip, port);

    if via_tor {
        let proxy = "127.0.0.1:9050";
        let user: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        let pass: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();
        let res = timeout(
            timeout_dur,
            Socks5Stream::connect_with_password(proxy, addr, &user, &pass),
        )
        .await;
        match res {
            Ok(Ok(s)) => Ok(s.into_inner()),
            Ok(Err(e)) => Err(Error::new(ErrorKind::Other, format!("SOCKS5 error: {}", e))),
            Err(_) => Err(Error::new(ErrorKind::TimedOut, "SOCKS5 timeout")),
        }
    } else {
        match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::new(ErrorKind::TimedOut, "TCP connect timeout")),
        }
    }
}

async fn load_settings(path: &str) -> Result<Settings> {
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file);
    let mut contents = String::new();
    reader.read_to_string(&mut contents).await?;
    serde_json::from_str(&contents).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
}

async fn read_last_ip(path: &str) -> Option<Ipv4Addr> {
    match File::open(path).await {
        Ok(mut file) => {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).await.is_ok() {
                contents.trim().parse().ok()
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

async fn write_last_ip(path: &str, ip: Ipv4Addr) {
    if let Ok(mut file) = File::create(path).await {
        let _ = file.write_all(ip.to_string().as_bytes()).await;
        let _ = file.flush().await;
    }
}

pub fn name_to_uuid(username: &str) -> String {
    let mut hash = md5::compute(format!("OfflinePlayer:{}", username)).0;
    hash[6] = hash[6] & 0x0f | 0x30; // uuid version 3
    hash[8] = hash[8] & 0x3f | 0x80; // RFC4122 variant

    let uuid = Uuid::from_bytes(hash);
    uuid.to_string()
}
