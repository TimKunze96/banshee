//! What the server keeps across restarts, in `state.json` in the data dir.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use banshee_proto::{Account, Ban, Channel, ChannelId, Key, Perm, Role, RoleId, Token, key_hex, parse_key};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    pub name: String,
    pub welcome: String,
    pub max_users: Option<u32>,
    /// Hashed, see [`hash_password`].
    pub password: Option<String>,
    /// Permanent channels in sibling order (parents don't have to come first).
    pub channels: Vec<StoredChannel>,
    pub roles: Vec<Role>,
    /// What new people get.
    pub default_role: RoleId,
    /// By key, hex.
    pub accounts: BTreeMap<String, StoredAccount>,
    pub bans: Vec<StoredBan>,
    pub tokens: Vec<Token>,
    pub next_channel: ChannelId,
    pub next_role: RoleId,
    pub next_ban: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredChannel {
    pub id: ChannelId,
    pub parent: Option<ChannelId>,
    pub name: String,
    #[serde(default)]
    pub topic: String,
    #[serde(default)]
    pub description: String,
    pub password: Option<String>,
    pub max_users: Option<u32>,
    #[serde(default)]
    pub talk_power: u32,
    #[serde(default)]
    pub default: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredAccount {
    pub name: String,
    pub role: RoleId,
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredBan {
    pub id: u32,
    pub key: Option<String>,
    pub ip: Option<String>,
    pub name: String,
    pub reason: String,
    pub by: String,
    pub created: u64,
    pub until: Option<u64>,
}

pub const ADMIN: RoleId = 1;
pub const FIRST_ADMIN_NOTE: &str = "first admin";

impl Store {
    /// A new server: the given channels (the first is the default), the
    /// standard roles and a token that makes its redeemer admin.
    pub fn fresh(channels: &[String]) -> Self {
        let role = |id, name: &str, rank, perms: &[Perm], talk_power| Role {
            id,
            name: name.into(),
            rank,
            perms: perms.to_vec(),
            talk_power,
        };
        use Perm::*;
        let roles = vec![
            role(ADMIN, "Admin", 100, &Perm::ALL, 100),
            role(2, "Moderator", 50, &[ManageChannels, CreateTempChannels, JoinAny, MoveUsers, Kick, Mute], 50),
            role(3, "Member", 10, &[CreateTempChannels], 10),
            role(4, "Guest", 0, &[], 0),
        ];
        let channels: Vec<StoredChannel> = channels
            .iter()
            .zip(1..)
            .map(|(name, id)| StoredChannel {
                id,
                parent: None,
                name: name.clone(),
                topic: String::new(),
                description: String::new(),
                password: None,
                max_users: None,
                talk_power: 0,
                default: id == 1,
            })
            .collect();
        Self {
            name: "Banshee".into(),
            welcome: String::new(),
            max_users: None,
            password: None,
            next_channel: channels.len() as ChannelId + 1,
            channels,
            roles,
            default_role: 3,
            accounts: BTreeMap::new(),
            bans: Vec::new(),
            tokens: vec![Token { token: new_token(), role: ADMIN, note: FIRST_ADMIN_NOTE.into(), created: now() }],
            next_role: 5,
            next_ban: 1,
        }
    }

    pub fn path(dir: &Path) -> PathBuf {
        dir.join("state.json")
    }

    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let path = Self::path(dir);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(serde_json::from_slice(&data).with_context(|| format!("reading {}", path.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write it out, through a temporary file so a crash can't leave half of it.
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join("state.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, Self::path(dir))?;
        Ok(())
    }

    pub fn role(&self, id: RoleId) -> Option<&Role> {
        self.roles.iter().find(|r| r.id == id)
    }

    pub fn account(&self, key: &Key) -> Option<&StoredAccount> {
        self.accounts.get(&key_hex(key))
    }

    pub fn accounts(&self) -> Vec<Account> {
        self.accounts
            .iter()
            .filter_map(|(k, a)| {
                Some(Account { key: parse_key(k)?, name: a.name.clone(), role: a.role, last_seen: a.last_seen })
            })
            .collect()
    }

    /// The ban that keeps this key or address out, if any.
    pub fn ban_for(&self, key: &Key, ip: &str) -> Option<&StoredBan> {
        let key = key_hex(key);
        let now = now();
        self.bans.iter().find(|b| {
            b.until.is_none_or(|u| u > now) && (b.key.as_deref() == Some(&key) || b.ip.as_deref() == Some(ip))
        })
    }

    pub fn bans(&self) -> Vec<Ban> {
        self.bans
            .iter()
            .map(|b| Ban {
                id: b.id,
                key: b.key.as_deref().and_then(parse_key),
                ip: b.ip.clone(),
                name: b.name.clone(),
                reason: b.reason.clone(),
                by: b.by.clone(),
                created: b.created,
                until: b.until,
            })
            .collect()
    }

    /// Forget bans that ran out.
    pub fn prune_bans(&mut self) -> bool {
        let now = now();
        let before = self.bans.len();
        self.bans.retain(|b| b.until.is_none_or(|u| u > now));
        self.bans.len() != before
    }

    /// Nobody has redeemed the first admin token yet: it, to print.
    pub fn unused_admin_token(&self) -> Option<&str> {
        self.tokens.iter().find(|t| t.note == FIRST_ADMIN_NOTE).map(|t| t.token.as_str())
    }
}

impl StoredChannel {
    pub fn public(&self, permanent: bool) -> Channel {
        Channel {
            id: self.id,
            parent: self.parent,
            name: self.name.clone(),
            topic: self.topic.clone(),
            description: self.description.clone(),
            has_password: self.password.is_some(),
            max_users: self.max_users,
            talk_power: self.talk_power,
            permanent,
            default: self.default,
        }
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut out).expect("randomness");
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 20 characters people can read out and type.
pub fn new_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    random::<20>().iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

/// "salt:sha256(salt | password)", both hex.
pub fn hash_password(password: &str) -> String {
    let salt = hex(&random::<16>());
    let hash = Sha256::new().chain_update(salt.as_bytes()).chain_update(password.as_bytes()).finalize();
    format!("{salt}:{}", hex(&hash))
}

pub fn check_password(stored: &str, password: &str) -> bool {
    let Some((salt, want)) = stored.split_once(':') else { return false };
    let hash = Sha256::new().chain_update(salt.as_bytes()).chain_update(password.as_bytes()).finalize();
    hex(&hash) == want
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords() {
        let stored = hash_password("hunter2");
        assert!(check_password(&stored, "hunter2"));
        assert!(!check_password(&stored, "hunter3"));
        assert_ne!(stored, hash_password("hunter2"));
    }

    #[test]
    fn fresh_server_has_an_admin_token() {
        let s = Store::fresh(&["Lobby".into(), "Games".into()]);
        assert_eq!(s.unused_admin_token().map(str::len), Some(20));
        assert!(s.channels[0].default && !s.channels[1].default);
        assert!(s.role(ADMIN).unwrap().perms.len() == Perm::ALL.len());
    }
}
