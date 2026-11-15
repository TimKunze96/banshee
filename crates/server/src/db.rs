//! What the server keeps across restarts, in `banshee.db` (SQLite) in the
//! data dir. Channels, roles and settings are few and also live in memory;
//! accounts, bans, tokens, offline messages and the log are only read when
//! needed.

use std::path::Path;

use anyhow::{Context, Result};
use banshee_proto::{
    Account, Ban, ChannelId, Key, LogLine, OfflineMessage, Perm, Role, RoleId, Token, key_hex, parse_key,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ADMIN: RoleId = 1;
pub const FIRST_ADMIN_NOTE: &str = "first admin";
/// Offline messages kept per person.
const INBOX: u32 = 100;
const LOG_LINES: u32 = 10_000;

pub struct Db(Connection);

/// Server-wide settings.
#[derive(Clone, Debug)]
pub struct Settings {
    pub name: String,
    pub welcome: String,
    pub max_users: Option<u32>,
    /// Hashed, see [`hash_password`].
    pub password: Option<String>,
    /// What new people get.
    pub default_role: RoleId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug)]
pub struct StoredAccount {
    pub role: RoleId,
    pub avatar: Option<String>,
}

const SCHEMA: &str = "
CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT);
CREATE TABLE channels (
    id INTEGER PRIMARY KEY, parent INTEGER, position INTEGER NOT NULL, name TEXT NOT NULL,
    topic TEXT NOT NULL, description TEXT NOT NULL, password TEXT, max_users INTEGER,
    talk_power INTEGER NOT NULL, is_default INTEGER NOT NULL
);
CREATE TABLE roles (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, rank INTEGER NOT NULL, perms TEXT NOT NULL,
    talk_power INTEGER NOT NULL
);
CREATE TABLE accounts (
    key TEXT PRIMARY KEY, name TEXT NOT NULL, role INTEGER NOT NULL, last_seen INTEGER NOT NULL, avatar TEXT
);
CREATE TABLE bans (
    id INTEGER PRIMARY KEY, key TEXT, ip TEXT, name TEXT NOT NULL, reason TEXT NOT NULL, by TEXT NOT NULL,
    created INTEGER NOT NULL, until INTEGER
);
CREATE TABLE tokens (token TEXT PRIMARY KEY, role INTEGER NOT NULL, note TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY, to_key TEXT NOT NULL, from_key TEXT NOT NULL, from_name TEXT NOT NULL,
    subject TEXT NOT NULL, text TEXT NOT NULL, sent INTEGER NOT NULL, read INTEGER NOT NULL
);
CREATE INDEX messages_to ON messages (to_key);
CREATE TABLE log (id INTEGER PRIMARY KEY, time INTEGER NOT NULL, text TEXT NOT NULL);
";

impl Db {
    /// Open (or create) the database. A new one gets `channels` (the first
    /// is the default), the standard roles and a token that makes its
    /// redeemer admin.
    pub fn open(dir: &Path, channels: &[String]) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join("banshee.db");
        let conn = Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut db = Self(conn);
        let version: u32 = db.0.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 0 {
            let tx = db.0.transaction()?;
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
            if !db.import_json(dir)? {
                if channels.is_empty() {
                    anyhow::bail!("the server needs at least one channel");
                }
                db.seed(channels)?;
            }
        }
        Ok(db)
    }

    fn seed(&mut self, channels: &[String]) -> Result<()> {
        use Perm::*;
        let role = |id, name: &str, rank, perms: &[Perm], talk_power| Role {
            id,
            name: name.into(),
            rank,
            perms: perms.to_vec(),
            talk_power,
        };
        let moderator = [ManageChannels, CreateTempChannels, JoinAny, MoveUsers, Kick, Mute, UploadFiles, ManageFiles];
        for r in [
            role(ADMIN, "Admin", 100, &Perm::ALL, 100),
            role(2, "Moderator", 50, &moderator, 50),
            role(3, "Member", 10, &[CreateTempChannels, UploadFiles], 10),
            role(4, "Guest", 0, &[], 0),
        ] {
            self.save_role(&r)?;
        }
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
        self.save_channels(&channels)?;
        self.save_settings(&Settings {
            name: "Banshee".into(),
            welcome: String::new(),
            max_users: None,
            password: None,
            default_role: 3,
        })?;
        self.add_token(&Token { token: new_token(), role: ADMIN, note: FIRST_ADMIN_NOTE.into(), created: now() })?;
        Ok(())
    }

    /// Take over a `state.json` from before the database, if there is one.
    fn import_json(&mut self, dir: &Path) -> Result<bool> {
        #[derive(Deserialize)]
        struct Old {
            name: String,
            welcome: String,
            max_users: Option<u32>,
            password: Option<String>,
            channels: Vec<StoredChannel>,
            roles: Vec<Role>,
            default_role: RoleId,
            accounts: std::collections::BTreeMap<String, OldAccount>,
            bans: Vec<OldBan>,
            tokens: Vec<Token>,
        }
        #[derive(Deserialize)]
        struct OldAccount {
            name: String,
            role: RoleId,
            last_seen: u64,
        }
        #[derive(Deserialize)]
        struct OldBan {
            key: Option<String>,
            ip: Option<String>,
            name: String,
            reason: String,
            by: String,
            created: u64,
            until: Option<u64>,
        }
        let path = dir.join("state.json");
        let Ok(data) = std::fs::read(&path) else { return Ok(false) };
        let old: Old = serde_json::from_slice(&data).with_context(|| format!("reading {}", path.display()))?;
        let tx = self.0.transaction()?;
        {
            let db = Db::borrowed(&tx);
            for r in &old.roles {
                db.save_role(r)?;
            }
            for (key, a) in &old.accounts {
                tx.execute(
                    "INSERT INTO accounts (key, name, role, last_seen) VALUES (?1, ?2, ?3, ?4)",
                    params![key, a.name, a.role, a.last_seen],
                )?;
            }
            for b in &old.bans {
                tx.execute(
                    "INSERT INTO bans (key, ip, name, reason, by, created, until) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![b.key, b.ip, b.name, b.reason, b.by, b.created, b.until],
                )?;
            }
            for t in &old.tokens {
                db.add_token(t)?;
            }
            db.save_channels(&old.channels)?;
            db.save_settings(&Settings {
                name: old.name,
                welcome: old.welcome,
                max_users: old.max_users,
                password: old.password,
                default_role: old.default_role,
            })?;
        }
        tx.commit()?;
        std::fs::rename(&path, dir.join("state.json.imported"))?;
        Ok(true)
    }

    /// The same queries on a transaction (it derefs to a connection).
    fn borrowed(conn: &Connection) -> BorrowedDb<'_> {
        BorrowedDb(conn)
    }

    fn conn(&self) -> BorrowedDb<'_> {
        BorrowedDb(&self.0)
    }

    pub fn settings(&self) -> Result<Settings> {
        let get = |name: &str| -> Result<Option<String>> {
            Ok(self
                .0
                .query_row("SELECT value FROM settings WHERE name = ?1", [name], |r| r.get::<_, Option<String>>(0))
                .optional()?
                .flatten())
        };
        Ok(Settings {
            name: get("name")?.unwrap_or_else(|| "Banshee".into()),
            welcome: get("welcome")?.unwrap_or_default(),
            max_users: get("max_users")?.and_then(|m| m.parse().ok()),
            password: get("password")?,
            default_role: get("default_role")?.and_then(|r| r.parse().ok()).unwrap_or(3),
        })
    }

    pub fn save_settings(&self, s: &Settings) -> Result<()> {
        self.conn().save_settings(s)
    }

    pub fn channels(&self) -> Result<Vec<StoredChannel>> {
        let mut stmt = self.0.prepare(
            "SELECT id, parent, name, topic, description, password, max_users, talk_power, is_default
             FROM channels ORDER BY position",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(StoredChannel {
                id: r.get(0)?,
                parent: r.get(1)?,
                name: r.get(2)?,
                topic: r.get(3)?,
                description: r.get(4)?,
                password: r.get(5)?,
                max_users: r.get(6)?,
                talk_power: r.get(7)?,
                default: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Replace the permanent channels (in sibling order).
    pub fn save_channels(&self, channels: &[StoredChannel]) -> Result<()> {
        self.conn().save_channels(channels)
    }

    /// The next channel id, above every saved one.
    pub fn next_channel(&self) -> Result<ChannelId> {
        Ok(self.0.query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM channels", [], |r| r.get(0))?)
    }

    pub fn roles(&self) -> Result<Vec<Role>> {
        let mut stmt = self.0.prepare("SELECT id, name, rank, perms, talk_power FROM roles ORDER BY rank DESC, id")?;
        let rows = stmt.query_map([], |r| {
            let perms: String = r.get(3)?;
            Ok(Role {
                id: r.get(0)?,
                name: r.get(1)?,
                rank: r.get(2)?,
                perms: serde_json::from_str(&perms).unwrap_or_default(),
                talk_power: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Insert or replace; id 0 gets a new id, which is returned.
    pub fn save_role(&self, role: &Role) -> Result<RoleId> {
        self.conn().save_role(role)
    }

    /// Delete a role; whoever had it gets `fallback`, its tokens go.
    pub fn delete_role(&mut self, id: RoleId, fallback: RoleId) -> Result<()> {
        let tx = self.0.transaction()?;
        tx.execute("DELETE FROM roles WHERE id = ?1", [id])?;
        tx.execute("DELETE FROM tokens WHERE role = ?1", [id])?;
        tx.execute("UPDATE accounts SET role = ?2 WHERE role = ?1", [id, fallback])?;
        tx.commit()?;
        Ok(())
    }

    pub fn account(&self, key: &Key) -> Result<Option<StoredAccount>> {
        Ok(self
            .0
            .query_row("SELECT role, avatar FROM accounts WHERE key = ?1", [key_hex(key)], |r| {
                Ok(StoredAccount { role: r.get(0)?, avatar: r.get(1)? })
            })
            .optional()?)
    }

    /// Note that someone is here (making the account if it's new).
    pub fn touch_account(&self, key: &Key, name: &str, role: RoleId) -> Result<()> {
        self.0.execute(
            "INSERT INTO accounts (key, name, role, last_seen) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (key) DO UPDATE SET name = excluded.name, last_seen = excluded.last_seen",
            params![key_hex(key), name, role, now()],
        )?;
        Ok(())
    }

    pub fn set_role(&self, key: &Key, role: RoleId) -> Result<()> {
        self.0.execute("UPDATE accounts SET role = ?2 WHERE key = ?1", params![key_hex(key), role])?;
        Ok(())
    }

    pub fn set_avatar(&self, key: &Key, hash: Option<&str>) -> Result<()> {
        self.0.execute("UPDATE accounts SET avatar = ?2 WHERE key = ?1", params![key_hex(key), hash])?;
        Ok(())
    }

    pub fn accounts(&self) -> Result<Vec<Account>> {
        let mut stmt = self.0.prepare("SELECT key, name, role, last_seen FROM accounts ORDER BY last_seen DESC")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (key, name, role, last_seen) = row?;
            if let Some(key) = parse_key(&key) {
                out.push(Account { key, name, role, last_seen });
            }
        }
        Ok(out)
    }

    pub fn account_name(&self, key: &Key) -> Result<Option<String>> {
        Ok(self.0.query_row("SELECT name FROM accounts WHERE key = ?1", [key_hex(key)], |r| r.get(0)).optional()?)
    }

    pub fn add_ban(&self, b: &Ban) -> Result<()> {
        self.0.execute(
            "INSERT INTO bans (key, ip, name, reason, by, created, until) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![b.key.as_ref().map(key_hex), b.ip, b.name, b.reason, b.by, b.created, b.until],
        )?;
        Ok(())
    }

    /// Bans that still count (ones that ran out are dropped).
    pub fn bans(&self) -> Result<Vec<Ban>> {
        self.0.execute("DELETE FROM bans WHERE until IS NOT NULL AND until <= ?1", [now()])?;
        let mut stmt = self.0.prepare("SELECT id, key, ip, name, reason, by, created, until FROM bans ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(Ban {
                id: r.get(0)?,
                key: r.get::<_, Option<String>>(1)?.as_deref().and_then(parse_key),
                ip: r.get(2)?,
                name: r.get(3)?,
                reason: r.get(4)?,
                by: r.get(5)?,
                created: r.get(6)?,
                until: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The ban that keeps this key or address out, if any.
    pub fn ban_for(&self, key: &Key, ip: &str) -> Result<Option<Ban>> {
        Ok(self.bans()?.into_iter().find(|b| b.key.as_ref() == Some(key) || b.ip.as_deref() == Some(ip)))
    }

    pub fn delete_ban(&self, id: u32) -> Result<()> {
        self.0.execute("DELETE FROM bans WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn add_token(&self, t: &Token) -> Result<()> {
        self.conn().add_token(t)
    }

    pub fn tokens(&self) -> Result<Vec<Token>> {
        let mut stmt = self.0.prepare("SELECT token, role, note, created FROM tokens ORDER BY created")?;
        let rows = stmt
            .query_map([], |r| Ok(Token { token: r.get(0)?, role: r.get(1)?, note: r.get(2)?, created: r.get(3)? }))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Use a token up: its role, if it existed.
    pub fn take_token(&self, token: &str) -> Result<Option<RoleId>> {
        Ok(self.0.query_row("DELETE FROM tokens WHERE token = ?1 RETURNING role", [token], |r| r.get(0)).optional()?)
    }

    pub fn delete_token(&self, token: &str) -> Result<()> {
        self.0.execute("DELETE FROM tokens WHERE token = ?1", [token])?;
        Ok(())
    }

    /// Nobody has redeemed the first admin token yet: it, to print.
    pub fn unused_admin_token(&self) -> Result<Option<String>> {
        Ok(self.0.query_row("SELECT token FROM tokens WHERE note = ?1", [FIRST_ADMIN_NOTE], |r| r.get(0)).optional()?)
    }

    /// Leave a message; the oldest ones go once someone has too many.
    pub fn send_offline(&self, to: &Key, from: &Key, from_name: &str, subject: &str, text: &str) -> Result<()> {
        let to = key_hex(to);
        self.0.execute(
            "INSERT INTO messages (to_key, from_key, from_name, subject, text, sent, read)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![to, key_hex(from), from_name, subject, text, now()],
        )?;
        self.0.execute(
            "DELETE FROM messages WHERE to_key = ?1 AND id NOT IN
             (SELECT id FROM messages WHERE to_key = ?1 ORDER BY id DESC LIMIT ?2)",
            params![to, INBOX],
        )?;
        Ok(())
    }

    pub fn inbox(&self, to: &Key) -> Result<Vec<OfflineMessage>> {
        let mut stmt = self.0.prepare(
            "SELECT id, from_key, from_name, subject, text, sent, read FROM messages WHERE to_key = ?1 ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([key_hex(to)], |r| {
            Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, from, from_name, subject, text, sent, read) = row?;
            let from = parse_key(&from).unwrap_or_default();
            out.push(OfflineMessage { id, from, from_name, subject, text, sent, read });
        }
        Ok(out)
    }

    pub fn mark_read(&self, to: &Key, id: u32, read: bool) -> Result<()> {
        self.0
            .execute("UPDATE messages SET read = ?3 WHERE id = ?1 AND to_key = ?2", params![id, key_hex(to), read])?;
        Ok(())
    }

    pub fn delete_offline(&self, to: &Key, id: u32) -> Result<()> {
        self.0.execute("DELETE FROM messages WHERE id = ?1 AND to_key = ?2", params![id, key_hex(to)])?;
        Ok(())
    }

    pub fn log(&self, text: &str) -> Result<()> {
        let id: u32 = self.0.query_row(
            "INSERT INTO log (time, text) VALUES (?1, ?2) RETURNING id",
            params![now(), text],
            |r| r.get(0),
        )?;
        if id.is_multiple_of(1000) {
            self.0.execute("DELETE FROM log WHERE id <= ?1", [id.saturating_sub(LOG_LINES)])?;
        }
        Ok(())
    }

    /// The last `lines` lines, oldest first.
    pub fn read_log(&self, lines: u32) -> Result<Vec<LogLine>> {
        let mut stmt = self.0.prepare("SELECT time, text FROM log ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([lines], |r| Ok(LogLine { time: r.get(0)?, text: r.get(1)? }))?;
        let mut out: Vec<LogLine> = rows.collect::<rusqlite::Result<_>>()?;
        out.reverse();
        Ok(out)
    }
}

/// Writes shared by the database and its transactions.
struct BorrowedDb<'a>(&'a Connection);

impl BorrowedDb<'_> {
    fn save_settings(&self, s: &Settings) -> Result<()> {
        let mut stmt = self.0.prepare("INSERT OR REPLACE INTO settings (name, value) VALUES (?1, ?2)")?;
        stmt.execute(params!["name", s.name])?;
        stmt.execute(params!["welcome", s.welcome])?;
        stmt.execute(params!["max_users", s.max_users.map(|m| m.to_string())])?;
        stmt.execute(params!["password", s.password])?;
        stmt.execute(params!["default_role", s.default_role.to_string()])?;
        Ok(())
    }

    fn save_channels(&self, channels: &[StoredChannel]) -> Result<()> {
        self.0.execute("SAVEPOINT channels", [])?;
        let result = (|| {
            self.0.execute("DELETE FROM channels", [])?;
            let mut stmt = self.0.prepare(
                "INSERT INTO channels (id, parent, position, name, topic, description, password, max_users,
                 talk_power, is_default) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for (i, c) in channels.iter().enumerate() {
                stmt.execute(params![
                    c.id,
                    c.parent,
                    i,
                    c.name,
                    c.topic,
                    c.description,
                    c.password,
                    c.max_users,
                    c.talk_power,
                    c.default
                ])?;
            }
            anyhow::Ok(())
        })();
        match result {
            Ok(()) => self.0.execute("RELEASE channels", [])?,
            Err(e) => {
                self.0.execute("ROLLBACK TO channels", [])?;
                self.0.execute("RELEASE channels", [])?;
                return Err(e);
            }
        };
        Ok(())
    }

    fn save_role(&self, r: &Role) -> Result<RoleId> {
        let perms = serde_json::to_string(&r.perms)?;
        let id = if r.id == 0 { None } else { Some(r.id) };
        Ok(self.0.query_row(
            "INSERT OR REPLACE INTO roles (id, name, rank, perms, talk_power) VALUES (?1, ?2, ?3, ?4, ?5) RETURNING id",
            params![id, r.name, r.rank, perms, r.talk_power],
            |row| row.get(0),
        )?)
    }

    fn add_token(&self, t: &Token) -> Result<()> {
        self.0.execute(
            "INSERT INTO tokens (token, role, note, created) VALUES (?1, ?2, ?3, ?4)",
            params![t.token, t.role, t.note, t.created],
        )?;
        Ok(())
    }
}

impl StoredChannel {
    pub fn public(&self, permanent: bool) -> banshee_proto::Channel {
        banshee_proto::Channel {
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

/// Short content hash for avatars.
pub fn content_hash(data: &[u8]) -> String {
    hex(&Sha256::digest(data)[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("banshee-db-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn passwords() {
        let stored = hash_password("hunter2");
        assert!(check_password(&stored, "hunter2"));
        assert!(!check_password(&stored, "hunter3"));
        assert_ne!(stored, hash_password("hunter2"));
    }

    #[test]
    fn new_server() {
        let d = dir("new");
        let db = Db::open(&d, &["Lobby".into(), "Games".into()]).unwrap();
        assert_eq!(db.unused_admin_token().unwrap().map(|t| t.len()), Some(20));
        let channels = db.channels().unwrap();
        assert!(channels[0].default && !channels[1].default);
        assert_eq!(db.roles().unwrap()[0].perms.len(), Perm::ALL.len());
        assert_eq!(db.next_channel().unwrap(), 3);
        drop(db);
        // opening again keeps it as it is
        let db = Db::open(&d, &[]).unwrap();
        assert_eq!(db.channels().unwrap().len(), 2);
    }

    #[test]
    fn imports_state_json() {
        let d = dir("import");
        std::fs::create_dir_all(&d).unwrap();
        let key = "ab".repeat(32);
        let json = serde_json::json!({
            "name": "Old", "welcome": "hi", "max_users": null, "password": null,
            "channels": [{"id": 7, "parent": null, "name": "Lobby", "password": null, "max_users": null, "default": true}],
            "roles": [{"id": 1, "name": "Admin", "rank": 100, "perms": ["Kick"], "talk_power": 100}],
            "default_role": 1,
            "accounts": {key.clone(): {"name": "A", "role": 1, "last_seen": 5}},
            "bans": [], "tokens": [], "next_channel": 8, "next_role": 2, "next_ban": 1
        });
        std::fs::write(d.join("state.json"), json.to_string()).unwrap();
        let db = Db::open(&d, &[]).unwrap();
        assert_eq!(db.settings().unwrap().name, "Old");
        assert_eq!(db.channels().unwrap()[0].id, 7);
        assert_eq!(db.account(&parse_key(&key).unwrap()).unwrap().unwrap().role, 1);
        assert!(d.join("state.json.imported").exists());
    }

    #[test]
    fn inbox_and_log() {
        let d = dir("inbox");
        let db = Db::open(&d, &["Lobby".into()]).unwrap();
        let (a, b) = ([1; 32], [2; 32]);
        db.send_offline(&b, &a, "A", "hi", "see you").unwrap();
        let inbox = db.inbox(&b).unwrap();
        assert_eq!((inbox[0].subject.as_str(), inbox[0].read), ("hi", false));
        db.mark_read(&a, inbox[0].id, true).unwrap();
        assert!(!db.inbox(&b).unwrap()[0].read, "only the recipient can mark it");
        db.mark_read(&b, inbox[0].id, true).unwrap();
        assert!(db.inbox(&b).unwrap()[0].read);
        db.log("one").unwrap();
        db.log("two").unwrap();
        let log: Vec<String> = db.read_log(10).unwrap().into_iter().map(|l| l.text).collect();
        assert_eq!(log, ["one", "two"]);
    }
}
