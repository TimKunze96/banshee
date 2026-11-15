//! Everything the server knows while it runs, and the rules for changing it.

use std::collections::HashMap;
use std::path::PathBuf;

use banshee_proto::{
    Ban, Channel, ChannelEdit, ChannelId, ChatTarget, ClientMsg, Key, Leave, NewChannel, Perm, Role, RoleId,
    ServerEdit, ServerInfo, ServerMsg, Token, User, UserId, Whisper, key_hex,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::db::{self, Db, Settings, StoredChannel, check_password, hash_password, now};
use crate::files;

pub const MAX_NAME: usize = 32;
const MAX_CHAT: usize = 2000;
const MAX_CHANNEL_NAME: usize = 64;
const MAX_TOPIC: usize = 255;
const MAX_DESCRIPTION: usize = 8000;
const MAX_SHORT: usize = 200;
const MAX_WHISPER: usize = 64;

pub struct State {
    pub db: Db,
    pub data_dir: PathBuf,
    settings: Settings,
    roles: Vec<Role>,
    next_channel: ChannelId,
    /// Sibling order is the order in here.
    channels: Vec<Chan>,
    pub users: HashMap<UserId, Peer>,
    next_user: UserId,
}

struct Chan {
    c: StoredChannel,
    permanent: bool,
}

pub struct Peer {
    pub user: User,
    pub conn: quinn::Connection,
    pub tx: mpsc::UnboundedSender<ServerMsg>,
    pub ip: String,
    pub whisper: Option<Whisper>,
}

/// Who connects, once their identity checked out.
pub struct Arrival {
    pub key: Key,
    pub name: String,
    pub password: Option<String>,
    pub ip: String,
    pub conn: quinn::Connection,
    pub tx: mpsc::UnboundedSender<ServerMsg>,
}

type Outcome = Result<(), String>;

impl State {
    pub fn new(db: Db, data_dir: PathBuf) -> anyhow::Result<Self> {
        let channels: Vec<Chan> = db.channels()?.into_iter().map(|c| Chan { c, permanent: true }).collect();
        if channels.is_empty() {
            anyhow::bail!("the server has no channels");
        }
        let mut s = Self {
            settings: db.settings()?,
            roles: db.roles()?,
            next_channel: db.next_channel()?,
            db,
            data_dir,
            channels,
            users: HashMap::new(),
            next_user: 1,
        };
        if !s.channels.iter().any(|c| c.c.default) {
            s.channels[0].c.default = true;
        }
        Ok(s)
    }

    /// Keep the permanent channels.
    fn save_channels(&mut self) {
        let keep: Vec<StoredChannel> = self.channels.iter().filter(|c| c.permanent).map(|c| c.c.clone()).collect();
        if let Err(e) = self.db.save_channels(&keep) {
            warn!("couldn't save the channels: {e:#}");
        }
    }

    /// Something for the server log.
    fn log(&self, text: String) {
        info!("{text}");
        if let Err(e) = self.db.log(&text) {
            warn!("couldn't write the log: {e:#}");
        }
    }

    pub fn admin_token(&self) -> Option<String> {
        self.db.unused_admin_token().ok().flatten()
    }

    pub fn info(&self) -> ServerInfo {
        ServerInfo {
            name: self.settings.name.clone(),
            welcome: self.settings.welcome.clone(),
            max_users: self.settings.max_users,
            has_password: self.settings.password.is_some(),
            default_role: self.settings.default_role,
        }
    }

    /// Channels in display order: each parent, then its children.
    pub fn channel_list(&self) -> Vec<Channel> {
        fn add(s: &State, parent: Option<ChannelId>, out: &mut Vec<Channel>) {
            for c in s.channels.iter().filter(|c| c.c.parent == parent) {
                out.push(c.c.public(c.permanent));
                add(s, Some(c.c.id), out);
            }
        }
        let mut out = Vec::new();
        add(self, None, &mut out);
        out
    }

    fn chan(&self, id: ChannelId) -> Option<&Chan> {
        self.channels.iter().find(|c| c.c.id == id)
    }

    fn default_channel(&self) -> ChannelId {
        self.channels.iter().find(|c| c.c.default).unwrap_or(&self.channels[0]).c.id
    }

    fn role(&self, id: RoleId) -> &Role {
        static NOBODY: Role = Role { id: 0, name: String::new(), rank: 0, perms: Vec::new(), talk_power: 0 };
        let find = |id| self.roles.iter().find(|r| r.id == id);
        find(id).or_else(|| find(self.settings.default_role)).unwrap_or(&NOBODY)
    }

    fn role_of(&self, id: UserId) -> &Role {
        let role = self.users.get(&id).map(|p| p.user.role).unwrap_or(0);
        self.role(role)
    }

    fn may(&self, id: UserId, perm: Perm) -> Outcome {
        match self.role_of(id).can(perm) {
            true => Ok(()),
            false => Err("you're not allowed to do that".into()),
        }
    }

    /// `id` may act on `target`: it's themselves or they rank higher.
    fn over(&self, id: UserId, target: UserId) -> Outcome {
        if id == target || self.role_of(id).rank > self.role_of(target).rank {
            Ok(())
        } else {
            Err("they rank the same as you or higher".into())
        }
    }

    fn known_role(&self, id: RoleId) -> Result<&Role, String> {
        self.roles.iter().find(|r| r.id == id).ok_or_else(|| "no such role".into())
    }

    fn user(&self, id: UserId) -> Result<&User, String> {
        self.users.get(&id).map(|p| &p.user).ok_or_else(|| "nobody with that id is here".into())
    }

    fn name(&self, id: UserId) -> String {
        self.users.get(&id).map(|p| p.user.name.clone()).unwrap_or_default()
    }

    pub fn send(&self, id: UserId, msg: ServerMsg) {
        if let Some(p) = self.users.get(&id) {
            let _ = p.tx.send(msg);
        }
    }

    pub fn broadcast(&self, to: impl Fn(&Peer) -> bool, msg: &ServerMsg) {
        for p in self.users.values().filter(|p| to(p)) {
            let _ = p.tx.send(msg.clone());
        }
    }

    fn changed(&self, id: UserId) {
        if let Some(p) = self.users.get(&id) {
            self.broadcast(|_| true, &ServerMsg::UserChanged(p.user.clone()));
        }
    }

    fn channels_changed(&self) {
        self.broadcast(|_| true, &ServerMsg::Channels(self.channel_list()));
    }

    /// Let someone in, or say why not.
    pub fn arrive(&mut self, a: Arrival) -> Result<UserId, String> {
        let name = a.name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME {
            return Err(format!("names need 1 to {MAX_NAME} characters"));
        }
        if let Some(ban) = stored(self.db.ban_for(&a.key, &a.ip))? {
            let until = match ban.until {
                Some(u) => format!(" for {} more minutes", (u.saturating_sub(now()) / 60).max(1)),
                None => String::new(),
            };
            return Err(format!("you're banned{until}: {}", ban.reason));
        }
        if let Some(hash) = &self.settings.password
            && !a.password.as_deref().is_some_and(|p| check_password(hash, p))
        {
            return Err("wrong server password".into());
        }
        let account = stored(self.db.account(&a.key))?;
        let role = account.as_ref().map(|acc| acc.role).unwrap_or(self.settings.default_role);
        let avatar = account.and_then(|acc| acc.avatar);
        if self.settings.max_users.is_some_and(|m| self.users.len() >= m as usize)
            && !self.role(role).can(Perm::JoinAny)
        {
            return Err("the server is full".into());
        }
        // most likely the old connection died and we haven't noticed yet
        let old: Vec<UserId> = self.users.values().filter(|p| p.user.key == a.key).map(|p| p.user.id).collect();
        for id in old {
            self.remove(id, Leave::Replaced);
        }

        let name = self.free_name(name, None);
        stored(self.db.touch_account(&a.key, &name, role))?;
        let unread = self.db.inbox(&a.key).map(|m| m.iter().filter(|m| !m.read).count()).unwrap_or(0);

        let id = self.next_user;
        self.next_user += 1;
        let user = User {
            id,
            key: a.key,
            name,
            channel: self.default_channel(),
            role,
            input_muted: false,
            output_muted: false,
            away: None,
            description: String::new(),
            server_muted: false,
            talk_granted: false,
            talk_request: None,
            avatar,
        };
        let welcome = ServerMsg::Welcome {
            you: id,
            server: self.info(),
            channels: self.channel_list(),
            users: self.users.values().map(|p| p.user.clone()).chain([user.clone()]).collect(),
            roles: self.roles.clone(),
        };
        self.broadcast(|_| true, &ServerMsg::UserJoined(user.clone()));
        let _ = a.tx.send(welcome);
        if unread > 0 {
            let text = match unread {
                1 => "You have a new offline message".to_string(),
                n => format!("You have {n} new offline messages"),
            };
            let _ = a.tx.send(ServerMsg::Notice { text });
        }
        self.log(format!("{} joined ({}, {})", user.name, key_hex(&a.key), a.ip));
        self.users.insert(id, Peer { user, conn: a.conn, tx: a.tx, ip: a.ip, whisper: None });
        Ok(id)
    }

    /// `name`, or with a number behind it when someone else has it.
    fn free_name(&self, name: &str, except: Option<UserId>) -> String {
        let taken =
            |n: &str| self.users.values().any(|p| Some(p.user.id) != except && p.user.name.eq_ignore_ascii_case(n));
        let mut candidate = name.to_string();
        let mut i = 1;
        while taken(&candidate) {
            candidate = format!("{name}{i}");
            i += 1;
        }
        candidate
    }

    /// Someone's connection ended; does nothing if they were already removed.
    pub fn depart(&mut self, id: UserId, reason: Leave) {
        if let Some(p) = self.users.remove(&id) {
            let why = match &reason {
                Leave::Quit => String::new(),
                Leave::Lost => " (connection lost)".into(),
                Leave::Kicked { by, reason } => format!(" (kicked by {}: {reason})", self.name(*by)),
                Leave::Banned { by, reason } => format!(" (banned by {}: {reason})", self.name(*by)),
                Leave::Replaced => " (connected again)".into(),
            };
            self.log(format!("{} left{why}", p.user.name));
            self.broadcast(|_| true, &ServerMsg::UserLeft { id, reason });
            self.drop_empty_channels();
        }
    }

    /// Tell them why, then drop them; their connection closes once that's sent.
    fn remove(&mut self, id: UserId, reason: Leave) {
        self.send(id, ServerMsg::UserLeft { id, reason: reason.clone() });
        self.depart(id, reason);
    }

    pub fn handle(&mut self, id: UserId, msg: ClientMsg) {
        if let Err(message) = self.apply(id, msg) {
            self.send(id, ServerMsg::Error { message });
        }
    }

    fn apply(&mut self, id: UserId, msg: ClientMsg) -> Outcome {
        match msg {
            ClientMsg::Hello { .. } => Err("already said hello".into()),
            ClientMsg::Join { channel, password } => self.join(id, channel, password),
            ClientMsg::Chat { to, text } => self.chat(id, to, text),
            ClientMsg::Poke { user, text } => {
                self.user(user)?;
                let text = limit(&text, MAX_SHORT, "pokes")?;
                self.send(user, ServerMsg::Poke { from: id, text });
                Ok(())
            }
            ClientMsg::Rename { name } => {
                let name = name.trim();
                if name.is_empty() || name.chars().count() > MAX_NAME {
                    return Err(format!("names need 1 to {MAX_NAME} characters"));
                }
                let name = self.free_name(name, Some(id));
                self.update(id, |u| u.name = name)
            }
            ClientMsg::SetMuted { input, output } => {
                self.update(id, |u| (u.input_muted, u.output_muted) = (input, output))
            }
            ClientMsg::SetAway(away) => {
                let away = away.map(|a| limit(&a, MAX_SHORT, "away messages")).transpose()?;
                self.update(id, |u| u.away = away)
            }
            ClientMsg::SetDescription(d) => {
                let d = limit(&d, MAX_SHORT, "descriptions")?;
                self.update(id, |u| u.description = d)
            }
            ClientMsg::RequestTalk(request) => {
                let request = request.map(|r| limit(&r, MAX_SHORT, "requests")).transpose()?;
                self.update(id, |u| u.talk_request = request)
            }
            ClientMsg::SetWhisper(whisper) => {
                if whisper.as_ref().is_some_and(|w| w.channels.len() + w.users.len() > MAX_WHISPER) {
                    return Err(format!("whisper to at most {MAX_WHISPER} channels and people"));
                }
                if let Some(p) = self.users.get_mut(&id) {
                    p.whisper = whisper;
                }
                Ok(())
            }
            ClientMsg::CreateChannel(new) => self.create_channel(id, new),
            ClientMsg::EditChannel { id: channel, edit } => self.edit_channel(id, channel, edit),
            ClientMsg::MoveChannel { id: channel, parent, after } => self.move_channel(id, channel, parent, after),
            ClientMsg::DeleteChannel { id: channel } => self.delete_channel(id, channel),
            ClientMsg::MoveUser { user, channel } => {
                self.may(id, Perm::MoveUsers)?;
                self.over(id, user)?;
                self.chan(channel).ok_or("no such channel")?;
                self.put(user, channel);
                Ok(())
            }
            ClientMsg::Kick { user, reason, server } => {
                self.may(id, Perm::Kick)?;
                self.over(id, user)?;
                self.user(user)?;
                let reason = limit(&reason, MAX_SHORT, "reasons")?;
                if server {
                    self.remove(user, Leave::Kicked { by: id, reason });
                } else {
                    let text = match reason.is_empty() {
                        true => format!("{} kicked you from the channel", self.name(id)),
                        false => format!("{} kicked you from the channel: {reason}", self.name(id)),
                    };
                    self.put(user, self.default_channel());
                    self.send(user, ServerMsg::Notice { text });
                }
                Ok(())
            }
            ClientMsg::Ban { user, reason, secs } => {
                self.may(id, Perm::Ban)?;
                self.over(id, user)?;
                if id == user {
                    return Err("you can't ban yourself".into());
                }
                let reason = limit(&reason, MAX_SHORT, "reasons")?;
                let target = self.users.get(&user).ok_or("nobody with that id is here")?;
                let (key, ip, name) = (target.user.key, target.ip.clone(), target.user.name.clone());
                self.add_ban(id, Some(key), Some(ip), name, reason.clone(), secs)?;
                self.remove(user, Leave::Banned { by: id, reason });
                Ok(())
            }
            ClientMsg::AddBan { key, ip, reason, secs } => {
                self.may(id, Perm::Ban)?;
                if key.is_none() && ip.as_deref().is_none_or(|i| i.trim().is_empty()) {
                    return Err("a ban needs a key or an address".into());
                }
                if let Some(k) = key
                    && let Some(acc) = stored(self.db.account(&k))?
                    && self.role(acc.role).rank >= self.role_of(id).rank
                {
                    return Err("they rank the same as you or higher".into());
                }
                let reason = limit(&reason, MAX_SHORT, "reasons")?;
                let name = match key {
                    Some(k) => stored(self.db.account_name(&k))?.unwrap_or_default(),
                    None => String::new(),
                };
                let ip = ip.map(|i| i.trim().to_string()).filter(|i| !i.is_empty());
                self.add_ban(id, key, ip.clone(), name, reason, secs)?;
                // anyone here it applies to goes
                let gone: Vec<UserId> = self
                    .users
                    .values()
                    .filter(|p| p.user.id != id && (Some(p.user.key) == key || Some(&p.ip) == ip.as_ref()))
                    .map(|p| p.user.id)
                    .collect();
                for user in gone {
                    self.remove(user, Leave::Banned { by: id, reason: String::new() });
                }
                self.send(id, ServerMsg::Bans(stored(self.db.bans())?));
                Ok(())
            }
            ClientMsg::Unban { id: ban } => {
                self.may(id, Perm::Ban)?;
                stored(self.db.delete_ban(ban))?;
                self.log(format!("{} lifted ban {ban}", self.name(id)));
                self.send(id, ServerMsg::Bans(stored(self.db.bans())?));
                Ok(())
            }
            ClientMsg::ServerMute { user, muted } => {
                self.may(id, Perm::Mute)?;
                self.over(id, user)?;
                self.update(user, |u| u.server_muted = muted)
            }
            ClientMsg::GrantTalk { user, granted } => {
                self.may(id, Perm::Mute)?;
                self.over(id, user)?;
                self.update(user, |u| {
                    u.talk_granted = granted;
                    u.talk_request = None;
                })
            }
            ClientMsg::SetRole { key, role } => self.set_role(id, key, role),
            ClientMsg::SaveRole(role) => self.save_role(id, role),
            ClientMsg::DeleteRole { id: role } => self.delete_role(id, role),
            ClientMsg::EditServer(edit) => self.edit_server(id, edit),
            ClientMsg::CreateToken { role, note } => {
                self.may(id, Perm::ManageRoles)?;
                let rank = self.known_role(role)?.rank;
                if rank > self.role_of(id).rank {
                    return Err("that role ranks higher than yours".into());
                }
                let token =
                    Token { token: db::new_token(), role, note: limit(&note, MAX_SHORT, "notes")?, created: now() };
                stored(self.db.add_token(&token))?;
                self.send(id, ServerMsg::TokenCreated(token));
                Ok(())
            }
            ClientMsg::DeleteToken { token } => {
                self.may(id, Perm::ManageRoles)?;
                stored(self.db.delete_token(&token))?;
                self.send(id, ServerMsg::Tokens(stored(self.db.tokens())?));
                Ok(())
            }
            ClientMsg::Redeem { token } => {
                let role = stored(self.db.take_token(token.trim()))?.ok_or("that token doesn't work")?;
                let key = self.user(id)?.key;
                self.give_role(key, role)?;
                let role = self.role(role).name.clone();
                self.log(format!("{} redeemed a token for {role}", self.name(id)));
                self.send(id, ServerMsg::Notice { text: format!("You're {role} now") });
                Ok(())
            }
            ClientMsg::ListBans => {
                self.may(id, Perm::Ban)?;
                self.send(id, ServerMsg::Bans(stored(self.db.bans())?));
                Ok(())
            }
            ClientMsg::ListAccounts => {
                self.may(id, Perm::ManageRoles)?;
                self.send(id, ServerMsg::Accounts(stored(self.db.accounts())?));
                Ok(())
            }
            ClientMsg::ListTokens => {
                self.may(id, Perm::ManageRoles)?;
                self.send(id, ServerMsg::Tokens(stored(self.db.tokens())?));
                Ok(())
            }
            ClientMsg::ListFiles { channel, password, path } => {
                let root = self.file_root(id, channel, password.as_deref(), None)?;
                let entries = files::list(&root, &path)?;
                self.send(id, ServerMsg::Files { channel, path, entries });
                Ok(())
            }
            ClientMsg::MakeDir { channel, password, path } => {
                let root = self.file_root(id, channel, password.as_deref(), Some(Perm::UploadFiles))?;
                files::make_dir(&root, &path)?;
                self.file_listing(id, channel, &root, files::parent(&path))
            }
            ClientMsg::DeleteFile { channel, password, path } => {
                let root = self.file_root(id, channel, password.as_deref(), Some(Perm::ManageFiles))?;
                files::delete(&root, &path)?;
                self.log(format!("{} deleted {path} in channel {channel}", self.name(id)));
                self.file_listing(id, channel, &root, files::parent(&path))
            }
            ClientMsg::RenameFile { channel, password, from, to } => {
                let root = self.file_root(id, channel, password.as_deref(), Some(Perm::ManageFiles))?;
                files::rename(&root, &from, &to)?;
                self.file_listing(id, channel, &root, files::parent(&to))
            }
            ClientMsg::ClearAvatar => self.set_avatar(id, None),
            ClientMsg::SendOffline { to, subject, text } => {
                let subject = limit(&subject, MAX_SHORT, "subjects")?;
                let text = limit(&text, MAX_CHAT, "messages")?;
                if text.is_empty() && subject.is_empty() {
                    return Err("the message is empty".into());
                }
                stored(self.db.account_name(&to))?.ok_or("nobody with that key has been here")?;
                let me = self.user(id)?;
                stored(self.db.send_offline(&to, &me.key, &me.name, &subject, &text))?;
                // tell them now if they're here
                for p in self.users.values().filter(|p| p.user.key == to) {
                    let _ = p.tx.send(ServerMsg::Notice { text: format!("New offline message from {}", me.name) });
                }
                Ok(())
            }
            ClientMsg::ListInbox => self.send_inbox(id),
            ClientMsg::MarkRead { id: message, read } => {
                stored(self.db.mark_read(&self.user(id)?.key, message, read))?;
                self.send_inbox(id)
            }
            ClientMsg::DeleteOffline { id: message } => {
                stored(self.db.delete_offline(&self.user(id)?.key, message))?;
                self.send_inbox(id)
            }
            ClientMsg::ReadLog { lines } => {
                self.may(id, Perm::ManageServer)?;
                self.send(id, ServerMsg::Log(stored(self.db.read_log(lines.min(10_000)))?));
                Ok(())
            }
        }
    }

    fn send_inbox(&self, id: UserId) -> Outcome {
        self.send(id, ServerMsg::Inbox(stored(self.db.inbox(&self.user(id)?.key))?));
        Ok(())
    }

    /// The folder of a channel's files, if `id` may get in there (and has
    /// `need`, for changes).
    pub fn file_root(
        &self,
        id: UserId,
        channel: ChannelId,
        password: Option<&str>,
        need: Option<Perm>,
    ) -> Result<PathBuf, String> {
        let c = &self.chan(channel).ok_or("no such channel")?.c;
        if let Some(perm) = need {
            self.may(id, perm)?;
        }
        let inside = self.user(id)?.channel == channel;
        if let Some(hash) = &c.password
            && !inside
            && !self.role_of(id).can(Perm::JoinAny)
            && !password.is_some_and(|p| check_password(hash, p))
        {
            return Err("that channel's files need its password".into());
        }
        Ok(files::channel_dir(&self.data_dir, channel))
    }

    fn file_listing(&self, id: UserId, channel: ChannelId, root: &std::path::Path, path: &str) -> Outcome {
        let entries = files::list(root, path)?;
        self.send(id, ServerMsg::Files { channel, path: path.to_string(), entries });
        Ok(())
    }

    /// A new picture (its hash), or none.
    pub fn set_avatar(&mut self, id: UserId, hash: Option<String>) -> Outcome {
        let key = self.user(id)?.key;
        stored(self.db.set_avatar(&key, hash.as_deref()))?;
        if hash.is_none() {
            let _ = std::fs::remove_file(files::avatar_path(&self.data_dir, &key));
        }
        self.update(id, |u| u.avatar = hash)
    }

    /// Who has this key's picture, for a download.
    pub fn avatar_of(&self, key: &Key) -> Option<PathBuf> {
        let path = files::avatar_path(&self.data_dir, key);
        path.exists().then_some(path)
    }

    fn update(&mut self, id: UserId, f: impl FnOnce(&mut User)) -> Outcome {
        let p = self.users.get_mut(&id).ok_or("nobody with that id is here")?;
        let before = p.user.clone();
        f(&mut p.user);
        if p.user != before {
            self.changed(id);
        }
        Ok(())
    }

    /// Move someone, no questions asked.
    fn put(&mut self, id: UserId, channel: ChannelId) {
        let Some(p) = self.users.get_mut(&id) else { return };
        if p.user.channel == channel {
            return;
        }
        p.user.channel = channel;
        self.changed(id);
        self.drop_empty_channels();
    }

    fn join(&mut self, id: UserId, channel: ChannelId, password: Option<String>) -> Outcome {
        let c = &self.chan(channel).ok_or("no such channel")?.c;
        let any = self.role_of(id).can(Perm::JoinAny);
        if let Some(stored) = &c.password
            && !any
            && !password.as_deref().is_some_and(|p| check_password(stored, p))
        {
            self.send(id, ServerMsg::NeedPassword { channel, wrong: password.is_some() });
            return Ok(());
        }
        let inside = self.users.values().filter(|p| p.user.channel == channel && p.user.id != id).count();
        if c.max_users.is_some_and(|m| inside >= m as usize) && !any {
            return Err("that channel is full".into());
        }
        self.put(id, channel);
        Ok(())
    }

    fn chat(&self, id: UserId, to: ChatTarget, text: String) -> Outcome {
        let text = text.trim();
        if text.is_empty() || text.chars().count() > MAX_CHAT {
            return Err(format!("messages need 1 to {MAX_CHAT} characters"));
        }
        let msg = ServerMsg::Chat { from: id, to, text: text.to_string() };
        match to {
            ChatTarget::Channel => {
                let channel = self.user(id)?.channel;
                self.broadcast(|p| p.user.channel == channel, &msg);
            }
            ChatTarget::Server => self.broadcast(|_| true, &msg),
            ChatTarget::User(other) => {
                self.user(other)?;
                self.send(other, msg.clone());
                if other != id {
                    self.send(id, msg);
                }
            }
        }
        Ok(())
    }

    fn create_channel(&mut self, id: UserId, new: NewChannel) -> Outcome {
        match new.permanent {
            true => self.may(id, Perm::ManageChannels)?,
            false => {
                if self.may(id, Perm::ManageChannels).is_err() {
                    self.may(id, Perm::CreateTempChannels)?
                }
            }
        }
        if let Some(parent) = new.parent {
            self.chan(parent).ok_or("no such parent channel")?;
        }
        let name = self.channel_name(&new.name, new.parent, None)?;
        let channel = self.next_channel;
        self.next_channel += 1;
        self.channels.push(Chan {
            c: StoredChannel {
                id: channel,
                parent: new.parent,
                name,
                topic: limit(&new.topic, MAX_TOPIC, "topics")?,
                description: limit(&new.description, MAX_DESCRIPTION, "descriptions")?,
                password: new.password.filter(|p| !p.is_empty()).map(|p| hash_password(&p)),
                max_users: new.max_users,
                talk_power: new.talk_power,
                default: false,
            },
            permanent: new.permanent,
        });
        self.save_channels();
        self.log(format!("{} created the channel {}", self.name(id), new.name.trim()));
        self.channels_changed();
        // whoever makes a temporary channel goes in, or it'd vanish right away
        if !new.permanent {
            self.put(id, channel);
        }
        Ok(())
    }

    /// A trimmed name no sibling has.
    fn channel_name(&self, name: &str, parent: Option<ChannelId>, except: Option<ChannelId>) -> Result<String, String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_CHANNEL_NAME {
            return Err(format!("channel names need 1 to {MAX_CHANNEL_NAME} characters"));
        }
        let clash = self
            .channels
            .iter()
            .any(|c| c.c.parent == parent && Some(c.c.id) != except && c.c.name.eq_ignore_ascii_case(name));
        if clash {
            return Err("a channel with that name is already there".into());
        }
        Ok(name.to_string())
    }

    fn edit_channel(&mut self, id: UserId, channel: ChannelId, e: ChannelEdit) -> Outcome {
        self.may(id, Perm::ManageChannels)?;
        let c = &self.chan(channel).ok_or("no such channel")?.c;
        let name = e.name.as_deref().map(|n| self.channel_name(n, c.parent, Some(channel))).transpose()?;
        let topic = e.topic.map(|t| limit(&t, MAX_TOPIC, "topics")).transpose()?;
        let description = e.description.map(|d| limit(&d, MAX_DESCRIPTION, "descriptions")).transpose()?;
        if e.permanent == Some(false) && c.default {
            return Err("the default channel has to stay".into());
        }
        if e.default == Some(true) {
            for c in &mut self.channels {
                c.c.default = c.c.id == channel;
            }
        }
        let chan = self.channels.iter_mut().find(|c| c.c.id == channel).expect("checked above");
        let c = &mut chan.c;
        if let Some(n) = name {
            c.name = n;
        }
        if let Some(t) = topic {
            c.topic = t;
        }
        if let Some(d) = description {
            c.description = d;
        }
        if let Some(p) = e.password {
            c.password = p.filter(|p| !p.is_empty()).map(|p| hash_password(&p));
        }
        if let Some(m) = e.max_users {
            c.max_users = m;
        }
        if let Some(t) = e.talk_power {
            c.talk_power = t;
        }
        if let Some(p) = e.permanent {
            chan.permanent = p;
        }
        self.save_channels();
        self.channels_changed();
        self.drop_empty_channels();
        Ok(())
    }

    fn move_channel(
        &mut self,
        id: UserId,
        channel: ChannelId,
        parent: Option<ChannelId>,
        after: Option<ChannelId>,
    ) -> Outcome {
        self.may(id, Perm::ManageChannels)?;
        let name = self.chan(channel).ok_or("no such channel")?.c.name.clone();
        if let Some(p) = parent {
            self.chan(p).ok_or("no such parent channel")?;
            if self.within(p, channel) {
                return Err("a channel can't go inside itself".into());
            }
        }
        if after.is_some_and(|a| a == channel || self.chan(a).is_none_or(|a| a.c.parent != parent)) {
            return Err("that channel isn't under the new parent".into());
        }
        self.channel_name(&name, parent, Some(channel))?;
        let pos = self.channels.iter().position(|c| c.c.id == channel).expect("checked above");
        let mut moving = self.channels.remove(pos);
        moving.c.parent = parent;
        let at = match after {
            Some(a) => self.channels.iter().position(|c| c.c.id == a).map(|i| i + 1),
            None => self.channels.iter().position(|c| c.c.parent == parent),
        };
        self.channels.insert(at.unwrap_or(self.channels.len()), moving);
        self.save_channels();
        self.channels_changed();
        Ok(())
    }

    /// `id` is `ancestor` or somewhere below it.
    fn within(&self, mut id: ChannelId, ancestor: ChannelId) -> bool {
        loop {
            if id == ancestor {
                return true;
            }
            match self.chan(id).and_then(|c| c.c.parent) {
                Some(p) => id = p,
                None => return false,
            }
        }
    }

    fn delete_channel(&mut self, id: UserId, channel: ChannelId) -> Outcome {
        self.may(id, Perm::ManageChannels)?;
        self.chan(channel).ok_or("no such channel")?;
        let default = self.default_channel();
        if self.within(default, channel) {
            return Err("the default channel can't go (make another one the default first)".into());
        }
        let name = self.chan(channel).map(|c| c.c.name.clone()).unwrap_or_default();
        self.log(format!("{} deleted the channel {name}", self.name(id)));
        self.remove_channels(|s, c| s.within(c, channel));
        Ok(())
    }

    /// Drop channels (and send their people to the default one).
    fn remove_channels(&mut self, gone: impl Fn(&Self, ChannelId) -> bool) {
        let ids: Vec<ChannelId> = self.channels.iter().map(|c| c.c.id).filter(|c| gone(self, *c)).collect();
        if ids.is_empty() {
            return;
        }
        let default = self.default_channel();
        let movers: Vec<UserId> =
            self.users.values().filter(|p| ids.contains(&p.user.channel)).map(|p| p.user.id).collect();
        self.channels.retain(|c| !ids.contains(&c.c.id));
        for id in &ids {
            let _ = std::fs::remove_dir_all(files::channel_dir(&self.data_dir, *id));
        }
        self.save_channels();
        self.channels_changed();
        for id in movers {
            if let Some(p) = self.users.get_mut(&id) {
                p.user.channel = default;
            }
            self.changed(id);
        }
    }

    /// Temporary channels with nobody in them (or below them) go.
    fn drop_empty_channels(&mut self) {
        let occupied = |s: &Self, c: ChannelId| s.users.values().any(|p| s.within(p.user.channel, c));
        let empty: Vec<ChannelId> =
            self.channels.iter().filter(|c| !c.permanent && !occupied(self, c.c.id)).map(|c| c.c.id).collect();
        if !empty.is_empty() {
            self.remove_channels(|s, c| empty.iter().any(|e| s.within(c, *e)));
        }
    }

    fn add_ban(
        &mut self,
        by: UserId,
        key: Option<Key>,
        ip: Option<String>,
        name: String,
        reason: String,
        secs: Option<u64>,
    ) -> Outcome {
        let created = now();
        let by = self.name(by);
        let what = if name.is_empty() { ip.clone().unwrap_or_default() } else { name.clone() };
        let until = secs.map(|s| created + s);
        stored(self.db.add_ban(&Ban { id: 0, key, ip, name, reason, by: by.clone(), created, until }))?;
        self.log(format!("{by} banned {what}"));
        Ok(())
    }

    fn set_role(&mut self, id: UserId, key: Key, role: RoleId) -> Outcome {
        self.may(id, Perm::ManageRoles)?;
        let mine = self.role_of(id).rank;
        let new = self.known_role(role)?;
        if new.rank > mine {
            return Err("that role ranks higher than yours".into());
        }
        let new = new.name.clone();
        let acc = stored(self.db.account(&key))?.ok_or("nobody with that key has been here")?;
        let me = self.user(id)?.key;
        if key != me && self.role(acc.role).rank >= mine {
            return Err("they rank the same as you or higher".into());
        }
        self.give_role(key, role)?;
        let who = stored(self.db.account_name(&key))?.unwrap_or_default();
        self.log(format!("{} made {who} {new}", self.name(id)));
        Ok(())
    }

    fn give_role(&mut self, key: Key, role: RoleId) -> Outcome {
        stored(self.db.set_role(&key, role))?;
        let online: Vec<UserId> = self.users.values().filter(|p| p.user.key == key).map(|p| p.user.id).collect();
        for id in online {
            self.update(id, |u| u.role = role)?;
        }
        Ok(())
    }

    fn save_role(&mut self, id: UserId, mut role: Role) -> Outcome {
        self.may(id, Perm::ManageRoles)?;
        let mine = self.role_of(id).rank;
        role.name = role.name.trim().to_string();
        if role.name.is_empty() || role.name.chars().count() > MAX_NAME {
            return Err(format!("role names need 1 to {MAX_NAME} characters"));
        }
        if role.rank > mine {
            return Err("roles can't rank higher than yours".into());
        }
        role.perms.sort();
        role.perms.dedup();
        if role.id != 0 && self.known_role(role.id)?.rank > mine {
            return Err("that role ranks higher than yours".into());
        }
        stored(self.db.save_role(&role))?;
        self.roles = stored(self.db.roles())?;
        self.log(format!("{} saved the role {}", self.name(id), role.name));
        self.broadcast(|_| true, &ServerMsg::Roles(self.roles.clone()));
        Ok(())
    }

    fn delete_role(&mut self, id: UserId, role: RoleId) -> Outcome {
        self.may(id, Perm::ManageRoles)?;
        let r = self.known_role(role)?;
        if r.rank >= self.role_of(id).rank {
            return Err("that role ranks the same as yours or higher".into());
        }
        if role == self.settings.default_role {
            return Err("new people get that role; it has to stay".into());
        }
        let name = r.name.clone();
        let fallback = self.settings.default_role;
        stored(self.db.delete_role(role, fallback))?;
        self.roles = stored(self.db.roles())?;
        self.log(format!("{} deleted the role {name}", self.name(id)));
        self.broadcast(|_| true, &ServerMsg::Roles(self.roles.clone()));
        let online: Vec<UserId> = self.users.values().filter(|p| p.user.role == role).map(|p| p.user.id).collect();
        for user in online {
            self.update(user, |u| u.role = fallback)?;
        }
        Ok(())
    }

    fn edit_server(&mut self, id: UserId, e: ServerEdit) -> Outcome {
        self.may(id, Perm::ManageServer)?;
        if let Some(n) = e.name {
            let n = n.trim();
            if n.is_empty() || n.chars().count() > MAX_CHANNEL_NAME {
                return Err(format!("server names need 1 to {MAX_CHANNEL_NAME} characters"));
            }
            self.settings.name = n.to_string();
        }
        if let Some(w) = e.welcome {
            self.settings.welcome = limit(&w, MAX_DESCRIPTION, "welcome messages")?;
        }
        if let Some(m) = e.max_users {
            self.settings.max_users = m;
        }
        if let Some(p) = e.password {
            self.settings.password = p.filter(|p| !p.is_empty()).map(|p| hash_password(&p));
        }
        stored(self.db.save_settings(&self.settings))?;
        self.log(format!("{} changed the server settings", self.name(id)));
        self.broadcast(|_| true, &ServerMsg::Server(self.info()));
        Ok(())
    }

    /// Who hears a voice datagram from `from` (and whether it's a whisper),
    /// or nobody when they may not talk.
    pub fn listeners(&self, from: UserId) -> (Vec<quinn::Connection>, bool) {
        let Some(speaker) = self.users.get(&from) else { return (Vec::new(), false) };
        if speaker.user.server_muted {
            return (Vec::new(), false);
        }
        let hears = |p: &&Peer| p.user.id != from && !p.user.output_muted;
        if let Some(w) = &speaker.whisper {
            let to = self
                .users
                .values()
                .filter(hears)
                .filter(|p| w.users.contains(&p.user.id) || w.channels.contains(&p.user.channel))
                .map(|p| p.conn.clone())
                .collect();
            return (to, true);
        }
        let channel = speaker.user.channel;
        let needed = self.chan(channel).map(|c| c.c.talk_power).unwrap_or(0);
        if !speaker.user.talk_granted && self.role(speaker.user.role).talk_power < needed {
            return (Vec::new(), false);
        }
        let to =
            self.users.values().filter(hears).filter(|p| p.user.channel == channel).map(|p| p.conn.clone()).collect();
        (to, false)
    }
}

/// A database result for a client: failures are logged, and the client
/// only hears that it didn't work.
pub fn stored<T>(r: anyhow::Result<T>) -> Result<T, String> {
    r.map_err(|e| {
        warn!("database: {e:#}");
        "the server couldn't do that (storage problem)".to_string()
    })
}

/// `text` trimmed, if it isn't longer than `max` characters.
fn limit(text: &str, max: usize, what: &str) -> Result<String, String> {
    let text = text.trim();
    match text.chars().count() <= max {
        true => Ok(text.to_string()),
        false => Err(format!("{what} can be {max} characters at most")),
    }
}
