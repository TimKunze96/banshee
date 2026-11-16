//! The Banshee wire protocol.
//!
//! A client opens one QUIC connection. The first bidirectional stream carries
//! control messages ([`ClientMsg`] up, [`ServerMsg`] down), each framed as a
//! little-endian `u32` length followed by the postcard encoding. Voice goes
//! as unreliable QUIC datagrams (see [`voice`]), screen sharing on
//! unidirectional streams (see [`video`]).
//!
//! People are known by an Ed25519 key. `Hello` carries the public key and a
//! signature over TLS keying material of this connection (see
//! [`IDENTITY_LABEL`]), so it can't be replayed on another one.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bumped on incompatible changes; the server refuses other versions.
pub const PROTOCOL_VERSION: u32 = 4;

/// The ALPN both sides agree on.
pub const ALPN: &[u8] = b"banshee/1";

/// Label for the TLS exporter whose output `Hello` signs (32 bytes, empty context).
pub const IDENTITY_LABEL: &[u8] = b"banshee identity";

/// Control messages are small; anything bigger is a broken or hostile peer.
pub const MAX_FRAME: u32 = 64 * 1024;

pub type UserId = u32;
pub type ChannelId = u32;
pub type RoleId = u32;
/// An Ed25519 public key.
pub type Key = [u8; 32];

/// A key as lowercase hex, the way people and files see it.
pub fn key_hex(key: &Key) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_key(hex: &str) -> Option<Key> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(key)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    /// Shown to everyone who connects.
    pub welcome: String,
    pub max_users: Option<u32>,
    pub has_password: bool,
    /// The role new people get.
    pub default_role: RoleId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    /// None: top level.
    pub parent: Option<ChannelId>,
    pub name: String,
    pub topic: String,
    pub description: String,
    pub has_password: bool,
    pub max_users: Option<u32>,
    /// Talk power needed to be heard here (0: everyone).
    pub talk_power: u32,
    /// Temporary channels go away once the last person leaves.
    pub permanent: bool,
    /// Where people land when they connect.
    pub default: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub key: Key,
    pub name: String,
    pub channel: ChannelId,
    pub role: RoleId,
    pub input_muted: bool,
    pub output_muted: bool,
    /// Some(message): away (the message may be empty).
    pub away: Option<String>,
    pub description: String,
    /// Silenced by a moderator.
    pub server_muted: bool,
    /// May talk in any channel, whatever its talk power.
    pub talk_granted: bool,
    /// Asking for talk power, with a message.
    pub talk_request: Option<String>,
    /// Hash of their picture (fetch it with [`transfer::Request::Avatar`]).
    pub avatar: Option<String>,
    /// Sharing their screen (watch it with [`ClientMsg::Watch`]).
    pub streaming: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Perm {
    /// Server name, welcome message, password, user limit.
    ManageServer,
    /// Create and edit roles, give people roles, make tokens.
    ManageRoles,
    /// Create, edit, move and delete any channel.
    ManageChannels,
    /// Create temporary channels.
    CreateTempChannels,
    /// Join channels that are full or have a password.
    JoinAny,
    MoveUsers,
    Kick,
    Ban,
    /// Mute people server-wide and grant talk power.
    Mute,
    /// Upload files and make folders in channels they can get into.
    UploadFiles,
    /// Delete and rename files.
    ManageFiles,
}

impl Perm {
    pub const ALL: [Perm; 11] = [
        Perm::ManageServer,
        Perm::ManageRoles,
        Perm::ManageChannels,
        Perm::CreateTempChannels,
        Perm::JoinAny,
        Perm::MoveUsers,
        Perm::Kick,
        Perm::Ban,
        Perm::Mute,
        Perm::UploadFiles,
        Perm::ManageFiles,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    /// Higher ranks can act on lower ones, never the other way round.
    pub rank: u8,
    pub perms: Vec<Perm>,
    pub talk_power: u32,
}

impl Role {
    pub fn can(&self, perm: Perm) -> bool {
        self.perms.contains(&perm)
    }
}

/// Someone who has been on the server, online or not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub key: Key,
    pub name: String,
    pub role: RoleId,
    /// Unix seconds.
    pub last_seen: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ban {
    pub id: u32,
    pub key: Option<Key>,
    pub ip: Option<String>,
    /// The name they had.
    pub name: String,
    pub reason: String,
    pub by: String,
    /// Unix seconds.
    pub created: u64,
    /// Unix seconds; None: for good.
    pub until: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    /// Unix seconds.
    pub modified: u64,
    pub is_dir: bool,
}

/// A message left for someone who wasn't there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineMessage {
    pub id: u32,
    pub from: Key,
    pub from_name: String,
    pub subject: String,
    pub text: String,
    /// Unix seconds.
    pub sent: u64,
    pub read: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// Unix seconds.
    pub time: u64,
    pub text: String,
}

/// A one-time code that gives whoever redeems it a role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub token: String,
    pub role: RoleId,
    pub note: String,
    pub created: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatTarget {
    /// Everyone in the sender's channel.
    Channel,
    /// Everyone on the server.
    Server,
    /// One person (both sides get the message).
    User(UserId),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewChannel {
    pub parent: Option<ChannelId>,
    pub name: String,
    pub topic: String,
    pub description: String,
    pub password: Option<String>,
    pub max_users: Option<u32>,
    pub talk_power: u32,
    pub permanent: bool,
}

/// Changes to a channel; None leaves a field as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEdit {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub description: Option<String>,
    /// Some(None) removes the password.
    pub password: Option<Option<String>>,
    pub max_users: Option<Option<u32>>,
    pub talk_power: Option<u32>,
    pub permanent: Option<bool>,
    /// Only `Some(true)` does something: the default moves here.
    pub default: Option<bool>,
}

/// Changes to the server; None leaves a field as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEdit {
    pub name: Option<String>,
    pub welcome: Option<String>,
    pub max_users: Option<Option<u32>>,
    /// Some(None) removes the password.
    pub password: Option<Option<String>>,
}

/// Who the voice goes to while whispering.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Whisper {
    pub channels: Vec<ChannelId>,
    pub users: Vec<UserId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// First message on the control stream.
    Hello {
        protocol: u32,
        name: String,
        key: Key,
        /// Ed25519 over the TLS exporter output for [`IDENTITY_LABEL`].
        signature: Vec<u8>,
        password: Option<String>,
    },
    Join {
        channel: ChannelId,
        password: Option<String>,
    },
    Chat {
        to: ChatTarget,
        text: String,
    },
    Poke {
        user: UserId,
        text: String,
    },
    Rename {
        name: String,
    },
    SetMuted {
        input: bool,
        output: bool,
    },
    SetAway(Option<String>),
    SetDescription(String),
    /// Some(message) asks for talk power; None takes the request back.
    RequestTalk(Option<String>),
    /// Voice goes here instead of our channel until set back to None.
    SetWhisper(Option<Whisper>),

    CreateChannel(NewChannel),
    EditChannel {
        id: ChannelId,
        edit: ChannelEdit,
    },
    /// Put a channel under `parent`, right after `after` (None: first).
    MoveChannel {
        id: ChannelId,
        parent: Option<ChannelId>,
        after: Option<ChannelId>,
    },
    DeleteChannel {
        id: ChannelId,
    },

    MoveUser {
        user: UserId,
        channel: ChannelId,
    },
    /// Out of their channel into the default one, or off the server.
    Kick {
        user: UserId,
        reason: String,
        server: bool,
    },
    Ban {
        user: UserId,
        reason: String,
        /// None: for good.
        secs: Option<u64>,
    },
    /// A ban for someone who isn't here, by key and/or IP.
    AddBan {
        key: Option<Key>,
        ip: Option<String>,
        reason: String,
        secs: Option<u64>,
    },
    Unban {
        id: u32,
    },
    ServerMute {
        user: UserId,
        muted: bool,
    },
    GrantTalk {
        user: UserId,
        granted: bool,
    },
    /// Give an account (online or not) a role.
    SetRole {
        key: Key,
        role: RoleId,
    },
    /// Create (id 0) or change a role.
    SaveRole(Role),
    DeleteRole {
        id: RoleId,
    },
    EditServer(ServerEdit),
    CreateToken {
        role: RoleId,
        note: String,
    },
    DeleteToken {
        token: String,
    },
    Redeem {
        token: String,
    },
    ListBans,
    ListAccounts,
    ListTokens,

    /// Files in a channel folder ("" or "/" for the top); answered with `Files`.
    ListFiles {
        channel: ChannelId,
        password: Option<String>,
        path: String,
    },
    MakeDir {
        channel: ChannelId,
        password: Option<String>,
        path: String,
    },
    DeleteFile {
        channel: ChannelId,
        password: Option<String>,
        path: String,
    },
    RenameFile {
        channel: ChannelId,
        password: Option<String>,
        from: String,
        to: String,
    },
    ClearAvatar,

    /// Leave a message for someone (online or not), by key.
    SendOffline {
        to: Key,
        subject: String,
        text: String,
    },
    ListInbox,
    MarkRead {
        id: u32,
        read: bool,
    },
    DeleteOffline {
        id: u32,
    },
    /// The last lines of the server log.
    ReadLog {
        lines: u32,
    },

    /// Watch someone's screen in our channel. Their frames come on a stream
    /// the server opens (see [`video`]).
    Watch {
        user: UserId,
    },
    Unwatch {
        user: UserId,
    },
    /// Our picture of their stream broke; ask them for a keyframe.
    WantKeyframe {
        user: UserId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Leave {
    Quit,
    /// The connection timed out or broke.
    Lost,
    Kicked {
        by: UserId,
        reason: String,
    },
    Banned {
        by: UserId,
        reason: String,
    },
    /// The same identity connected again (after a network change, say).
    Replaced,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMsg {
    /// Answer to `Hello`: who we are and what the server looks like.
    Welcome {
        you: UserId,
        server: ServerInfo,
        channels: Vec<Channel>,
        users: Vec<User>,
        roles: Vec<Role>,
    },
    /// Every channel, in display order (parents before children, siblings in order).
    Channels(Vec<Channel>),
    UserJoined(User),
    /// Anything about a user changed (channel, state, role...).
    UserChanged(User),
    UserLeft {
        id: UserId,
        reason: Leave,
    },
    Chat {
        from: UserId,
        to: ChatTarget,
        text: String,
    },
    Poke {
        from: UserId,
        text: String,
    },
    Roles(Vec<Role>),
    Server(ServerInfo),
    Bans(Vec<Ban>),
    Accounts(Vec<Account>),
    Tokens(Vec<Token>),
    /// A token just made.
    TokenCreated(Token),
    /// A join was refused because of the channel's password.
    NeedPassword {
        channel: ChannelId,
        wrong: bool,
    },
    /// Something for us to read (kicked from a channel, token redeemed...).
    Notice {
        text: String,
    },
    Files {
        channel: ChannelId,
        path: String,
        entries: Vec<FileEntry>,
    },
    Inbox(Vec<OfflineMessage>),
    Log(Vec<LogLine>),
    /// Someone started watching our screen or lost the picture: send a keyframe next.
    SendKeyframe,
    /// A request was refused. The connection stays up unless it was `Hello`.
    Error {
        message: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("connection closed")]
    Closed,
    #[error("frame of {0} bytes is too big")]
    TooBig(u32),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("bad message: {0}")]
    Decode(#[from] postcard::Error),
}

pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = postcard::to_stdvec(msg)?;
    let len = u32::try_from(body.len()).ok().filter(|l| *l <= MAX_FRAME).ok_or(FrameError::TooBig(u32::MAX))?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

/// The next message, or `FrameError::Closed` when the stream ended cleanly
/// between messages.
pub async fn read_msg<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len);
    if len > MAX_FRAME {
        return Err(FrameError::TooBig(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(postcard::from_bytes(&body)?)
}

/// File transfers. Each one gets its own bidirectional stream: the client
/// sends a [`transfer::Request`] (framed like control messages), the server
/// answers with a [`transfer::Reply`]. A download's bytes follow `Ready`; an
/// upload's bytes follow the client's request once `Ready` came, the client
/// finishes the stream, and the server answers `Done` once the file is kept.
pub mod transfer {
    use super::{ChannelId, Key};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum Request {
        Download {
            channel: ChannelId,
            password: Option<String>,
            path: String,
        },
        Upload {
            channel: ChannelId,
            password: Option<String>,
            path: String,
            size: u64,
        },
        /// Someone's picture.
        Avatar {
            key: Key,
        },
        /// Our picture (PNG or JPEG).
        SetAvatar {
            size: u64,
        },
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum Reply {
        Ready { size: u64 },
        Done,
        Refused { message: String },
    }

    /// Biggest avatar the server takes.
    pub const MAX_AVATAR: u64 = 512 * 1024;
}

/// Voice datagrams. Up: `seq (u16 LE) | opus`. Down: the server puts the
/// speaker and a flags byte in front: `from (u32 LE) | seq (u16 LE) | flags | opus`.
/// The sequence number lets the receiver spot loss and reordering.
pub mod voice {
    use super::UserId;

    /// The speaker is whispering to us rather than talking in the channel.
    pub const WHISPER: u8 = 1;

    pub fn encode_up(seq: u16, opus: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + opus.len());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(opus);
        out
    }

    /// The datagram the server relays: the client's bytes behind the speaker id.
    pub fn relay(from: UserId, flags: u8, up: &[u8]) -> Option<Vec<u8>> {
        if up.len() < 2 {
            return None;
        }
        let mut out = Vec::with_capacity(5 + up.len());
        out.extend_from_slice(&from.to_le_bytes());
        out.extend_from_slice(&up[..2]);
        out.push(flags);
        out.extend_from_slice(&up[2..]);
        Some(out)
    }

    pub struct Down<'a> {
        pub from: UserId,
        pub seq: u16,
        pub whisper: bool,
        pub opus: &'a [u8],
    }

    pub fn decode_down(data: &[u8]) -> Option<Down<'_>> {
        let from = UserId::from_le_bytes(data.get(..4)?.try_into().ok()?);
        let seq = u16::from_le_bytes(data.get(4..6)?.try_into().ok()?);
        let flags = *data.get(6)?;
        Some(Down { from, seq, whisper: flags & WHISPER != 0, opus: &data[7..] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = ClientMsg::Chat { to: ChatTarget::User(3), text: "hi".into() };
        write_msg(&mut a, &msg).await.unwrap();
        drop(a);
        assert_eq!(read_msg::<_, ClientMsg>(&mut b).await.unwrap(), msg);
        assert!(matches!(read_msg::<_, ClientMsg>(&mut b).await, Err(FrameError::Closed)));
    }

    #[tokio::test]
    async fn refuses_huge_frames() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_FRAME + 1).to_le_bytes()).await.unwrap();
        assert!(matches!(read_msg::<_, ClientMsg>(&mut b).await, Err(FrameError::TooBig(_))));
    }

    #[test]
    fn voice_relay() {
        let up = voice::encode_up(7, b"opus");
        let down = voice::relay(42, voice::WHISPER, &up).unwrap();
        let d = voice::decode_down(&down).unwrap();
        assert_eq!((d.from, d.seq, d.whisper, d.opus), (42, 7, true, &b"opus"[..]));
        assert!(voice::relay(1, 0, &[0]).is_none());
    }

    #[test]
    fn keys_as_hex() {
        let key = [0xab; 32];
        assert_eq!(parse_key(&key_hex(&key)), Some(key));
        assert_eq!(parse_key("abc"), None);
    }
}

/// Screen sharing. A client shares its screen by opening a unidirectional
/// stream and writing [`KIND`] followed by frames; finishing the stream stops
/// sharing. For each watcher the server opens a unidirectional stream with
/// [`KIND`], the sharer's id (u32 LE), then the same frames. A frame is
/// `len (u32 LE) | flags | H.264 Annex B data`. Watchers start at a keyframe,
/// and the server skips frames for watchers that fall behind until the next one.
pub mod video {
    use super::{FrameError, UserId};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// First byte of a video stream.
    pub const KIND: u8 = 1;
    /// The frame can be decoded on its own.
    pub const KEYFRAME: u8 = 1;
    /// Biggest frame either side takes.
    pub const MAX_FRAME: u32 = 8 * 1024 * 1024;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Frame {
        pub keyframe: bool,
        pub data: Vec<u8>,
    }

    /// A frame as it goes on the wire.
    pub fn encode(keyframe: bool, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + data.len());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.push(if keyframe { KEYFRAME } else { 0 });
        out.extend_from_slice(data);
        out
    }

    pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, keyframe: bool, data: &[u8]) -> Result<(), FrameError> {
        if data.len() > MAX_FRAME as usize {
            return Err(FrameError::TooBig(data.len() as u32));
        }
        w.write_all(&encode(keyframe, data)).await?;
        Ok(())
    }

    /// The next frame; None when the stream ended between frames.
    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>, FrameError> {
        let mut head = [0u8; 5];
        match r.read_exact(&mut head[..1]).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        r.read_exact(&mut head[1..]).await?;
        let len = u32::from_le_bytes(head[..4].try_into().unwrap());
        if len > MAX_FRAME {
            return Err(FrameError::TooBig(len));
        }
        let mut data = vec![0u8; len as usize];
        r.read_exact(&mut data).await?;
        Ok(Some(Frame { keyframe: head[4] & KEYFRAME != 0, data }))
    }

    /// Start of the stream the server opens to a watcher.
    pub fn watcher_header(from: UserId) -> [u8; 5] {
        let mut out = [KIND, 0, 0, 0, 0];
        out[1..].copy_from_slice(&from.to_le_bytes());
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn frames() {
            let mut buf = Vec::new();
            write(&mut buf, true, b"key").await.unwrap();
            write(&mut buf, false, b"").await.unwrap();
            let mut r = &buf[..];
            assert_eq!(read(&mut r).await.unwrap(), Some(Frame { keyframe: true, data: b"key".to_vec() }));
            assert_eq!(read(&mut r).await.unwrap(), Some(Frame { keyframe: false, data: vec![] }));
            assert_eq!(read(&mut r).await.unwrap(), None);
        }
    }
}
