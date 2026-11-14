//! The Banshee wire protocol.
//!
//! A client opens one QUIC connection. The first bidirectional stream carries
//! control messages ([`ClientMsg`] up, [`ServerMsg`] down), each framed as a
//! little-endian `u32` length followed by the postcard encoding. Voice goes
//! as unreliable QUIC datagrams (see [`voice`]).

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bumped on incompatible changes; the server refuses other versions.
pub const PROTOCOL_VERSION: u32 = 1;

/// The ALPN both sides agree on.
pub const ALPN: &[u8] = b"banshee/1";

/// Control messages are small; anything bigger is a broken or hostile peer.
pub const MAX_FRAME: u32 = 64 * 1024;

pub type UserId = u32;
pub type ChannelId = u32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub name: String,
    pub channel: ChannelId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// First message on the control stream.
    Hello {
        protocol: u32,
        name: String,
    },
    Join {
        channel: ChannelId,
    },
    /// Text to everyone in our channel.
    Chat {
        text: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMsg {
    /// Answer to `Hello`: who we are and what the server looks like.
    Welcome {
        you: UserId,
        channels: Vec<Channel>,
        users: Vec<User>,
    },
    UserJoined(User),
    UserLeft {
        id: UserId,
    },
    UserMoved {
        id: UserId,
        channel: ChannelId,
    },
    Chat {
        from: UserId,
        channel: ChannelId,
        text: String,
    },
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

/// Voice datagrams. Up: `seq (u16 LE) | opus`. Down: the server puts the
/// speaker in front: `from (u32 LE) | seq (u16 LE) | opus`. The sequence
/// number lets the receiver spot loss and reordering.
pub mod voice {
    use super::UserId;

    pub fn encode_up(seq: u16, opus: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + opus.len());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(opus);
        out
    }

    /// The datagram the server relays: the client's bytes behind the speaker id.
    pub fn relay(from: UserId, up: &[u8]) -> Option<Vec<u8>> {
        if up.len() < 2 {
            return None;
        }
        let mut out = Vec::with_capacity(4 + up.len());
        out.extend_from_slice(&from.to_le_bytes());
        out.extend_from_slice(up);
        Some(out)
    }

    pub struct Down<'a> {
        pub from: UserId,
        pub seq: u16,
        pub opus: &'a [u8],
    }

    pub fn decode_down(data: &[u8]) -> Option<Down<'_>> {
        let from = UserId::from_le_bytes(data.get(..4)?.try_into().ok()?);
        let seq = u16::from_le_bytes(data.get(4..6)?.try_into().ok()?);
        Some(Down { from, seq, opus: &data[6..] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = ClientMsg::Hello { protocol: PROTOCOL_VERSION, name: "Rook".into() };
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
        let down = voice::relay(42, &up).unwrap();
        let d = voice::decode_down(&down).unwrap();
        assert_eq!((d.from, d.seq, d.opus), (42, 7, &b"opus"[..]));
        assert!(voice::relay(1, &[0]).is_none());
    }
}
