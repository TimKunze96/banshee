//! A Banshee client: connect, then send control messages and voice and read
//! what the server sends back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
pub use banshee_proto::transfer::{MAX_AVATAR, Reply, Request};
pub use banshee_proto::video::{AUDIO, MAX_LAYERS, Packet};
use banshee_proto::{ALPN, IDENTITY_LABEL, PROTOCOL_VERSION, read_msg, voice, write_msg};
pub use banshee_proto::{
    Account, Ban, Channel, ChannelEdit, ChannelId, ChatTarget, ClientMsg, FileEntry, Key, Layer, Leave, LogLine,
    NewChannel, OfflineMessage, Perm, Quality, Role, RoleId, ServerEdit, ServerInfo, ServerMsg, StreamInfo, Token,
    User, UserId, Whisper, key_hex, parse_key,
};
use quinn::crypto::rustls::QuicClientConfig;
pub use quinn::{RecvStream, SendStream};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// Who we are to servers: an Ed25519 key pair. Keep it, or servers forget
/// our role and bans no longer stick.
pub struct Identity(Ed25519KeyPair, Vec<u8>);

impl Identity {
    pub fn generate() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("random key");
        Self::from_pkcs8(pkcs8.as_ref()).expect("a key we just made")
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        let pair = Ed25519KeyPair::from_pkcs8(der).map_err(|e| anyhow::anyhow!("bad identity key: {e}"))?;
        Ok(Self(pair, der.to_vec()))
    }

    /// The key in `path`, or a new one saved there.
    pub fn load_or_create(path: &std::path::Path) -> Result<Self> {
        if let Ok(der) = std::fs::read(path) {
            return Self::from_pkcs8(&der);
        }
        let id = Self::generate();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, id.pkcs8()).with_context(|| format!("saving {}", path.display()))?;
        Ok(id)
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.1
    }

    pub fn key(&self) -> Key {
        self.0.public_key().as_ref().try_into().expect("ed25519 keys are 32 bytes")
    }
}

pub struct Options<'a> {
    pub name: &'a str,
    pub identity: &'a Identity,
    /// The server's self-signed certificate fingerprint. Without one, the
    /// certificate has to be valid for `server_name` (Let's Encrypt).
    pub fingerprint: Option<&'a str>,
    pub password: Option<&'a str>,
    /// The name the server's certificate is for: the domain in the link.
    pub server_name: Option<&'a str>,
}

pub struct Client {
    pub you: UserId,
    pub server: ServerInfo,
    pub channels: Vec<Channel>,
    pub roles: Vec<Role>,
    /// Everyone on the server when we joined, us included.
    pub users: Vec<User>,
    /// The server's certificate fingerprint, to pin next time.
    pub fingerprint: String,
    conn: quinn::Connection,
    control: mpsc::UnboundedSender<ClientMsg>,
    events: mpsc::UnboundedReceiver<ServerMsg>,
    // keeps the socket open
    endpoint: quinn::Endpoint,
}

pub struct Voice {
    pub from: UserId,
    pub seq: u16,
    pub whisper: bool,
    pub opus: Vec<u8>,
}

impl Client {
    /// Connect and say hello.
    pub async fn connect(addr: SocketAddr, opts: Options<'_>) -> Result<Self> {
        let verifier = Arc::new(Pinned::new(opts.fingerprint.map(str::to_lowercase)));
        let provider = verifier.provider.clone();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        config.transport_config(Arc::new(transport));

        let local: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
        let mut endpoint = quinn::Endpoint::client(local)?;
        endpoint.set_default_client_config(config);
        let name = opts.server_name.unwrap_or("banshee");
        let conn = endpoint.connect(addr, name)?.await.with_context(|| format!("connecting to {addr}"))?;
        let fingerprint = verifier.seen().unwrap_or_default();

        let mut binding = [0u8; 32];
        conn.export_keying_material(&mut binding, IDENTITY_LABEL, b"")
            .map_err(|_| anyhow::anyhow!("no keying material"))?;
        let hello = ClientMsg::Hello {
            protocol: PROTOCOL_VERSION,
            name: opts.name.to_string(),
            key: opts.identity.key(),
            signature: opts.identity.0.sign(&binding).as_ref().to_vec(),
            password: opts.password.map(str::to_string),
        };
        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, &hello).await?;
        let welcome = tokio::time::timeout(Duration::from_secs(10), read_msg::<_, ServerMsg>(&mut recv))
            .await
            .context("the server didn't answer")??;
        let (you, server, channels, users, roles) = match welcome {
            ServerMsg::Welcome { you, server, channels, users, roles } => (you, server, channels, users, roles),
            ServerMsg::Error { message } => bail!("refused: {message}"),
            other => bail!("unexpected answer: {other:?}"),
        };

        let (control, mut control_rx) = mpsc::unbounded_channel::<ClientMsg>();
        tokio::spawn(async move {
            while let Some(msg) = control_rx.recv().await {
                if write_msg(&mut send, &msg).await.is_err() {
                    break;
                }
            }
        });
        let (events_tx, events) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(msg) = read_msg::<_, ServerMsg>(&mut recv).await {
                if events_tx.send(msg).is_err() {
                    break;
                }
            }
        });
        Ok(Self { you, server, channels, users, roles, fingerprint, conn, control, events, endpoint })
    }

    pub fn send(&self, msg: ClientMsg) {
        let _ = self.control.send(msg);
    }

    pub fn join(&self, channel: ChannelId) {
        self.send(ClientMsg::Join { channel, password: None });
    }

    /// Text to our channel.
    pub fn chat(&self, text: &str) {
        self.send(ClientMsg::Chat { to: ChatTarget::Channel, text: text.to_string() });
    }

    /// The next message from the server; None once the connection is gone.
    pub async fn next_event(&mut self) -> Option<ServerMsg> {
        self.events.recv().await
    }

    pub fn send_voice(&self, seq: u16, opus: &[u8]) -> Result<()> {
        self.conn.send_datagram(voice::encode_up(seq, opus).into())?;
        Ok(())
    }

    pub async fn recv_voice(&self) -> Result<Voice> {
        self.voice().recv().await
    }

    /// Files and avatars; the handle can go to other tasks.
    pub fn files(&self) -> Files {
        Files(self.conn.clone())
    }

    /// Receives voice on its own, so it can be awaited next to `next_event`.
    pub fn voice(&self) -> VoiceReceiver {
        VoiceReceiver(self.conn.clone())
    }

    /// Screen sharing; the handle can go to other tasks.
    pub fn video(&self) -> Video {
        Video(self.conn.clone())
    }

    /// Leave, and wait until the server has been told.
    pub async fn close(self) {
        self.conn.close(0u32.into(), b"bye");
        self.endpoint.wait_idle().await;
    }
}

/// File transfers on a connection (each on its own stream).
#[derive(Clone)]
pub struct Files(quinn::Connection);

impl Files {
    /// Start a download (a channel file or an avatar): its size and the
    /// stream its bytes come on.
    pub async fn download(&self, request: Request) -> Result<(u64, RecvStream)> {
        let (_send, mut recv) = self.open_transfer(&request).await?;
        match read_msg::<_, Reply>(&mut recv).await? {
            Reply::Ready { size } => Ok((size, recv)),
            Reply::Refused { message } => bail!(message),
            Reply::Done => bail!("unexpected answer"),
        }
    }

    /// Start an upload: write the bytes to the returned upload, then `finish` it.
    pub async fn upload(&self, request: Request) -> Result<Upload> {
        let (send, mut recv) = self.open_transfer(&request).await?;
        match read_msg::<_, Reply>(&mut recv).await? {
            Reply::Ready { .. } => Ok(Upload { send, recv }),
            Reply::Refused { message } => bail!(message),
            Reply::Done => bail!("unexpected answer"),
        }
    }

    /// Someone's picture.
    pub async fn avatar(&self, key: Key) -> Result<Vec<u8>> {
        let (size, recv) = self.download(Request::Avatar { key }).await?;
        let mut data = Vec::new();
        recv.take(size.min(MAX_AVATAR)).read_to_end(&mut data).await?;
        Ok(data)
    }

    /// Our picture (PNG or JPEG); `ClientMsg::ClearAvatar` removes it.
    pub async fn set_avatar(&self, picture: &[u8]) -> Result<()> {
        let mut up = self.upload(Request::SetAvatar { size: picture.len() as u64 }).await?;
        up.send.write_all(picture).await?;
        up.finish().await
    }

    async fn open_transfer(&self, request: &Request) -> Result<(SendStream, RecvStream)> {
        let (mut send, recv) = self.0.open_bi().await?;
        write_msg(&mut send, request).await?;
        Ok((send, recv))
    }
}

pub struct Upload {
    pub send: SendStream,
    recv: RecvStream,
}

impl Upload {
    /// Say we're through and wait until the server kept the file.
    pub async fn finish(mut self) -> Result<()> {
        self.send.finish()?;
        match read_msg::<_, Reply>(&mut self.recv).await? {
            Reply::Done => Ok(()),
            Reply::Refused { message } => bail!(message),
            Reply::Ready { .. } => bail!("unexpected answer"),
        }
    }
}

/// Sharing our screen and receiving the screens we watch.
#[derive(Clone)]
pub struct Video(quinn::Connection);

impl Video {
    /// Start sharing. Packets go out with [`Share::send`]; dropping it or
    /// [`Share::stop`] ends the share. The server says no with an `Error` message.
    pub async fn share(&self, info: &StreamInfo) -> Result<Share> {
        let mut send = self.0.open_uni().await?;
        send.write_all(&[banshee_proto::video::KIND]).await?;
        write_msg(&mut send, info).await?;
        Ok(Share(send))
    }

    /// The next screen we get (after `ClientMsg::Watch`).
    pub async fn next(&self) -> Result<Watching> {
        loop {
            let mut recv = self.0.accept_uni().await?;
            let mut head = [0u8; 5];
            if recv.read_exact(&mut head).await.is_err() || head[0] != banshee_proto::video::KIND {
                let _ = recv.stop(0u32.into());
                continue;
            }
            let from = UserId::from_le_bytes(head[1..].try_into().unwrap());
            return Ok(Watching { from, recv });
        }
    }
}

pub struct Share(SendStream);

impl Share {
    /// A video frame (H.264 Annex B, on the track of its layer) or sound.
    pub async fn send(&mut self, packet: &Packet) -> Result<()> {
        banshee_proto::video::write(&mut self.0, packet).await?;
        Ok(())
    }

    pub fn stop(mut self) {
        let _ = self.0.finish();
    }
}

/// Someone's screen, as it arrives. It starts with a keyframe.
pub struct Watching {
    pub from: UserId,
    recv: RecvStream,
}

impl Watching {
    /// The next packet; None once they stop sharing or we stop watching.
    pub async fn packet(&mut self) -> Result<Option<Packet>> {
        Ok(banshee_proto::video::read(&mut self.recv).await?)
    }
}

#[derive(Clone)]
pub struct VoiceReceiver(quinn::Connection);

impl VoiceReceiver {
    pub async fn recv(&self) -> Result<Voice> {
        loop {
            let data = self.0.read_datagram().await?;
            if let Some(d) = voice::decode_down(&data) {
                return Ok(Voice { from: d.from, seq: d.seq, whisper: d.whisper, opus: d.opus.to_vec() });
            }
        }
    }
}

/// Takes a certificate that's valid for the server's name (Let's Encrypt),
/// or a self-signed one matching the pinned fingerprint. A valid one wins
/// over the pin, so renewals don't break saved links.
#[derive(Debug)]
struct Pinned {
    expected: Option<String>,
    seen: std::sync::Mutex<Option<String>>,
    provider: Arc<CryptoProvider>,
    trusted: Arc<rustls::client::WebPkiServerVerifier>,
}

impl Pinned {
    fn new(expected: Option<String>) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let trusted = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .expect("the bundled root certificates are valid");
        Self { expected, seen: Default::default(), provider, trusted }
    }

    fn seen(&self) -> Option<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp: String = Sha256::digest(end_entity).iter().map(|b| format!("{b:02x}")).collect();
        *self.seen.lock().unwrap() = Some(fp.clone());
        if let Ok(ok) = self.trusted.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            return Ok(ok);
        }
        match &self.expected {
            Some(e) if *e == fp => Ok(ServerCertVerified::assertion()),
            Some(_) => {
                Err(rustls::Error::General(format!("certificate fingerprint {fp} doesn't match the pinned one")))
            }
            None => Err(rustls::Error::General(
                "the server's certificate isn't valid for this address; use the link with its #fingerprint".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
