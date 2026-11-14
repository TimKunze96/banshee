//! The Banshee server: one QUIC endpoint, channels, text chat, and voice
//! relayed to everyone else in the speaker's channel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use banshee_proto::{
    ALPN, Channel, ChannelId, ClientMsg, FrameError, PROTOCOL_VERSION, ServerMsg, User, UserId, read_msg, voice,
    write_msg,
};
use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct Config {
    pub bind: SocketAddr,
    /// Where the server keeps its certificate.
    pub data_dir: PathBuf,
    /// Channel names; the first one is where people land.
    pub channels: Vec<String>,
}

pub struct Server {
    endpoint: quinn::Endpoint,
    fingerprint: String,
    state: Arc<Mutex<State>>,
}

struct State {
    channels: Vec<Channel>,
    users: HashMap<UserId, Peer>,
    next_id: UserId,
}

struct Peer {
    user: User,
    conn: quinn::Connection,
    tx: mpsc::UnboundedSender<ServerMsg>,
}

const MAX_NAME: usize = 32;
const MAX_CHAT: usize = 2000;

impl Server {
    pub fn bind(config: Config) -> Result<Self> {
        if config.channels.is_empty() {
            bail!("the server needs at least one channel");
        }
        let (cert, key) = load_or_create_cert(&config.data_dir)?;
        let fingerprint = fingerprint(&cert);

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        server_config.transport_config(Arc::new(transport));

        let endpoint =
            quinn::Endpoint::server(server_config, config.bind).with_context(|| format!("binding {}", config.bind))?;
        let channels = config.channels.into_iter().zip(1..).map(|(name, id)| Channel { id, name }).collect();
        let state = Arc::new(Mutex::new(State { channels, users: HashMap::new(), next_id: 1 }));
        Ok(Self { endpoint, fingerprint, state })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// SHA-256 of the certificate, hex. Clients pin it.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Accept connections until the endpoint closes.
    pub async fn run(self) {
        while let Some(incoming) = self.endpoint.accept().await {
            let state = self.state.clone();
            tokio::spawn(async move {
                let remote = incoming.remote_address();
                if let Err(e) = handle(incoming, state).await {
                    info!(%remote, "connection ended: {e:#}");
                }
            });
        }
    }
}

async fn handle(incoming: quinn::Incoming, state: Arc<Mutex<State>>) -> Result<()> {
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;

    let hello = tokio::time::timeout(Duration::from_secs(10), read_msg::<_, ClientMsg>(&mut recv))
        .await
        .context("no hello")??;
    let ClientMsg::Hello { protocol, name } = hello else { bail!("expected hello") };
    let name = name.trim().to_string();
    let refusal = if protocol != PROTOCOL_VERSION {
        Some(format!("this server speaks protocol {PROTOCOL_VERSION}, not {protocol}"))
    } else if name.is_empty() || name.chars().count() > MAX_NAME {
        Some(format!("names need 1 to {MAX_NAME} characters"))
    } else {
        None
    };
    if let Some(message) = refusal {
        write_msg(&mut send, &ServerMsg::Error { message: message.clone() }).await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        bail!(message);
    }

    let (tx, mut rx) = mpsc::unbounded_channel();
    let id = {
        let mut s = state.lock().unwrap();
        let id = s.next_id;
        s.next_id += 1;
        let user = User { id, name, channel: s.channels[0].id };
        let welcome = ServerMsg::Welcome {
            you: id,
            channels: s.channels.clone(),
            users: s.users.values().map(|p| p.user.clone()).chain([user.clone()]).collect(),
        };
        s.broadcast(|_| true, &ServerMsg::UserJoined(user.clone()));
        let _ = tx.send(welcome);
        s.users.insert(id, Peer { user, conn: conn.clone(), tx });
        id
    };
    info!(id, "joined");

    let writer = async {
        while let Some(msg) = rx.recv().await {
            write_msg(&mut send, &msg).await?;
        }
        anyhow::Ok(())
    };
    let control = async {
        loop {
            match read_msg::<_, ClientMsg>(&mut recv).await {
                Ok(msg) => state.lock().unwrap().handle(id, msg),
                Err(FrameError::Closed) => return anyhow::Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    };
    let voice = async {
        loop {
            let data = conn.read_datagram().await?;
            relay(&state, id, &data);
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    let result = tokio::select! {
        r = writer => r,
        r = control => r,
        r = voice => r,
    };

    let mut s = state.lock().unwrap();
    s.users.remove(&id);
    s.broadcast(|_| true, &ServerMsg::UserLeft { id });
    info!(id, "left");
    result
}

impl State {
    fn handle(&mut self, id: UserId, msg: ClientMsg) {
        match msg {
            ClientMsg::Hello { .. } => self.reply(id, "already said hello"),
            ClientMsg::Join { channel } => {
                if !self.channels.iter().any(|c| c.id == channel) {
                    return self.reply(id, "no such channel");
                }
                let Some(peer) = self.users.get_mut(&id) else { return };
                if peer.user.channel == channel {
                    return;
                }
                peer.user.channel = channel;
                self.broadcast(|_| true, &ServerMsg::UserMoved { id, channel });
            }
            ClientMsg::Chat { text } => {
                let text = text.trim();
                if text.is_empty() || text.chars().count() > MAX_CHAT {
                    return self.reply(id, &format!("messages need 1 to {MAX_CHAT} characters"));
                }
                let Some(channel) = self.channel_of(id) else { return };
                let msg = ServerMsg::Chat { from: id, channel, text: text.to_string() };
                self.broadcast(|p| p.user.channel == channel, &msg);
            }
        }
    }

    fn channel_of(&self, id: UserId) -> Option<ChannelId> {
        self.users.get(&id).map(|p| p.user.channel)
    }

    fn reply(&self, id: UserId, message: &str) {
        if let Some(p) = self.users.get(&id) {
            let _ = p.tx.send(ServerMsg::Error { message: message.to_string() });
        }
    }

    fn broadcast(&self, to: impl Fn(&Peer) -> bool, msg: &ServerMsg) {
        for p in self.users.values().filter(|p| to(p)) {
            let _ = p.tx.send(msg.clone());
        }
    }
}

/// Forward a voice datagram to everyone else in the speaker's channel.
fn relay(state: &Mutex<State>, from: UserId, data: &[u8]) {
    let Some(out) = voice::relay(from, data) else { return };
    let out = Bytes::from(out);
    let targets: Vec<quinn::Connection> = {
        let s = state.lock().unwrap();
        let Some(channel) = s.channel_of(from) else { return };
        s.users.values().filter(|p| p.user.id != from && p.user.channel == channel).map(|p| p.conn.clone()).collect()
    };
    for conn in targets {
        if let Err(e) = conn.send_datagram(out.clone()) {
            warn!("dropping voice for {}: {e}", conn.remote_address());
        }
    }
}

fn load_or_create_cert(dir: &Path) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let (cert_path, key_path) = (dir.join("cert.der"), dir.join("key.der"));
    if let (Ok(cert), Ok(key)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
        return Ok((cert.into(), PrivatePkcs8KeyDer::from(key).into()));
    }
    let generated = rcgen::generate_simple_self_signed(vec!["banshee".into()])?;
    let cert = generated.cert.der().clone();
    let key = generated.signing_key.serialize_der();
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(&cert_path, &cert)?;
    std::fs::write(&key_path, &key)?;
    Ok((cert, PrivatePkcs8KeyDer::from(key).into()))
}

fn fingerprint(cert: &CertificateDer) -> String {
    Sha256::digest(cert).iter().map(|b| format!("{b:02x}")).collect()
}
