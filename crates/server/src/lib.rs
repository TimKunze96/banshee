//! The Banshee server: one QUIC endpoint, a channel tree, roles and
//! moderation, text chat, and voice relayed to whoever should hear it.

mod db;
mod files;
mod state;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use banshee_proto::transfer::{MAX_AVATAR, Reply, Request};
use banshee_proto::{
    ALPN, ClientMsg, FrameError, IDENTITY_LABEL, Leave, PROTOCOL_VERSION, Perm, ServerMsg, UserId, read_msg, voice,
    write_msg,
};
use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use ring::signature::{ED25519, UnparsedPublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use db::Db;
use state::{Arrival, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Config {
    pub bind: SocketAddr,
    /// Where the server keeps its certificate and state.
    pub data_dir: PathBuf,
    /// Channels for a new server; the first one is where people land.
    pub channels: Vec<String>,
    /// Biggest file people can upload, in bytes.
    pub max_file: u64,
}

pub struct Server {
    endpoint: quinn::Endpoint,
    fingerprint: String,
    state: Arc<Mutex<State>>,
    max_file: u64,
}

impl Server {
    pub fn bind(config: Config) -> Result<Self> {
        let db = Db::open(&config.data_dir, &config.channels)?;
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
        let state = Arc::new(Mutex::new(State::new(db, config.data_dir)?));
        Ok(Self { endpoint, fingerprint, state, max_file: config.max_file })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// SHA-256 of the certificate, hex. Clients pin it.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The token that makes its redeemer admin, while nobody has used it.
    pub fn admin_token(&self) -> Option<String> {
        self.state.lock().unwrap().admin_token()
    }

    /// Accept connections until the endpoint closes.
    pub async fn run(self) {
        while let Some(incoming) = self.endpoint.accept().await {
            let state = self.state.clone();
            let max_file = self.max_file;
            tokio::spawn(async move {
                let remote = incoming.remote_address();
                if let Err(e) = handle(incoming, state, max_file).await {
                    info!(%remote, "connection ended: {e:#}");
                }
            });
        }
    }
}

async fn handle(incoming: quinn::Incoming, state: Arc<Mutex<State>>, max_file: u64) -> Result<()> {
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;

    let hello = tokio::time::timeout(Duration::from_secs(10), read_msg::<_, ClientMsg>(&mut recv))
        .await
        .context("no hello")??;
    let ClientMsg::Hello { protocol, name, key, signature, password } = hello else { bail!("expected hello") };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let admitted = if protocol != PROTOCOL_VERSION {
        Err(format!("this server speaks protocol {PROTOCOL_VERSION}, not {protocol}"))
    } else if !signed(&conn, &key, &signature) {
        Err("the identity signature doesn't check out".into())
    } else {
        let ip = conn.remote_address().ip().to_canonical().to_string();
        state.lock().unwrap().arrive(Arrival { key, name, password, ip, conn: conn.clone(), tx })
    };
    let id = match admitted {
        Ok(id) => id,
        Err(message) => {
            write_msg(&mut send, &ServerMsg::Error { message: message.clone() }).await?;
            let _ = send.finish();
            let _ = send.stopped().await;
            bail!(message);
        }
    };

    let writer = async {
        while let Some(msg) = rx.recv().await {
            write_msg(&mut send, &msg).await?;
        }
        // the server let go of them (kick, ban): let them read why, then close
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(3), send.stopped()).await;
        conn.close(1u32.into(), b"removed");
        anyhow::Ok(Leave::Quit)
    };
    let control = async {
        loop {
            match read_msg::<_, ClientMsg>(&mut recv).await {
                Ok(msg) => state.lock().unwrap().handle(id, msg),
                Err(FrameError::Closed) => return anyhow::Ok(Leave::Quit),
                Err(e) => return Err(e.into()),
            }
        }
    };
    let voice = async {
        loop {
            match conn.read_datagram().await {
                Ok(data) => relay(&state, id, &data),
                // the client said goodbye
                Err(quinn::ConnectionError::ApplicationClosed(_)) => return anyhow::Ok(Leave::Quit),
                Err(e) => return Err(e.into()),
            }
        }
    };
    // file transfers, each on its own stream
    let streams = async {
        loop {
            let (send, recv) = conn.accept_bi().await?;
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = transfer(&state, id, send, recv, max_file).await {
                    info!(id, "transfer failed: {e:#}");
                }
            });
        }
        #[allow(unreachable_code)]
        anyhow::Ok(Leave::Quit)
    };
    let result = tokio::select! {
        r = writer => r,
        r = control => r,
        r = voice => r,
        r = streams => r,
    };
    // the client closing shows up as an error on whichever read noticed first
    let said_bye = matches!(conn.close_reason(), Some(quinn::ConnectionError::ApplicationClosed(_)));
    let result = if said_bye { Ok(Leave::Quit) } else { result };
    let reason = match &result {
        Ok(reason) => reason.clone(),
        Err(_) => Leave::Lost,
    };
    state.lock().unwrap().depart(id, reason);
    result.map(|_| ())
}

/// One file transfer (see `banshee_proto::transfer`).
async fn transfer(
    state: &Mutex<State>,
    id: UserId,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    max_file: u64,
) -> Result<()> {
    let request = tokio::time::timeout(Duration::from_secs(10), read_msg::<_, Request>(&mut recv))
        .await
        .context("no transfer request")??;
    let outcome = match request {
        Request::Download { channel, password, path } => {
            let file = state
                .lock()
                .unwrap()
                .file_root(id, channel, password.as_deref(), None)
                .and_then(|root| files::resolve(&root, &path));
            match file {
                Ok(file) => return send_file(send, &file).await,
                Err(e) => Err(e),
            }
        }
        Request::Avatar { key } => {
            let file = state.lock().unwrap().avatar_of(&key);
            match file {
                Some(file) => return send_file(send, &file).await,
                None => Err("they have no picture".into()),
            }
        }
        Request::Upload { channel, password, path, size } => {
            let target = state
                .lock()
                .unwrap()
                .file_root(id, channel, password.as_deref(), Some(Perm::UploadFiles))
                .and_then(|root| files::resolve(&root, &path).map(|t| (root, t)));
            match target {
                Ok(_) if size > max_file => Err(format!("files can be {} MB at most", max_file / 1_000_000)),
                Ok((root, target)) if target == root || target.is_dir() => Err("that's a folder".to_string()),
                Ok((_, target)) => {
                    let result = receive_file(&mut send, &mut recv, &target, size).await?;
                    if result.is_ok() {
                        let s = state.lock().unwrap();
                        let who = s.users.get(&id).map(|p| p.user.name.clone()).unwrap_or_default();
                        let _ = s.db.log(&format!("{who} uploaded {path} to channel {channel}"));
                    }
                    result
                }
                Err(e) => Err(e),
            }
        }
        Request::SetAvatar { size } if size > MAX_AVATAR => {
            Err(format!("pictures can be {} KB at most", MAX_AVATAR / 1024))
        }
        Request::SetAvatar { size } => {
            write_msg(&mut send, &Reply::Ready { size: 0 }).await?;
            let mut data = Vec::new();
            (&mut recv).take(size + 1).read_to_end(&mut data).await?;
            if data.len() as u64 != size || !files::is_picture(&data) {
                Err("that isn't a PNG or JPEG picture".to_string())
            } else {
                let mut s = state.lock().unwrap();
                let key = s.users.get(&id).map(|p| p.user.key).context("gone")?;
                let path = files::avatar_path(&s.data_dir, &key);
                let saved =
                    path.parent().map(std::fs::create_dir_all).transpose().and_then(|_| std::fs::write(&path, &data));
                match saved {
                    Ok(()) => s.set_avatar(id, Some(db::content_hash(&data))),
                    Err(e) => Err(format!("the server couldn't keep it: {e}")),
                }
            }
        }
    };
    let reply = match outcome {
        Ok(()) => Reply::Done,
        Err(message) => Reply::Refused { message },
    };
    write_msg(&mut send, &reply).await?;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;
    Ok(())
}

/// `Ready`, then the file, then the stream ends (no `Done`: the client
/// counts bytes), or a refusal.
async fn send_file(mut send: quinn::SendStream, path: &Path) -> Result<()> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) if f.metadata().await.is_ok_and(|m| m.is_file()) => f,
        _ => {
            return refuse(send, "there's no such file").await;
        }
    };
    let size = file.metadata().await?.len();
    write_msg(&mut send, &Reply::Ready { size }).await?;
    tokio::io::copy(&mut (&mut file).take(size), &mut send).await?;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(30), send.stopped()).await;
    Ok(())
}

async fn refuse(mut send: quinn::SendStream, message: &str) -> Result<()> {
    write_msg(&mut send, &Reply::Refused { message: message.to_string() }).await?;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;
    Ok(())
}

/// `Ready`, then `size` bytes into `<target>.part`, renamed once complete.
async fn receive_file(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    target: &Path,
    size: u64,
) -> Result<std::result::Result<(), String>> {
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let part = target.with_file_name(format!("{name}.part"));
    if let Some(dir) = target.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    write_msg(send, &Reply::Ready { size: 0 }).await?;
    let mut file = tokio::fs::File::create(&part).await?;
    let copied = tokio::io::copy(&mut recv.take(size + 1), &mut file).await;
    file.flush().await?;
    drop(file);
    match copied {
        Ok(n) if n == size => {
            tokio::fs::rename(&part, target).await?;
            Ok(Ok(()))
        }
        Ok(_) => {
            let _ = tokio::fs::remove_file(&part).await;
            Ok(Err("the upload didn't match its size".into()))
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&part).await;
            Err(e.into())
        }
    }
}

/// The client holds the key: it signed this connection's keying material.
fn signed(conn: &quinn::Connection, key: &[u8; 32], signature: &[u8]) -> bool {
    let mut binding = [0u8; 32];
    if conn.export_keying_material(&mut binding, IDENTITY_LABEL, b"").is_err() {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, key).verify(&binding, signature).is_ok()
}

/// Forward a voice datagram to whoever hears the speaker.
fn relay(state: &Mutex<State>, from: u32, data: &[u8]) {
    let (targets, whisper) = state.lock().unwrap().listeners(from);
    if targets.is_empty() {
        return;
    }
    let flags = if whisper { voice::WHISPER } else { 0 };
    let Some(out) = voice::relay(from, flags, data) else { return };
    let out = Bytes::from(out);
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
