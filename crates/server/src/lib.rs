//! The Banshee server: one QUIC endpoint, a channel tree, roles and
//! moderation, text chat, and voice relayed to whoever should hear it.

mod state;
mod store;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use banshee_proto::{
    ALPN, ClientMsg, FrameError, IDENTITY_LABEL, Leave, PROTOCOL_VERSION, ServerMsg, read_msg, voice, write_msg,
};
use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use ring::signature::{ED25519, UnparsedPublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use state::{Arrival, State};
use store::Store;

pub struct Config {
    pub bind: SocketAddr,
    /// Where the server keeps its certificate and state.
    pub data_dir: PathBuf,
    /// Channels for a new server; the first one is where people land.
    pub channels: Vec<String>,
}

pub struct Server {
    endpoint: quinn::Endpoint,
    fingerprint: String,
    state: Arc<Mutex<State>>,
}

impl Server {
    pub fn bind(config: Config) -> Result<Self> {
        let store = match Store::load(&config.data_dir)? {
            Some(store) if !store.channels.is_empty() => store,
            Some(_) => bail!("the saved state has no channels"),
            None => {
                if config.channels.is_empty() {
                    bail!("the server needs at least one channel");
                }
                let store = Store::fresh(&config.channels);
                store.save(&config.data_dir)?;
                store
            }
        };
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
        let state = Arc::new(Mutex::new(State::new(store, config.data_dir)));
        Ok(Self { endpoint, fingerprint, state })
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
        self.state.lock().unwrap().store.unused_admin_token().map(str::to_string)
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
    let result = tokio::select! {
        r = writer => r,
        r = control => r,
        r = voice => r,
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
