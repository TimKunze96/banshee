//! A Banshee client: connect, then send control messages and voice and read
//! what the server sends back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use banshee_proto::{ALPN, ClientMsg, PROTOCOL_VERSION, read_msg, voice, write_msg};
pub use banshee_proto::{Channel, ChannelId, ServerMsg, User, UserId};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

pub struct Client {
    pub you: UserId,
    pub channels: Vec<Channel>,
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
    pub opus: Vec<u8>,
}

impl Client {
    /// Connect and say hello. With a `fingerprint`, the server's certificate
    /// has to match it; without one, any certificate is taken (first use).
    pub async fn connect(addr: SocketAddr, name: &str, fingerprint: Option<&str>) -> Result<Self> {
        let verifier = Arc::new(Pinned::new(fingerprint.map(str::to_lowercase)));
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
        let conn = endpoint.connect(addr, "banshee")?.await.with_context(|| format!("connecting to {addr}"))?;
        let fingerprint = verifier.seen().unwrap_or_default();

        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, &ClientMsg::Hello { protocol: PROTOCOL_VERSION, name: name.to_string() }).await?;
        let welcome = tokio::time::timeout(Duration::from_secs(10), read_msg::<_, ServerMsg>(&mut recv))
            .await
            .context("the server didn't answer")??;
        let (you, channels, users) = match welcome {
            ServerMsg::Welcome { you, channels, users } => (you, channels, users),
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
        Ok(Self { you, channels, users, fingerprint, conn, control, events, endpoint })
    }

    pub fn join(&self, channel: ChannelId) {
        let _ = self.control.send(ClientMsg::Join { channel });
    }

    pub fn chat(&self, text: &str) {
        let _ = self.control.send(ClientMsg::Chat { text: text.to_string() });
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

    /// Receives voice on its own, so it can be awaited next to `next_event`.
    pub fn voice(&self) -> VoiceReceiver {
        VoiceReceiver(self.conn.clone())
    }

    /// Leave, and wait until the server has been told.
    pub async fn close(self) {
        self.conn.close(0u32.into(), b"bye");
        self.endpoint.wait_idle().await;
    }
}

#[derive(Clone)]
pub struct VoiceReceiver(quinn::Connection);

impl VoiceReceiver {
    pub async fn recv(&self) -> Result<Voice> {
        loop {
            let data = self.0.read_datagram().await?;
            if let Some(d) = voice::decode_down(&data) {
                return Ok(Voice { from: d.from, seq: d.seq, opus: d.opus.to_vec() });
            }
        }
    }
}

/// Takes the server's self-signed certificate if it matches the pinned
/// fingerprint (or any, when none is pinned). Signatures are still checked.
#[derive(Debug)]
struct Pinned {
    expected: Option<String>,
    seen: std::sync::Mutex<Option<String>>,
    provider: Arc<CryptoProvider>,
}

impl Pinned {
    fn new(expected: Option<String>) -> Self {
        Self { expected, seen: Default::default(), provider: Arc::new(rustls::crypto::ring::default_provider()) }
    }

    fn seen(&self) -> Option<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp: String = Sha256::digest(end_entity).iter().map(|b| format!("{b:02x}")).collect();
        if self.expected.as_ref().is_some_and(|e| *e != fp) {
            return Err(rustls::Error::General(format!("certificate fingerprint {fp} doesn't match the pinned one")));
        }
        *self.seen.lock().unwrap() = Some(fp);
        Ok(ServerCertVerified::assertion())
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
