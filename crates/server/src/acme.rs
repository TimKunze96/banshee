//! A Let's Encrypt certificate for `BANSHEE_DOMAIN`, so clients check the
//! server like a browser checks a website and the link is just the domain.
//!
//! The challenge is HTTP-01: while a certificate is being issued, a tiny HTTP
//! server answers Let's Encrypt on `BANSHEE_ACME_HTTP` (the host's TCP port 80
//! has to reach it). The certificate lives in `<data>/acme` and is renewed
//! after 60 days (they last 90), swapped in without a restart.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

/// Renew when the certificate is this old.
const RENEW_AFTER: Duration = Duration::from_secs(60 * 24 * 3600);
/// Wait this long after a failed attempt.
const RETRY: Duration = Duration::from_secs(3600);

/// What `BANSHEE_DOMAIN` and friends ask for.
#[derive(Clone, Debug)]
pub struct AcmeConfig {
    pub domain: String,
    /// For Let's Encrypt's expiry mails (optional).
    pub email: Option<String>,
    /// Where the challenge server listens.
    pub http: SocketAddr,
    /// Let's Encrypt's staging directory (untrusted certificates, for testing).
    pub staging: bool,
    /// Another ACME directory, and the root certificate its API uses (for
    /// testing against Pebble).
    pub directory: Option<String>,
    pub directory_root: Option<PathBuf>,
}

/// The certificate the server hands out; swapped when a new one arrives.
#[derive(Debug)]
pub struct Certs(RwLock<Arc<CertifiedKey>>);

impl Certs {
    pub fn new(key: CertifiedKey) -> Self {
        Self(RwLock::new(Arc::new(key)))
    }

    fn set(&self, key: CertifiedKey) {
        *self.0.write().unwrap() = Arc::new(key);
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().unwrap().clone())
    }
}

/// A certificate and key the provider can sign with.
pub fn certified(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    provider: &CryptoProvider,
) -> Result<CertifiedKey> {
    let key = provider.key_provider.load_private_key(key).map_err(|e| anyhow!("{e}"))?;
    Ok(CertifiedKey::new(chain, key))
}

fn dir(data: &std::path::Path) -> PathBuf {
    data.join("acme")
}

/// The certificate we got earlier, and when, if there is one.
pub fn load(data: &std::path::Path, provider: &CryptoProvider) -> Option<(CertifiedKey, SystemTime)> {
    let dir = dir(data);
    let chain_pem = std::fs::read(dir.join("cert.pem")).ok()?;
    let key_pem = std::fs::read(dir.join("key.pem")).ok()?;
    let chain: Vec<_> = CertificateDer::pem_slice_iter(&chain_pem).filter_map(|c| c.ok()).collect();
    let key = PrivateKeyDer::from_pem_slice(&key_pem).ok()?;
    let issued = std::fs::metadata(dir.join("cert.pem")).and_then(|m| m.modified()).ok()?;
    Some((certified(chain, key, provider).ok()?, issued))
}

/// What keeps the certificate fresh.
pub struct Renewal {
    pub config: AcmeConfig,
    pub data: PathBuf,
    pub certs: Arc<Certs>,
    pub provider: Arc<CryptoProvider>,
    /// When the current certificate was issued (None: still self-signed).
    pub issued: Option<SystemTime>,
}

/// Keep a valid certificate in `certs`: get one now if there's none, then
/// renew it in time. Runs as long as the server.
pub async fn run(renewal: Renewal) {
    let Renewal { config, data, certs, provider, mut issued } = renewal;
    loop {
        let age = issued.and_then(|t| t.elapsed().ok());
        if let Some(age) = age.filter(|a| *a < RENEW_AFTER) {
            tokio::time::sleep((RENEW_AFTER - age).min(Duration::from_secs(12 * 3600))).await;
            continue;
        }
        info!(domain = config.domain, "getting a certificate from Let's Encrypt");
        match obtain(&config, &data).await.and_then(|(chain, key)| {
            let chain: Vec<_> = CertificateDer::pem_slice_iter(chain.as_bytes()).collect::<Result<_, _>>()?;
            let key = PrivateKeyDer::from_pem_slice(key.as_bytes())?;
            certified(chain, key, &provider)
        }) {
            Ok(key) => {
                certs.set(key);
                issued = Some(SystemTime::now());
                info!(domain = config.domain, "got the certificate; connect with banshee://{}", config.domain);
            }
            Err(e) => {
                error!(
                    domain = config.domain,
                    "Let's Encrypt failed: {e:#}. Check that {} points at this server and that TCP port 80 reaches {} \
                     (trying again in an hour)",
                    config.domain,
                    config.http
                );
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}

/// One certificate: (chain PEM, key PEM), also saved to `<data>/acme`.
async fn obtain(config: &AcmeConfig, data: &std::path::Path) -> Result<(String, String)> {
    let dir = dir(data);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let tokens: Arc<Mutex<HashMap<String, String>>> = Arc::default();
    let listener = tokio::net::TcpListener::bind(config.http)
        .await
        .with_context(|| format!("listening for the challenge on {}", config.http))?;
    let challenge_server = tokio::spawn(serve_challenges(listener, tokens.clone()));
    let result = issue(config, &dir, &tokens).await;
    challenge_server.abort();
    let (chain, key) = result?;
    std::fs::write(dir.join("key.pem"), &key)?;
    std::fs::write(dir.join("cert.pem"), &chain)?;
    Ok((chain, key))
}

async fn issue(
    config: &AcmeConfig,
    dir: &std::path::Path,
    tokens: &Mutex<HashMap<String, String>>,
) -> Result<(String, String)> {
    let account = account(config, dir).await?;
    let identifiers = [Identifier::Dns(config.domain.clone())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let mut authorizations = order.authorizations();
    while let Some(authz) = authorizations.next().await {
        let mut authz = authz?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => bail!("authorization is {other:?}"),
        }
        let mut challenge =
            authz.challenge(ChallengeType::Http01).context("Let's Encrypt offered no HTTP challenge")?;
        tokens.lock().unwrap().insert(challenge.token.clone(), challenge.key_authorization().as_str().to_string());
        challenge.set_ready().await?;
    }
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        bail!("the order ended up {status:?} (Let's Encrypt couldn't fetch the challenge)");
    }
    let key = order.finalize().await?;
    let chain = order.poll_certificate(&RetryPolicy::default()).await?;
    Ok((chain, key))
}

/// The account from last time, or a new one (saved for next time).
async fn account(config: &AcmeConfig, dir: &std::path::Path) -> Result<Account> {
    let path = dir.join(if config.staging { "account-staging.json" } else { "account.json" });
    let builder = || match &config.directory_root {
        Some(root) => Account::builder_with_root(root),
        None => Account::builder(),
    };
    if let Ok(saved) = std::fs::read(&path) {
        let credentials: AccountCredentials = serde_json::from_slice(&saved)?;
        return Ok(builder()?.from_credentials(credentials).await?);
    }
    let contact: Vec<String> = config.email.iter().map(|e| format!("mailto:{e}")).collect();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let url = match &config.directory {
        Some(url) => url.clone(),
        None if config.staging => LetsEncrypt::Staging.url().to_owned(),
        None => LetsEncrypt::Production.url().to_owned(),
    };
    let new = NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false };
    let (account, credentials) = builder()?.create(&new, url, None).await?;
    std::fs::write(&path, serde_json::to_vec(&credentials)?)?;
    Ok(account)
}

/// Answers `GET /.well-known/acme-challenge/<token>` and nothing else.
async fn serve_challenges(listener: tokio::net::TcpListener, tokens: Arc<Mutex<HashMap<String, String>>>) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let tokens = tokens.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut len = 0;
            // the request line and headers, up to the blank line
            while len < buf.len() {
                let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf[len..])).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                len += n;
                if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf[..len]);
            let path = request.lines().next().and_then(|l| l.strip_prefix("GET ")).and_then(|l| l.split(' ').next());
            let token = path.and_then(|p| p.strip_prefix("/.well-known/acme-challenge/"));
            let answer = token.and_then(|t| tokens.lock().unwrap().get(t).cloned());
            let response = match answer {
                Some(body) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            };
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The challenge server answers known tokens, 404s the rest.
    #[tokio::test]
    async fn answers_challenges() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tokens: Arc<Mutex<HashMap<String, String>>> = Arc::default();
        tokens.lock().unwrap().insert("abc".into(), "abc.thumb".into());
        tokio::spawn(serve_challenges(listener, tokens));
        let get = |path: &'static str| async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        let ok = get("/.well-known/acme-challenge/abc").await;
        assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("abc.thumb"), "{ok}");
        assert!(get("/.well-known/acme-challenge/nope").await.starts_with("HTTP/1.1 404"));
        assert!(get("/").await.starts_with("HTTP/1.1 404"));
    }
}
