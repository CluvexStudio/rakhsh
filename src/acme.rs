use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::carrier::tls;

const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 3600);
const CHECK_EVERY: Duration = Duration::from_secs(12 * 3600);
const RETRY_FIRST: Duration = Duration::from_secs(600);
const RETRY_MAX: Duration = Duration::from_secs(12 * 3600);
const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

#[derive(Clone, Debug)]
pub struct Acme {
    pub domain: String,
    pub email: Option<String>,
    pub dir: PathBuf,
    pub port: u16,
    pub staging: bool,
}

impl Acme {
    pub fn from_config(
        domain: &str,
        email: &Option<String>,
        dir: &Option<String>,
        port: Option<u16>,
        staging: Option<bool>,
    ) -> Result<Acme> {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            bail!("acme_domain is empty");
        }
        if domain.parse::<std::net::IpAddr>().is_ok() {
            bail!("acme_domain must be a name, not an address: a certificate authority will not issue for {domain}");
        }
        if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
            bail!("acme_domain {domain} is not a fully qualified name");
        }
        if domain.starts_with('*') {
            bail!("acme_domain {domain} is a wildcard, which needs a dns-01 challenge this build does not do");
        }
        if let Some(e) = email {
            if !e.contains('@') {
                bail!("acme_email {e} is not an address");
            }
        }
        Ok(Acme {
            domain,
            email: email.clone(),
            dir: PathBuf::from(dir.clone().unwrap_or_else(|| "/var/lib/rakhsh/acme".into())),
            port: port.unwrap_or(80),
            staging: staging.unwrap_or(false),
        })
    }

    pub(crate) fn cert_file(&self) -> PathBuf {
        self.dir.join(format!("{}.crt", self.domain))
    }

    pub(crate) fn key_file(&self) -> PathBuf {
        self.dir.join(format!("{}.key", self.domain))
    }

    pub(crate) fn account_file(&self) -> PathBuf {
        self.dir.join(if self.staging {
            "account-staging.json"
        } else {
            "account.json"
        })
    }

    pub(crate) fn directory(&self) -> &'static str {
        if self.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        }
    }
}

pub struct Resolver {
    current: RwLock<Arc<CertifiedKey>>,
    real: RwLock<bool>,
}

impl Resolver {
    fn install(&self, ck: Arc<CertifiedKey>) {
        if let Ok(mut w) = self.current.write() {
            *w = ck;
        }
        if let Ok(mut w) = self.real.write() {
            *w = true;
        }
    }

    pub fn has_real_certificate(&self) -> bool {
        self.real.read().map(|r| *r).unwrap_or(false)
    }
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("real", &self.has_real_certificate())
            .finish()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.current.read().ok().map(|c| c.clone())
    }
}

pub fn start(cfg: &Acme) -> Result<Arc<Resolver>> {
    let (seed, cached) = match load(cfg) {
        Ok(Some(ck)) => (ck, true),
        Ok(None) => (self_signed(&cfg.domain)?, false),
        Err(e) => {
            warn!(
                "acme: cached certificate for {} unusable: {e:#}",
                cfg.domain
            );
            (self_signed(&cfg.domain)?, false)
        }
    };
    let resolver = Arc::new(Resolver {
        current: RwLock::new(seed),
        real: RwLock::new(cached),
    });
    if cached {
        info!("acme: serving the cached certificate for {}", cfg.domain);
    } else {
        info!(
            "acme: no certificate for {} yet, serving a self-signed one until one is issued",
            cfg.domain
        );
    }
    tokio::spawn(keep(cfg.clone(), resolver.clone()));
    Ok(resolver)
}

async fn keep(cfg: Acme, resolver: Arc<Resolver>) {
    let mut backoff = RETRY_FIRST;
    loop {
        let left = match remaining(&cfg) {
            Ok(Some(d)) => Some(d),
            Ok(None) => None,
            Err(e) => {
                warn!("acme: reading the stored certificate failed: {e:#}");
                None
            }
        };
        let due = !matches!(left, Some(d) if d > RENEW_BEFORE);
        if due {
            match issue(&cfg).await {
                Ok(ck) => {
                    resolver.install(ck);
                    backoff = RETRY_FIRST;
                    info!("acme: certificate for {} installed", cfg.domain);
                }
                Err(e) => {
                    warn!(
                        "acme: could not get a certificate for {}: {e:#} — trying again in {} \
                         minutes. A certificate authority counts failures against the name, so \
                         each attempt waits longer than the last.",
                        cfg.domain,
                        backoff.as_secs() / 60
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RETRY_MAX);
                    continue;
                }
            }
        } else if let Some(d) = left {
            info!(
                "acme: certificate for {} is good for {} more days",
                cfg.domain,
                d.as_secs() / 86400
            );
        }
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

pub(crate) fn remaining(cfg: &Acme) -> Result<Option<Duration>> {
    let path = cfg.cert_file();
    if !path.exists() {
        return Ok(None);
    }
    let pem = std::fs::read_to_string(&path).with_context(|| format!("reading {path:?}"))?;
    let Some(der) = pem_blocks(&pem, "CERTIFICATE").into_iter().next() else {
        return Ok(None);
    };
    let (_, cert) =
        x509_parser::parse_x509_certificate(&der).context("parsing the stored certificate")?;
    Ok(cert
        .validity()
        .time_to_expiration()
        .map(|d| Duration::from_secs(u64::try_from(d.whole_seconds().max(0)).unwrap_or_default())))
}

fn load(cfg: &Acme) -> Result<Option<Arc<CertifiedKey>>> {
    let (cert_path, key_path) = (cfg.cert_file(), cfg.key_file());
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }
    let cert_pem =
        std::fs::read_to_string(&cert_path).with_context(|| format!("reading {cert_path:?}"))?;
    let key_pem =
        std::fs::read_to_string(&key_path).with_context(|| format!("reading {key_path:?}"))?;
    Ok(Some(certified(&cert_pem, &key_pem)?))
}

async fn issue(cfg: &Acme) -> Result<Arc<CertifiedKey>> {
    std::fs::create_dir_all(&cfg.dir)
        .with_context(|| format!("creating the acme directory {:?}", cfg.dir))?;
    restrict(&cfg.dir, 0o700)?;

    let account = account(cfg).await?;
    let identifier = Identifier::Dns(cfg.domain.clone());
    let mut order = account
        .new_order(&NewOrder::new(std::slice::from_ref(&identifier)))
        .await
        .context("asking the certificate authority for an order")?;

    let answers: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let listener = TcpListener::bind(("0.0.0.0", cfg.port))
        .await
        .with_context(|| {
            format!(
                "binding port {} for the http-01 challenge — it must be free and reachable from the internet",
                cfg.port
            )
        })?;
    let server = tokio::spawn(serve(listener, answers.clone()));

    let outcome = run_order(&mut order, &answers).await;
    server.abort();
    outcome?;

    let key_pem = order
        .finalize()
        .await
        .context("finalizing the certificate order")?;
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("collecting the issued certificate")?;

    write_private(&cfg.key_file(), &key_pem)?;
    std::fs::write(cfg.cert_file(), &cert_pem)
        .with_context(|| format!("writing {:?}", cfg.cert_file()))?;
    certified(&cert_pem, &key_pem)
}

async fn run_order(
    order: &mut instant_acme::Order,
    answers: &Arc<RwLock<HashMap<String, String>>>,
) -> Result<()> {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("reading an authorization")?;
        if authz.status != AuthorizationStatus::Pending {
            continue;
        }
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .context("the authority offered no http-01 challenge")?;
        let token = challenge.token.to_string();
        let key_auth = challenge.key_authorization().as_str().to_string();
        if let Ok(mut w) = answers.write() {
            w.insert(token, key_auth);
        }
        challenge
            .set_ready()
            .await
            .context("telling the authority the challenge is ready")?;
    }
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("waiting for the authority to check the challenge")?;
    if status != OrderStatus::Ready {
        bail!("the authority did not accept the challenge (order is {status:?}); check that port 80 reaches this host and that the name points here");
    }
    Ok(())
}

async fn account(cfg: &Acme) -> Result<Account> {
    let path = cfg.account_file();
    if path.exists() {
        let stored = std::fs::read_to_string(&path).with_context(|| format!("reading {path:?}"))?;
        let creds: AccountCredentials =
            serde_json::from_str(&stored).with_context(|| format!("parsing {path:?}"))?;
        return Account::builder()?
            .from_credentials(creds)
            .await
            .context("restoring the stored acme account");
    }
    let contact: Vec<String> = cfg
        .email
        .iter()
        .map(|e| format!("mailto:{}", e.trim()))
        .collect();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            cfg.directory().to_owned(),
            None,
        )
        .await
        .context("registering an account with the certificate authority")?;
    let json = serde_json::to_string(&credentials).context("serializing the acme account")?;
    write_private(&path, &json)?;
    info!("acme: registered a new account, stored in {path:?}");
    Ok(account)
}

async fn serve(listener: TcpListener, answers: Arc<RwLock<HashMap<String, String>>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let answers = answers.clone();
        tokio::spawn(async move {
            let _ = answer(stream, answers).await;
        });
    }
}

async fn answer(
    mut stream: TcpStream,
    answers: Arc<RwLock<HashMap<String, String>>>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let path = head
        .split_whitespace()
        .nth(1)
        .filter(|p| p.starts_with(CHALLENGE_PATH))
        .map(|p| p[CHALLENGE_PATH.len()..].to_string());
    let body = path.and_then(|t| answers.read().ok().and_then(|a| a.get(&t).cloned()));
    let response = match body {
        Some(b) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
    };
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

fn certified(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>> {
    let certs: Vec<CertificateDer<'static>> = pem_blocks(cert_pem, "CERTIFICATE")
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if certs.is_empty() {
        bail!("no CERTIFICATE block in the issued chain");
    }
    let key = private_key(key_pem)?;
    let signing = tls::provider()
        .key_provider
        .load_private_key(key)
        .context("loading the certificate's private key")?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    if let Some(d) = pem_blocks(pem, "PRIVATE KEY").into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(d.into()));
    }
    if let Some(d) = pem_blocks(pem, "EC PRIVATE KEY").into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(d.into()));
    }
    if let Some(d) = pem_blocks(pem, "RSA PRIVATE KEY").into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(d.into()));
    }
    bail!("no private key block in the issued key")
}

fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    use base64::prelude::{Engine, BASE64_STANDARD};
    let (begin, end) = (
        format!("-----BEGIN {label}-----"),
        format!("-----END {label}-----"),
    );
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(s) = rest.find(&begin) {
        let after = &rest[s + begin.len()..];
        let Some(e) = after.find(&end) else { break };
        let b64: String = after[..e].split_whitespace().collect();
        if let Ok(der) = BASE64_STANDARD.decode(b64.as_bytes()) {
            out.push(der);
        }
        rest = &after[e + end.len()..];
    }
    out
}

fn self_signed(domain: &str) -> Result<Arc<CertifiedKey>> {
    let ck = rcgen::generate_simple_self_signed(vec![domain.to_string()])
        .context("generating a placeholder certificate")?;
    let certs = vec![ck.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let signing = tls::provider()
        .key_provider
        .load_private_key(key)
        .context("loading the placeholder key")?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

fn write_private(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
        restrict(parent, 0o700)?;
    }
    std::fs::write(path, body).with_context(|| format!("writing {path:?}"))?;
    restrict(path, 0o600)
}

fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("restricting {path:?}"))
}

#[cfg(test)]
#[path = "../tests/unit/acme.rs"]
mod tests;
