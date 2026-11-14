//! Buffered target connections with a common interface for plaintext and TLS.

use anyhow::{Context, Result, bail};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Disable TLS.
    Disable,
    /// Use TLS if supported; otherwise permit plaintext.
    Prefer,
    /// Require TLS with certificate verification.
    Require,
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct Conn {
    io: Box<dyn Io>,
    buf: Vec<u8>,
    pos: usize,
    pub tls: bool,
}

impl Conn {
    pub async fn connect(addr: &str) -> Result<Self> {
        let s = TcpStream::connect(addr).await.with_context(|| format!("Cannot connect to {addr}"))?;
        // Disable Nagle to avoid delaying small sequential requests.
        s.set_nodelay(true)?;
        Ok(Conn { io: Box::new(s), buf: Vec::with_capacity(16 * 1024), pos: 0, tls: false })
    }

    /// Upgrade a negotiated connection to TLS.
    pub async fn upgrade(self, tls: &TlsConfig, host: &str) -> Result<Self> {
        if self.pos != self.buf.len() {
            bail!("Unexpected buffered data before TLS upgrade");
        }
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).context("Invalid TLS server name")?;
        let s = tokio_rustls::TlsConnector::from(tls.cfg.clone()).connect(name, self.io).await.context("TLS handshake failed")?;
        // Discard already-consumed pre-TLS buffers.
        let mut buf = self.buf;
        buf.clear();
        Ok(Conn { io: Box::new(s), buf, pos: 0, tls: true })
    }

    pub async fn write_all(&mut self, b: &[u8]) -> Result<()> {
        self.io.write_all(b).await?;
        Ok(())
    }

    /// Read until at least n unread bytes are available.
    pub async fn fill(&mut self, n: usize) -> Result<()> {
        if n > dbtap_core::journal::MAX_FIELD {
            bail!("Received message exceeds size limit");
        }
        while self.buf.len() - self.pos < n {
            if self.pos > 0 && self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            } else if self.pos > 64 * 1024 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            let want = (n - (self.buf.len() - self.pos)).max(16 * 1024);
            self.buf.reserve(want);
            if self.io.read_buf(&mut self.buf).await? == 0 {
                bail!("Peer closed the connection");
            }
        }
        Ok(())
    }

    pub fn peek(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    pub fn consume(&mut self, n: usize) {
        self.pos += n;
    }

    pub async fn read_u8(&mut self) -> Result<u8> {
        self.fill(1).await?;
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub async fn shutdown(&mut self) {
        let _ = self.io.shutdown().await;
    }
}

#[derive(Clone)]
pub struct TlsConfig {
    cfg: Arc<rustls::ClientConfig>,
}

impl TlsConfig {
    /// ca adds PEM trust roots; insecure bypasses verification for isolated tests.
    pub fn new(ca: Option<&str>, insecure: bool) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = ca {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            for c in CertificateDer::pem_file_iter(path).with_context(|| format!("open {path}"))? {
                roots.add(c?)?;
            }
        }
        let mut cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        if insecure {
            cfg.dangerous().set_certificate_verifier(Arc::new(NoVerify(
                rustls::crypto::CryptoProvider::get_default().cloned().context("No TLS crypto provider installed")?,
            )));
        }
        Ok(TlsConfig { cfg: Arc::new(cfg) })
    }
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Extract host from host:port, stripping IPv6 brackets.
pub fn host_of(addr: &str) -> &str {
    let h = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    h.trim_start_matches('[').trim_end_matches(']')
}
