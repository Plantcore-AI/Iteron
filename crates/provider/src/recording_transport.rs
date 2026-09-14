use crate::catalog::{HttpClient, HttpTransport};
use crate::{ProviderError, ProviderTransportTimeoutPolicy};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};

/// A release-recording-only Provider transport with one case-local trust root.
///
/// Construction parses the bounded PEM bytes supplied by the CLI. The resulting client disables
/// the built-in root set, keeps hostname and chain verification enabled, and refuses redirects so
/// the configured loopback origin remains the credential and prompt authority boundary.
pub struct RecordingProviderTransport {
    root: reqwest::Certificate,
}

impl std::fmt::Debug for RecordingProviderTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordingProviderTransport")
            .field("root", &"<case-local-ca>")
            .finish()
    }
}

impl RecordingProviderTransport {
    pub fn from_pem(pem: &[u8]) -> Result<Self, ProviderError> {
        let certificate = CertificateDer::from_pem_slice(pem).map_err(|_| {
            ProviderError::Configuration("recording_provider_ca_invalid_pem".into())
        })?;
        rustls::RootCertStore::empty()
            .add(certificate)
            .map_err(|_| {
                ProviderError::Configuration("recording_provider_ca_invalid_pem".into())
            })?;
        let root = reqwest::Certificate::from_pem(pem).map_err(|_| {
            ProviderError::Configuration("recording_provider_ca_invalid_pem".into())
        })?;
        Ok(Self { root })
    }
}

impl HttpTransport for RecordingProviderTransport {
    fn client(&self, policy: ProviderTransportTimeoutPolicy) -> Result<HttpClient, ProviderError> {
        let policy = policy.validate()?;
        let mut builder = reqwest::Client::builder()
            .connect_timeout(policy.connect_tls)
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.root.clone());
        if policy.connection_reuse {
            builder = builder
                .pool_idle_timeout(policy.pool_idle)
                .tcp_keepalive((!policy.tcp_keepalive.is_zero()).then_some(policy.tcp_keepalive));
        } else {
            builder = builder.pool_max_idle_per_host(0).tcp_keepalive(None);
        }
        builder.build().map_err(|_| {
            ProviderError::Configuration("recording_provider_http_client_invalid".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, date_time_ymd,
    };
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn invalid_pem_is_rejected_without_reflecting_bytes() {
        let secret_shaped = b"not-a-ca-private-material";
        let error = RecordingProviderTransport::from_pem(secret_shaped).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("recording_provider_ca_invalid_pem"));
        assert!(!rendered.contains("private-material"));
    }

    fn certificate_authority() -> (Certificate, KeyPair) {
        let mut parameters = CertificateParams::new(Vec::new()).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let certificate = parameters.self_signed(&key).unwrap();
        (certificate, key)
    }

    fn server_certificate(
        authority: &Certificate,
        authority_key: &KeyPair,
        subject_alt_name: &str,
        expired: bool,
    ) -> (Certificate, KeyPair) {
        let mut parameters = CertificateParams::new(vec![subject_alt_name.to_owned()]).unwrap();
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            parameters.not_before = date_time_ymd(2010, 1, 1);
            parameters.not_after = date_time_ymd(2011, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        let certificate = parameters
            .signed_by(&key, authority, authority_key)
            .unwrap();
        (certificate, key)
    }

    async fn tls_server(
        certificate: &Certificate,
        key: &KeyPair,
        response: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let configuration = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(configuration));
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut request = [0_u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request)).await;
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
        });
        (address, task)
    }

    fn test_policy() -> ProviderTransportTimeoutPolicy {
        ProviderTransportTimeoutPolicy {
            connect_tls: Duration::from_secs(2),
            request_total: Duration::from_secs(3),
            stream_idle: Duration::from_secs(2),
            pool_idle: Duration::from_secs(2),
            tcp_keepalive: Duration::from_secs(1),
            connection_reuse: true,
        }
    }

    #[tokio::test]
    async fn case_ca_preserves_chain_hostname_expiry_redirect_and_process_isolation() {
        const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        const REDIRECT: &[u8] = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (authority, authority_key) = certificate_authority();
        let transport = RecordingProviderTransport::from_pem(authority.pem().as_bytes()).unwrap();
        let client = transport.client(test_policy()).unwrap();

        let (certificate, key) = server_certificate(&authority, &authority_key, "127.0.0.1", false);
        let (address, server) = tls_server(&certificate, &key, OK).await;
        let response = client
            .get(format!("https://{address}/v1"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        server.await.unwrap();

        let (certificate, key) = server_certificate(&authority, &authority_key, "localhost", false);
        let (address, server) = tls_server(&certificate, &key, OK).await;
        assert!(
            client
                .get(format!("https://{address}/v1"))
                .send()
                .await
                .is_err()
        );
        server.await.unwrap();

        let (certificate, key) = server_certificate(&authority, &authority_key, "127.0.0.1", true);
        let (address, server) = tls_server(&certificate, &key, OK).await;
        assert!(
            client
                .get(format!("https://{address}/v1"))
                .send()
                .await
                .is_err()
        );
        server.await.unwrap();

        let (other_authority, _) = certificate_authority();
        let other_transport =
            RecordingProviderTransport::from_pem(other_authority.pem().as_bytes()).unwrap();
        let other_client = other_transport.client(test_policy()).unwrap();
        let (certificate, key) = server_certificate(&authority, &authority_key, "127.0.0.1", false);
        let (address, server) = tls_server(&certificate, &key, OK).await;
        assert!(
            other_client
                .get(format!("https://{address}/v1"))
                .send()
                .await
                .is_err()
        );
        server.await.unwrap();

        let (certificate, key) = server_certificate(&authority, &authority_key, "127.0.0.1", false);
        let (address, server) = tls_server(&certificate, &key, OK).await;
        assert!(
            reqwest::Client::new()
                .get(format!("https://{address}/v1"))
                .send()
                .await
                .is_err(),
            "the case-local CA must not alter an unrelated client"
        );
        server.await.unwrap();

        let (certificate, key) = server_certificate(&authority, &authority_key, "127.0.0.1", false);
        let (address, server) = tls_server(&certificate, &key, REDIRECT).await;
        let response = client
            .post(format!("https://{address}/v1"))
            .body("synthetic-body")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.unwrap();
    }
}
