use flume::Sender;
use papaya::HashMap;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::fmt::Debug;
use std::sync::Arc;
#[cfg(feature = "tracing")]
use tracing::debug;

#[derive(Debug, Default)]
pub struct CertResolver {
    pub(crate) map: HashMap<String, DomainResolver>,
}

#[derive(Debug)]
pub(crate) struct DomainResolver {
    pub(crate) key: Arc<CertifiedKey>,
    pub(crate) challenge_key: Option<Arc<CertifiedKey>>,
    pub(crate) notifier: Option<Sender<String>>,
}

impl From<CertifiedKey> for DomainResolver {
    fn from(value: CertifiedKey) -> Self {
        Self {
            key: Arc::new(value),
            challenge_key: None,
            notifier: None,
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        #[cfg(feature = "tracing")]
        debug!("new TLS connection");
        if let Some(server_name) = client_hello.server_name() {
            #[cfg(feature = "tracing")]
            debug!(server_name = server_name);
            if client_hello
                .alpn()
                .and_then(|mut it| it.find(|&it| it == b"acme-tls/1"))
                .is_some()
            {
                #[cfg(feature = "tracing")]
                debug!("alpn challenge");
                if let Some(resolver) = self.map.pin().get(server_name) {
                    match &resolver.challenge_key {
                        Some(key) => {
                            if let Some(ref notifier) = resolver.notifier {
                                let _ = notifier.try_send(server_name.to_string());
                            }
                            Some(key.clone())
                        }
                        None => None,
                    }
                } else {
                    None
                }
            } else {
                self.map
                    .pin()
                    .get(server_name)
                    .map(|resolver| resolver.key.clone())
            }
        } else {
            None
        }
    }
}

pub(crate) fn create_self_signed_certificate(domain_name: &str) -> CertifiedKey {
    let cert = rcgen::generate_simple_self_signed(vec![domain_name.to_string()])
        .expect("failed to generate certificate");
    CertifiedKey::new(
        vec![cert.cert.der().to_vec().into()],
        any_supported_type(&PrivateKeyDer::Pkcs8(
            cert.signing_key.serialize_der().into(),
        ))
        .expect("failed to generate signing key"),
    )
}
