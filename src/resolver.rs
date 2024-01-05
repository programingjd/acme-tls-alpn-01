use flashmap::{ReadHandle, WriteHandle};
use flume::Sender;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::hash_map::RandomState;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

pub struct CertResolver {
    reader: ReadHandle<String, DomainResolver, RandomState>,
}

#[derive(Debug)]
pub(crate) struct DomainResolver {
    pub(crate) key: Arc<CertifiedKey>,
    pub(crate) challenge_key: Option<Arc<CertifiedKey>>,
    pub(crate) notifier: Option<Sender<String>>,
}

impl Debug for CertResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let view = self.reader.guard();
        let vec = view.iter().collect::<Vec<_>>();
        write!(f, "{vec:?}")
    }
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

impl CertResolver {
    pub(crate) fn create() -> (
        CertResolver,
        WriteHandle<String, DomainResolver, RandomState>,
    ) {
        let (writer, reader) = flashmap::new::<String, DomainResolver>();
        (CertResolver { reader }, writer)
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            if client_hello
                .alpn()
                .and_then(|mut it| it.find(|&it| it == b"acme-tls/1"))
                .is_some()
            {
                let guard = self.reader.guard();
                if let Some(resolver) = guard.get(server_name) {
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
                let guard = self.reader.guard();
                if let Some(resolver) = guard.get(server_name) {
                    Some(resolver.key.clone())
                } else {
                    None
                }
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
        vec![cert
            .serialize_der()
            .expect("failed to serialize certificate")
            .into()],
        any_supported_type(&PrivateKeyDer::Pkcs8(
            cert.serialize_private_key_der().into(),
        ))
        .expect("failed to generate signing key"),
    )
}
