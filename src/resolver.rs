use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

#[derive(Debug)]
struct DomainResolver {
    domain: &'static str,
    key: RwLock<Arc<CertifiedKey>>,
    challenge_key: RwLock<Option<Arc<CertifiedKey>>>,
}

#[derive(Debug)]
struct CertResolver {
    map: BTreeMap<&'static str, DomainResolver>,
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            if let Some(resolver) = self.map.get(server_name) {
                return if client_hello
                    .alpn()
                    .and_then(|mut it| it.find(|&it| it == b"acme-tls/1"))
                    .is_some()
                {
                    resolver
                        .challenge_key
                        .read()
                        .ok()
                        .and_then(|lock| lock.as_ref().map(|key| key.clone()))
                } else {
                    resolver.key.read().ok().map(|key| key.clone())
                };
            }
        }
        None
    }
}
