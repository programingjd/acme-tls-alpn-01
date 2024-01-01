use std::net::Ipv6Addr;
use std::sync::{Arc, RwLock};
use tokio::io::{copy, sink, split, AsyncWriteExt};
use tokio::join;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::crypto::ring::sign::any_supported_type;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::version::TLS13;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::LazyConfigAcceptor;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let domain_name: &'static str = std::env::var("DOMAIN_NAME")
        .unwrap_or("localhost".to_string())
        // .expect("DOMAIN_NAME not set")
        .leak();
    let https_listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 443)).await?;
    let resolver = CertResolver {
        domain: domain_name,
        key: RwLock::new(Arc::new(
            restore_certificate(domain_name)
                .unwrap_or_else(|| create_self_signed_certificate(domain_name)),
        )),
        challenge_key: RwLock::new(None),
    };
    let mut tls_config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_config = Arc::new(tls_config);
    tokio::spawn(async move {
        loop {
            match https_listener.accept().await {
                Ok((tcp, _remote_addr)) => {
                    let mut acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp);
                    let config = tls_config.clone();
                    match (&mut acceptor).await {
                        Ok(start_handshake) => {
                            let client_hello = start_handshake.client_hello();
                            let server_name = client_hello.server_name();
                            if server_name.is_some_and(|name| name == domain_name) {
                                if let Ok(stream) = start_handshake.into_stream(config).await {
                                    handle_request(stream).await;
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("Failed to start TLS handshake\n{:?}", err);
                        }
                    }
                }
                Err(err) => eprintln!("Failed to accept TCP connection\n{:?}", err),
            }
        }
    })
    .await
    .unwrap();
    Ok(())
}

fn restore_certificate(_domain_name: &str) -> Option<CertifiedKey> {
    None
}

fn create_self_signed_certificate(domain_name: &str) -> CertifiedKey {
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

async fn handle_request(stream: TlsStream<TcpStream>) {
    let (mut reader, mut writer) = split(stream);
    let (reader, writer) = join!(
        async move {
            let _ = copy(&mut reader, &mut sink()).await;
            reader
        },
        async move {
            let _ = writer
                .write(
                    b"\
                        HTTP/1.1 200 OK\r\n\
                        Cache-Control: no-cache\r\n\
                        Connection: close\r\n\
                        Content-Type: text/plain;charset=UTF-8\r\n\
                        Content-Length: 2\r\n\
                        \r\n\
                        OK\
                    ",
                )
                .await;
            writer
        }
    );
    let mut stream = reader.unsplit(writer);
    let _ = stream.shutdown().await;
}

#[derive(Debug)]
struct CertResolver {
    domain: &'static str,
    key: RwLock<Arc<CertifiedKey>>,
    challenge_key: RwLock<Option<Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if client_hello.server_name() == Some(self.domain) {
            if client_hello
                .alpn()
                .and_then(|mut it| it.find(|&it| it == b"acme-tls/1"))
                .is_some()
            {
                self.challenge_key
                    .read()
                    .ok()
                    .and_then(|lock| lock.as_ref().cloned())
            } else {
                self.key.read().ok().map(|key| key.clone())
            }
        } else {
            None
        }
    }
}
