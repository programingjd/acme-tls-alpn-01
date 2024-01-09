use acme_tls_alpn_01::letsencrypt::LetsEncrypt;
use acme_tls_alpn_01::Acme;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::io::{copy, sink, split, AsyncWriteExt};
use tokio::join;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::rustls::version::TLS13;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::LazyConfigAcceptor;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter("acme_tls_alpn_01=trace")
        .without_time()
        .with_line_number(false)
        .try_init()
        .expect("could not init env filter");
    let domain_name: String = std::env::var("DOMAIN_NAME")
        .unwrap_or("tunnel.programingjd.me".to_string())
        // .expect("DOMAIN_NAME not set")
        .to_string();
    let https_listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 443)).await?;
    let mut acme = Acme::from_domain_names(vec![domain_name].into_iter());
    let resolver = acme.resolver.clone();
    let mut tls_config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];
    let tls_config = Arc::new(tls_config);
    let server = tokio::spawn(async move {
        loop {
            match https_listener.accept().await {
                Ok((tcp, _remote_addr)) => {
                    let mut acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp);
                    let config = tls_config.clone();
                    match (&mut acceptor).await {
                        Ok(start_handshake) => {
                            let mut is_challenge = false;
                            if let Ok(stream) = start_handshake
                                .into_stream_with(config, |conn| {
                                    is_challenge = conn.alpn_protocol() == Some(b"acme-tls/1")
                                })
                                .await
                            {
                                if is_challenge {
                                    handle_acme_challenge_request(stream).await;
                                } else {
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
    });
    let directory = acme
        .directory(LetsEncrypt::StagingEnvironment.directory_url())
        .await
        .unwrap();
    let account = acme
        .new_account("void@programingjd.me", &directory)
        .await
        .unwrap();
    let certificate = acme
        .request_certificates(&account, &directory)
        .await
        .unwrap();
    println!("{certificate}");
    let _ = server.await;
    Ok(())
}

async fn handle_acme_challenge_request(stream: TlsStream<TcpStream>) {
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
                        Connection: close\r\n\
                        Content-Length: 0\r\n\
                        \r\n\
                    ",
                )
                .await;
            writer
        }
    );
    let mut stream = reader.unsplit(writer);
    let _ = stream.shutdown().await;
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
