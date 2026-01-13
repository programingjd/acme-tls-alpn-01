use acme_tls_alpn_01::letsencrypt::LetsEncrypt;
use acme_tls_alpn_01::Acme;
use clap::error::ErrorKind;
use clap::{Arg, ArgAction, ArgGroup, Command};
use rustls::crypto;
use std::env::args;
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
    let mut cmd = Command::new(env!("CARGO_BIN_NAME"))
        .bin_name(env!("CARGO_BIN_NAME"))
        .no_binary_name(false)
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("prod")
                .long("prod")
                .alias("production")
                .help("Use production environment")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("staging")
                .long("staging")
                .help("Use staging environment (default)")
                .action(ArgAction::SetTrue)
                .default_value("true"),
        )
        .arg(
            Arg::new("directory")
                .long("directory")
                .help("Use a custom directory URL")
                .value_name("url")
                .num_args(1),
        )
        .arg(
            Arg::new("email")
                .long("email")
                .help("Contact email")
                .value_name("email")
                .num_args(1),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("very_verbose")
                .visible_alias("vv") // allows -vv
                .long("very-verbose")
                .help("Enable very verbose output")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("domains")
                .help("Domain names")
                .num_args(1..)
                .required(true),
        )
        .group(
            ArgGroup::new("environment")
                .args(["prod", "staging", "directory"])
                .multiple(false),
        );
    let matches = match cmd.try_get_matches_from_mut(args()) {
        Ok(matches) => matches,
        Err(err) => match err.kind() {
            ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => err.exit(),
            err => {
                eprintln!("{err}");
                cmd.print_help()?;
                std::process::exit(2);
            }
        },
    };
    let domain_names = matches.get_many::<String>("domains");

    let env_filter = if matches.get_flag("very_verbose") {
        "acme_tls_alpn_01=trace,reqwest=warn,tokio_rustls=warn,rustls=warn,off"
    } else if matches.get_flag("verbose") {
        "acme_tls_alpn_01=debug,reqwest=error,tokio_rustls=error,rustls=error,off"
    } else {
        "acme_tls_alpn_01=warn,off"
    };

    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(env_filter)
        .without_time()
        .with_line_number(false)
        .try_init()
        .expect("could not init env filter");

    let domain_name: String = std::env::var("DOMAIN_NAME")
        .unwrap_or("tunnel.programingjd.me".to_string())
        // .expect("DOMAIN_NAME not set")
        .to_string();
    let https_listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 443)).await?;
    crypto::ring::default_provider()
        .install_default()
        .map_err(|_err| {
            std::io::Error::other("Could not install ring as default crypto provider.")
        })?;
    let mut acme = Acme::<reqwest::Response, reqwest::Client>::from_domain_names(
        vec![domain_name].into_iter(),
    );
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
                            eprintln!("Failed to start TLS handshake\n{err:?}");
                        }
                    }
                }
                Err(err) => eprintln!("Failed to accept TCP connection\n{err:?}"),
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
