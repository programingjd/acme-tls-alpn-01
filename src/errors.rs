use crate::csr::Csr;
use std::fmt::{Debug, Display, Formatter};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    pub(crate) kind: ErrorKind,
    pub(crate) cause: Option<ErrorDetail>,
}

#[derive(Debug)]
pub enum ErrorDetail {
    Error(Box<Error>),
    Message(String),
}

#[derive(Debug)]
pub enum ErrorKind {
    ConnectionError,
    TooManyRequests,
    ServiceUnavailable,
    DeserializationError { type_name: String },
    FetchDirectory { url: String },
    InvalidKey,
    NewNonce,
    NewAccount,
    DeserializeAccount,
    GetAccount,
    ChangeAccountKey,
    Csr { domains: Vec<String> },
    NewOrder,
    InvalidOrder { domains: Vec<String> },
    GetAuthorization,
    InvalidAuthorization,
    GetOrder,
    FinalizeOrder,
    DownloadCertificate,
    OrderProcessing { csr: Csr },
}

impl From<ErrorKind> for Error {
    fn from(value: ErrorKind) -> Self {
        Self {
            kind: value,
            cause: None,
        }
    }
}

impl ErrorKind {
    pub fn wrap(self, err: Error) -> Error {
        Error {
            kind: self,
            cause: Some(ErrorDetail::Error(Box::new(err))),
        }
    }
    pub fn with_msg(self, msg: impl Into<String>) -> Error {
        Error {
            kind: self,
            cause: Some(ErrorDetail::Message(msg.into())),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = vec![
            Some(self.kind.to_string()),
            self.cause.as_ref().map(|it| it.to_string()),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(":\n");
        f.write_str(&message)
    }
}

impl Display for ErrorDetail {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorDetail::Error(err) => write!(f, "{}", err),
            ErrorDetail::Message(msg) => f.write_str(msg),
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::ConnectionError => {
                write!(f, "could not connect to acme server")
            }
            ErrorKind::TooManyRequests => {
                write!(f, "too many requests to acme server")
            }
            ErrorKind::ServiceUnavailable => {
                write!(f, "acme service not available")
            }
            ErrorKind::DeserializationError { type_name } => {
                write!(f, "failed to deserialize to {}", type_name)
            }
            ErrorKind::FetchDirectory { ref url } => {
                write!(f, "could not fetch ACME directory at {url}")
            }
            ErrorKind::InvalidKey => {
                write!(
                    f,
                    "invalid pkcs8 (the key should be ECDSA_P256_SHA256_FIXED_SIGNING)"
                )
            }
            ErrorKind::NewNonce => {
                write!(f, "could not get a new nonce")
            }
            ErrorKind::NewAccount => {
                write!(f, "could not create account")
            }
            ErrorKind::DeserializeAccount => {
                write!(f, "could not deserialize account")
            }
            ErrorKind::GetAccount => {
                write!(f, "could not get account")
            }
            ErrorKind::ChangeAccountKey => {
                write!(f, "could not change account key")
            }
            ErrorKind::Csr { ref domains } => {
                write!(
                    f,
                    "could not generate CSR for domains: {}",
                    domains
                        .iter()
                        .map(|it| format!("\"{}\"", it))
                        .collect::<Vec<String>>()
                        .join(", ")
                )
            }
            ErrorKind::NewOrder => {
                write!(f, "could not get or create new order")
            }
            ErrorKind::InvalidOrder { ref domains } => {
                write!(
                    f,
                    "invalid order for domains: {}",
                    domains
                        .iter()
                        .map(|it| format!("\"{}\"", it))
                        .collect::<Vec<String>>()
                        .join(", ")
                )
            }
            ErrorKind::GetAuthorization => {
                write!(f, "could not get authorization challenges")
            }
            ErrorKind::InvalidAuthorization => {
                write!(f, "invalid authorization")
            }
            ErrorKind::GetOrder => {
                write!(f, "could not get order")
            }
            ErrorKind::DownloadCertificate => {
                write!(f, "failed to download certificate")
            }
            ErrorKind::FinalizeOrder => {
                write!(f, "failed to finalize order")
            }
            ErrorKind::OrderProcessing { .. } => {
                write!(f, "order processing stalled")
            }
        }
    }
}
