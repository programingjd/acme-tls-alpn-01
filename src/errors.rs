use std::fmt::{write, Display, Formatter};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    FetchDirectory { url: String },
    NewNonce,
    NewAccount,
    DeserializeAccount,
    Csr { domains: Vec<String> },
    NewOrder,
    InvalidOrder { domains: Vec<String> },
    GetAuthorization,
    InvalidAuthorization,
    GetOrder,
    OrderProcessing,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FetchDirectory { ref url } => {
                write!(f, "could not fetch ACME directory at {url}")
            }
            Error::NewNonce => {
                write!(f, "could not get a new nonce")
            }
            Error::NewAccount => {
                write!(f, "could not get or create account")
            }
            Error::DeserializeAccount => {
                write!(f, "could not deserialize account")
            }
            Error::Csr { ref domains } => {
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
            Error::NewOrder => {
                write!(f, "could not get or create new order")
            }
            Error::InvalidOrder { ref domains } => {
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
            Error::GetAuthorization => {
                write!(f, "could not get authorization challenges")
            }
            Error::InvalidAuthorization => {
                write!(f, "invalid authorization")
            }
            Error::GetOrder => {
                write!(f, "could not get order")
            }
            Error::OrderProcessing => {
                write!(f, "order processing stalled")
            }
        }
    }
}
