use std::fmt::{Display, Formatter};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    FetchDirectory { url: String },
    NewNonce,
    NewAccount,
    DeserializeAccount,
}

impl Error {
    pub(crate) fn fetch_directory_error(url: impl Into<String>) -> Self {
        Error::FetchDirectory { url: url.into() }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FetchDirectory { ref url } => {
                write!(f, "Could not fetch ACME directory at {url}")
            }
            Error::NewNonce => {
                write!(f, "Could not get a new nonce")
            }
            Error::NewAccount => {
                write!(f, "Could not get or create account")
            }
            Error::DeserializeAccount => {
                write!(f, "Could not deserialize account")
            }
        }
    }
}
