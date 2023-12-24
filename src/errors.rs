use std::fmt::{Display, Formatter};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    FetchDirectory { url: String },
    GenerateAccountKeyPair,
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
            Error::GenerateAccountKeyPair => {
                write!(f, "Could not generate account key pair")
            }
        }
    }
}
