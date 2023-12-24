use crate::errors::Error::FetchDirectoryError;
use std::fmt::{Display, Formatter};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    FetchDirectoryError { url: String },
}

impl Error {
    pub(crate) fn fetch_directory_error(url: impl Into<String>) -> Self {
        FetchDirectoryError { url: url.into() }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FetchDirectoryError { ref url } => {
                write!(f, "Could not fetch ACME directory at {url}")
            }
        }
    }
}
