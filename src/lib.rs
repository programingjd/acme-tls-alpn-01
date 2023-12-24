use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::Result;
use std::error::Error;

mod client;
mod directory;
mod errors;
mod letsencrypt;

#[cfg(feature = "reqwest")]
mod reqwest_client;
#[cfg(feature = "reqwest")]
pub extern crate reqwest;

#[cfg(feature = "reqwest")]
pub struct Acme<R, E, C = reqwest::Client>
where
    E: Error,
    R: Response<E>,
    C: HttpClient<R, E>,
{
    client: C,
}

#[cfg(not(feature = "reqwest"))]
pub struct Acme<R, E, C>
where
    E: Error,
    R: Response<E>,
    C: HttpClient<R, E>,
{
    client: C,
}

impl<C: HttpClient<R, E>, R: Response<E>, E: Error> Acme<R, E, C> {
    pub async fn directory(&self, directory_url: impl AsRef<str>) -> Result<Directory> {
        Directory::from(directory_url, &self.client).await
    }
}
