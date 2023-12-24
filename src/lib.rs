use crate::account::Account;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::Result;
use std::error::Error;
use std::marker::PhantomData;

mod account;
mod client;
mod directory;
mod errors;
mod jose;
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
    _e: PhantomData<E>,
    _r: PhantomData<R>,
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
    pub async fn new_account(
        &self,
        contact_email: impl AsRef<str>,
        directory: &Directory,
    ) -> Result<Account> {
        Account::from(contact_email, directory, &self.client).await
    }
}
