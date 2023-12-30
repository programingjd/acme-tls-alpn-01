use crate::account::Account;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::Error::InvalidOrder;
use crate::errors::Result;
use crate::order::{Identifier, Order};
use std::error::Error;
use std::marker::PhantomData;

mod account;
mod client;
mod directory;
mod errors;
mod jose;
mod letsencrypt;

mod order;

#[cfg(feature = "reqwest")]
mod reqwest_client;
#[cfg(feature = "reqwest")]
pub extern crate reqwest;

pub extern crate rcgen;

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
    pub async fn request_certificates(
        &self,
        domain_names: impl Iterator<Item = impl Into<String>>,
        account: &Account,
        directory: &Directory,
    ) -> Result<()> {
        match Order::new_order(domain_names, account, directory, &self.client).await? {
            Order::Invalid { identifiers, .. } => Err(InvalidOrder {
                domains: identifiers
                    .iter()
                    .map(|it| match it {
                        Identifier::Dns(name) => name.clone(),
                    })
                    .collect(),
            }),
            Order::Ready { finalize, .. } => self.finalize(finalize).await,
            Order::Valid { certificate, .. } => self.download_certificate(certificate).await,
            // Order::Processing { .. } =>
            _ => Ok(()),
        }
    }
    async fn finalize(&self, url: String) -> Result<()> {
        todo!()
    }
    async fn download_certificate(&self, url: String) -> Result<()> {
        todo!()
    }
}
