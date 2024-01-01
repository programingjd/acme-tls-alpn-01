use crate::account::AccountMaterial;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::Result;
use crate::order::LocatedOrder;
use crate::resolver::{CertResolver, DomainResolver};
use flashmap::WriteHandle;
use rustls::sign::CertifiedKey;
use std::collections::hash_map::RandomState;
use std::marker::PhantomData;
use std::ops::Deref;

mod account;
mod authorization;
mod challenge;
mod client;
mod csr;
mod directory;
pub mod ecdsa;
mod errors;
mod jose;
pub mod letsencrypt;
mod order;
pub mod resolver;

#[cfg(feature = "reqwest")]
mod reqwest_client;
#[cfg(feature = "reqwest")]
pub extern crate reqwest;

pub extern crate rcgen;

#[cfg(feature = "reqwest")]
pub struct Acme<R, C = reqwest::Client>
where
    R: Response,
    C: HttpClient<R>,
{
    _r: PhantomData<R>,
    client: C,
    domains: Vec<String>,
    resolver: CertResolver,
    writer: WriteHandle<String, DomainResolver, RandomState>,
}

impl Acme<reqwest::Response, reqwest::Client> {
    pub fn from_domain_keys(
        domain_names: impl Iterator<Item = (impl Into<String>, Option<CertifiedKey>)>,
    ) -> Self {
        Self::from_client_and_domain_keys(reqwest::Client::default(), domain_names)
    }
}

#[cfg(not(feature = "reqwest"))]
pub struct Acme<R, E, C>
where
    E: Error,
    R: Response<E>,
    C: HttpClient<R, E>,
{
    client: C,
    domains: Vec<&'static str>,
    resolver: CertResolver,
    writer: WriteHandle<&'static str, DomainResolver, RandomState>,
}

impl<C: HttpClient<R>, R: Response> Deref for Acme<R, C> {
    type Target = CertResolver;

    fn deref(&self) -> &Self::Target {
        &self.resolver
    }
}

impl<C: HttpClient<R>, R: Response> Acme<R, C> {
    pub async fn directory(&self, directory_url: impl AsRef<str>) -> Result<Directory> {
        Directory::from(directory_url, &self.client).await
    }
    pub async fn new_account(
        &self,
        contact_email: impl AsRef<str>,
        directory: &Directory,
    ) -> Result<AccountMaterial> {
        AccountMaterial::from(contact_email, directory, &self.client).await
    }
    pub async fn request_certificates(
        &mut self,
        account: &AccountMaterial,
        directory: &Directory,
    ) -> Result<String> {
        LocatedOrder::new_order(self.domains.iter(), account, directory, &self.client)
            .await?
            .process(account, directory, &mut self.writer, &self.client)
            .await
    }
}
