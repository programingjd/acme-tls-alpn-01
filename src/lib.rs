pub extern crate rcgen;
#[cfg(feature = "reqwest")]
pub extern crate reqwest;

use crate::account::AccountMaterial;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::Result;
use crate::order::LocatedOrder;
use crate::resolver::CertResolver;
use rustls::sign::CertifiedKey;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;

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

#[cfg(test)]
pub(crate) static INIT: std::sync::Once = std::sync::Once::new();

#[cfg(feature = "reqwest")]
#[derive(Default)]
pub struct Acme<R = reqwest::Response, C = reqwest::Client>
where
    R: Response,
    C: HttpClient<R> + Default,
{
    _r: std::marker::PhantomData<R>,
    client: C,
    domains: Vec<String>,
    pub resolver: Arc<CertResolver>,
}

#[cfg(all(test, feature = "reqwest"))]
impl Acme<reqwest::Response, reqwest::Client> {
    pub(crate) fn empty() -> Self {
        Self {
            _r: std::marker::PhantomData,
            client: reqwest::Client::default(),
            domains: Vec::default(),
            resolver: Arc::new(CertResolver::default()),
        }
    }
}

#[cfg(not(feature = "reqwest"))]
#[derive(Default)]
pub struct Acme<R, C>
where
    R: Response,
    C: HttpClient<R> + Default,
{
    _r: std::marker::PhantomData<R>,
    client: C,
    domains: Vec<String>,
    pub resolver: Arc<CertResolver>,
}

impl<C: HttpClient<R> + Default, R: Response> Acme<R, C> {
    pub fn from_domain_keys(
        domain_names: impl Iterator<Item = (impl Into<String>, Option<CertifiedKey>)>,
    ) -> Self {
        Self::from_client_and_domain_keys(C::default(), domain_names)
    }
    pub fn from_domain_names(domain_names: impl Iterator<Item = impl Into<String>>) -> Self {
        Self::from_domain_keys(domain_names.into_iter().map(|it| (it, None)))
    }
}

impl<C: HttpClient<R> + Default, R: Response> Deref for Acme<R, C> {
    type Target = CertResolver;

    fn deref(&self) -> &Self::Target {
        &self.resolver
    }
}

impl<C: HttpClient<R> + Default, R: Response> Acme<R, C> {
    /// Retrieve the ACME directory at the specified url.
    pub async fn directory(&self, directory_url: impl AsRef<str> + Debug) -> Result<Directory> {
        Directory::from(directory_url, &self.client).await
    }
    /// Create a new account with the specified contact email.
    pub async fn new_account(
        &self,
        contact_email: impl AsRef<str>,
        directory: &Directory,
    ) -> Result<AccountMaterial> {
        AccountMaterial::from(contact_email, directory, &self.client).await
    }
    /// Request a new certificate and update the resolver.
    pub async fn request_certificates(
        &mut self,
        account: &AccountMaterial,
        directory: &Directory,
    ) -> Result<String> {
        LocatedOrder::new_order(self.domains.iter(), account, directory, &self.client)
            .await?
            .process(account, directory, &self.resolver, &self.client)
            .await
    }
}
