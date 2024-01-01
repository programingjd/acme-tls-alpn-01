use crate::errors::Result;
use crate::resolver::{create_self_signed_certificate, CertResolver, DomainResolver};
use crate::Acme;
use rustls::sign::CertifiedKey;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::borrow::Borrow;
use std::marker::PhantomData;
use std::sync::Arc;

#[allow(async_fn_in_trait)]
pub trait HttpClient<R: Response> {
    async fn get_request(&self, url: impl AsRef<str>) -> Result<R>;
    async fn post_jose(&self, url: impl AsRef<str>, body: impl Borrow<Value>) -> Result<R>;
}

#[allow(async_fn_in_trait)]
pub trait Response {
    fn status_code(&self) -> u16;
    fn is_success(&self) -> bool;
    fn header_value(&self, header_name: impl AsRef<str>) -> Option<String>;
    async fn body_as_json<T: DeserializeOwned>(self) -> Result<T>;
    async fn body_as_text(self) -> Result<String>;
    async fn body_as_bytes(self) -> Result<impl Borrow<[u8]>>;
}

impl<C: HttpClient<R>, R: Response> Acme<R, C> {
    pub fn from_client_and_domain_keys(
        client: C,
        domain_names: impl Iterator<Item = (&'static str, Option<CertifiedKey>)>,
    ) -> Self {
        let (resolver, mut writer) = CertResolver::create();
        let mut domains = Vec::new();
        domain_names.for_each(|(domain, it)| {
            domains.push(domain);
            writer.guard().insert(
                domain,
                DomainResolver {
                    key: Arc::new(it.unwrap_or_else(|| create_self_signed_certificate(domain))),
                    challenge_key: None,
                    notifier: None,
                },
            );
        });
        Self {
            client,
            _r: PhantomData,
            domains,
            resolver,
            writer,
        }
    }
}
