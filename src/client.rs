use crate::errors::Result;
use crate::Acme;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::borrow::Borrow;
use std::marker::PhantomData;

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
    pub fn new(client: C) -> Self {
        Self {
            client,
            _r: PhantomData,
        }
    }
}
