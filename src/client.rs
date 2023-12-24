use crate::Acme;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::borrow::Borrow;
use std::error::Error;
use std::marker::PhantomData;

#[allow(async_fn_in_trait)]
pub trait HttpClient<R: Response<E>, E: Error> {
    async fn get_request(&self, url: impl AsRef<str>) -> Result<R, E>;
    async fn post_jose(&self, url: impl AsRef<str>, body: impl Borrow<Value>) -> Result<R, E>;
}

#[allow(async_fn_in_trait)]
pub trait Response<E: Error> {
    fn status_code(&self) -> u16;
    fn is_success(&self) -> bool;
    fn header_value(&self, header_name: impl AsRef<str>) -> Option<String>;
    async fn body_as_json<T: DeserializeOwned>(self) -> Result<T, E>;
    async fn body_as_text(self) -> Result<String, E>;
    async fn body_as_bytes(self) -> Result<impl Borrow<[u8]>, E>;
}

impl<C: HttpClient<R, E>, R: Response<E>, E: Error> Acme<R, E, C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            _e: PhantomData,
            _r: PhantomData,
        }
    }
}
