use crate::Acme;
use serde::de::DeserializeOwned;
use std::borrow::Borrow;
use std::error::Error;
use std::marker::PhantomData;

pub trait HttpClient<R: Response<E>, E: Error> {
    async fn get_request(&self, url: impl AsRef<str>) -> Result<R, E>;
}

pub trait Response<E: Error> {
    fn status_code(&self) -> u16;
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
