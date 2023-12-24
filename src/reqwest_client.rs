use crate::client::{HttpClient, Response};
use crate::Acme;
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::borrow::Borrow;

impl HttpClient<reqwest::Response, reqwest::Error> for Client {
    async fn get(&self, url: impl AsRef<str>) -> Result<reqwest::Response, reqwest::Error> {
        self.get(url.as_ref()).send().await
    }
}

impl Response<reqwest::Error> for reqwest::Response {
    fn status_code(&self) -> u16 {
        self.status().as_u16()
    }

    async fn body_as_json<T: DeserializeOwned>(self) -> Result<T, reqwest::Error> {
        self.json::<T>().await
    }

    async fn body_as_text(self) -> Result<String, reqwest::Error> {
        self.text().await
    }

    async fn body_as_bytes(self) -> Result<impl Borrow<[u8]>, reqwest::Error> {
        self.bytes().await
    }
}

impl Default for Acme<reqwest::Response, reqwest::Error, Client> {
    fn default() -> Self {
        Acme::new(init_client())
    }
}

fn init_client() -> Client {
    Client::default()
}
