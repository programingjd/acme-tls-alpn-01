use crate::client::{HttpClient, Response};
use crate::Acme;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::borrow::Borrow;

impl HttpClient<reqwest::Response, reqwest::Error> for Client {
    async fn get_request(&self, url: impl AsRef<str>) -> Result<reqwest::Response, reqwest::Error> {
        self.get(url.as_ref()).send().await
    }
    async fn post_jose(
        &self,
        url: impl AsRef<str>,
        body: impl Borrow<Value>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut headers = HeaderMap::new();
        let _ = headers.insert(
            "content-type",
            HeaderValue::from_static("application/jose+json"),
        );
        self.post(url.as_ref())
            .json(body.borrow())
            .headers(headers)
            .send()
            .await
    }
}

impl Response<reqwest::Error> for reqwest::Response {
    fn status_code(&self) -> u16 {
        self.status().as_u16()
    }
    fn is_success(&self) -> bool {
        self.status().is_success()
    }
    fn header_value(&self, header_name: impl AsRef<str>) -> Option<String> {
        self.headers()
            .get(header_name.as_ref())
            .and_then(|it| it.to_str().map(|it| it.to_string()).ok())
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

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_text() {
        let client = init_client();
        let response = client.get_request("https://www.example.com").await.unwrap();
        let text = response.text().await.unwrap();
        assert!(text.starts_with("<!doctype html>"))
    }
}
