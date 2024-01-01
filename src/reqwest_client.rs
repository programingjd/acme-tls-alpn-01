use crate::client::{HttpClient, Response};
use crate::errors::{ErrorKind, Result};
use crate::Acme;
use futures_timer::Delay;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::any::type_name;
use std::borrow::Borrow;
use std::time::Duration;

impl HttpClient<reqwest::Response> for Client {
    async fn get_request(&self, url: impl AsRef<str>) -> Result<reqwest::Response> {
        let mut retry_count = 0;
        loop {
            match self.get(url.as_ref()).send().await {
                Ok(response) => match response.status_code() {
                    429 => return Err(ErrorKind::TooManyRequests.into()),
                    503 | 504 => {
                        let delay: u64 = match retry_count {
                            0 => 5,
                            1 => 30,
                            2 => 120,
                            3 => 600,
                            _ => return Err(ErrorKind::ServiceUnavailable.into()),
                        };
                        retry_count += 1;
                        Delay::new(Duration::from_secs(delay)).await;
                    }
                    _ => return Ok(response),
                },
                Err(_) => {
                    let delay: u64 = match retry_count {
                        0 => 1,
                        1 => 5,
                        2 => 30,
                        3 => 120,
                        _ => return Err(ErrorKind::ConnectionError.into()),
                    };
                    retry_count += 1;
                    Delay::new(Duration::from_secs(delay)).await;
                }
            }
        }
    }
    async fn post_jose(
        &self,
        url: impl AsRef<str>,
        body: impl Borrow<Value>,
    ) -> Result<reqwest::Response> {
        let mut headers = HeaderMap::new();
        let _ = headers.insert(
            "content-type",
            HeaderValue::from_static("application/jose+json"),
        );
        let mut retry_count = 0;
        loop {
            match self
                .post(url.as_ref())
                .json(body.borrow())
                .headers(headers.clone())
                .send()
                .await
            {
                Ok(response) => match response.status_code() {
                    429 => return Err(ErrorKind::TooManyRequests.into()),
                    503 | 504 => {
                        let delay: u64 = match retry_count {
                            0 => 5,
                            1 => 30,
                            2 => 120,
                            3 => 600,
                            _ => return Err(ErrorKind::ServiceUnavailable.into()),
                        };
                        retry_count += 1;
                        Delay::new(Duration::from_secs(delay)).await;
                    }
                    _ => return Ok(response),
                },
                Err(_) => {
                    let delay: u64 = match retry_count {
                        0 => 1,
                        1 => 5,
                        2 => 30,
                        3 => 120,
                        _ => return Err(ErrorKind::ConnectionError.into()),
                    };
                    retry_count += 1;
                    Delay::new(Duration::from_secs(delay)).await;
                }
            }
        }
    }
}

impl Response for reqwest::Response {
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
    async fn body_as_json<T: DeserializeOwned>(self) -> Result<T> {
        self.json::<T>().await.map_err(|_| {
            ErrorKind::DeserializationError {
                type_name: type_name::<T>().to_string(),
            }
            .into()
        })
    }
    async fn body_as_text(self) -> Result<String> {
        self.text()
            .await
            .map_err(|_| ErrorKind::ConnectionError.into())
    }
    async fn body_as_bytes(self) -> Result<impl Borrow<[u8]>> {
        self.bytes()
            .await
            .map_err(|_| ErrorKind::ConnectionError.into())
    }
}

impl Default for Acme<reqwest::Response, Client> {
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
