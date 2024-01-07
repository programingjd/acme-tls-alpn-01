use crate::client::{HttpClient, Response};
use crate::errors::{Error, ErrorKind, Result};
use serde::Deserialize;
use std::fmt::Debug;
#[cfg(feature = "tracing")]
use tracing::debug;

/// [RFC 8555 Directory](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1)
#[derive(Debug, Deserialize)]
pub struct Directory {
    #[serde(rename = "newAccount")]
    pub(crate) new_account: String,
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newOrder")]
    pub(crate) new_order: String,
    // #[serde(rename = "revokeCert")]
    // revoke_cert: String,
    #[serde(rename = "keyChange")]
    pub(crate) key_change: String,
}

impl Directory {
    /// [RFC 8555 Directory](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.1)
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "get_directory",
        skip(client),
        level = tracing::Level::TRACE,
        ret(level = tracing::Level::TRACE),
        err(level = tracing::Level::WARN)
    )]
    pub(crate) async fn from<C: HttpClient<R>, R: Response>(
        directory_url: impl AsRef<str> + Debug,
        client: &C,
    ) -> Result<Self> {
        let directory_url = directory_url.as_ref();
        let response = client.get_request(directory_url).await.map_err(|err| {
            ErrorKind::FetchDirectory {
                url: directory_url.to_string(),
            }
            .wrap(err)
        })?;
        if response.is_success() {
            response.body_as_json::<Directory>().await.map_err(|err| {
                ErrorKind::FetchDirectory {
                    url: directory_url.to_string(),
                }
                .wrap(err)
            })
        } else {
            #[cfg(feature = "tracing")]
            if let Ok(text) = response.body_as_text().await {
                debug!(body = ?text);
            }
            #[cfg(not(feature = "tracing"))]
            let _ = response.body_as_text();
            Err(ErrorKind::FetchDirectory {
                url: directory_url.to_string(),
            }
            .into())
        }
    }
    /// [RFC 8555 Nonce](https://datatracker.ietf.org/doc/html/rfc8555#section-7.2)
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "new_nonce",
        skip(client),
        level = tracing::Level::TRACE,
        ret(level = tracing::Level::TRACE),
        err(level = tracing::Level::WARN)
    )]
    pub(crate) async fn new_nonce<C: HttpClient<R>, R: Response>(
        &self,
        client: &C,
    ) -> Result<String> {
        let nounce_url = &self.new_nonce;
        let response = client
            .get_request(nounce_url)
            .await
            .map_err(|err| ErrorKind::NewNonce.wrap(err))?;
        if response.is_success() {
            let nonce = response
                .header_value("replay-nonce")
                .ok_or::<Error>(ErrorKind::NewNonce.into())?;
            let _ = response.body_as_bytes().await;
            Ok(nonce)
        } else {
            #[cfg(feature = "tracing")]
            if let Ok(text) = response.body_as_text().await {
                debug!(body = ?text);
            }
            #[cfg(not(feature = "tracing"))]
            let _ = response.body_as_text();
            Err(ErrorKind::NewNonce.into())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::directory::Directory;
    use crate::letsencrypt::LetsEncrypt;
    use crate::Acme;
    use serde_json::json;
    use test_tracing::test;

    #[test]
    fn test_deserialization() {
        let json = serde_json::to_string_pretty(&json!({
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "newAuthz": "https://example.com/acme/new-authz",
            "revokeCert": "https://example.com/acme/revoke-cert",
            "keyChange": "https://example.com/acme/key-change",
            "meta": {
                "termsOfService": "https://example.com/acme/terms/2017-5-30",
                "website": "https://www.example.com/",
                "caaIdentities": ["example.com"],
                "externalAccountRequired": false
            }
        }))
        .unwrap();
        let deserialized = serde_json::from_str::<Directory>(json.as_str()).unwrap();
        assert_eq!(deserialized.new_nonce, "https://example.com/acme/new-nonce");
        assert_eq!(
            deserialized.new_account,
            "https://example.com/acme/new-account"
        );
        assert_eq!(deserialized.new_order, "https://example.com/acme/new-order");
        assert_eq!(
            deserialized.key_change,
            "https://example.com/acme/key-change"
        );
    }

    #[test(tokio::test)]
    async fn invalid_url() {
        let acme = Acme::empty();
        assert!(acme
            .directory("https://nonexisting.org/acme")
            .await
            .is_err());
    }

    async fn letsencrypt(environment: &LetsEncrypt) {
        let acme = Acme::empty();
        let directory = acme.directory(environment.directory_url()).await.unwrap();
        assert_eq!(
            directory.new_account,
            format!("https://{}/acme/new-acct", environment.domain())
        );
        assert_eq!(
            directory.new_nonce,
            format!("https://{}/acme/new-nonce", environment.domain())
        );
        assert_eq!(
            directory.new_order,
            format!("https://{}/acme/new-order", environment.domain())
        );
        assert_eq!(
            directory.key_change,
            format!("https://{}/acme/key-change", environment.domain())
        );
    }

    #[test(tokio::test)]
    async fn letsencrypt_production() {
        letsencrypt(&LetsEncrypt::ProductionEnvironment).await
    }

    #[test(tokio::test)]
    async fn letsencrypt_staging() {
        letsencrypt(&LetsEncrypt::StagingEnvironment).await
    }

    #[test(tokio::test)]
    async fn new_nonce() {
        let acme = Acme::empty();
        let directory = acme
            .directory(LetsEncrypt::default().directory_url())
            .await
            .unwrap();
        let nonce = directory.new_nonce(&acme.client).await.unwrap();
        assert!(nonce.len() > 0)
    }
}
