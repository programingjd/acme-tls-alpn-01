use crate::client::{HttpClient, Response};
use crate::errors::{Error, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Directory {
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    // #[serde(rename = "revokeCert")]
    // revoke_cert: Option<String>,
    // #[serde(rename = "keyChange")]
    // key_change: Option<String>,
}

impl Directory {
    pub(crate) async fn from<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        directory_url: impl AsRef<str>,
        client: &C,
    ) -> Result<Self> {
        let directory_url = directory_url.as_ref();
        let response = client
            .get_request(directory_url)
            .await
            .map_err(|_| Error::fetch_directory_error(directory_url))?;
        response
            .body_as_json::<Directory>()
            .await
            .map_err(|_| Error::fetch_directory_error(directory_url))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::letsencrypt::LetsEncrypt;
    use crate::Acme;

    async fn letsencrypt(environment: &LetsEncrypt) {
        let acme = Acme::default();
        let directory = acme.directory(environment.directory_url()).await.unwrap();
        #[cfg(debug_assertions)]
        println!("{directory:?}");
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
    }

    #[tokio::test]
    async fn letsencrypt_production() {
        letsencrypt(&LetsEncrypt::ProductionEnvironment).await
    }

    #[tokio::test]
    async fn letsencrypt_staging() {
        letsencrypt(&LetsEncrypt::StagingEnvironment).await
    }
}
