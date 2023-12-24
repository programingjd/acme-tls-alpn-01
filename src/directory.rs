use crate::client::{HttpClient, Response};
use crate::errors::{Error, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Directory {
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    #[serde(rename = "newAuthz")]
    new_authz: String,
    #[serde(rename = "revokeCert")]
    revoke_cert: String,
    #[serde(rename = "keyChange")]
    key_change: String,
}

impl Directory {
    pub(crate) async fn from<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        directory_url: impl AsRef<str>,
        client: &C,
    ) -> Result<Self> {
        let directory_url = directory_url.as_ref();
        let a = client
            .get(directory_url)
            .await
            .map_err(|_| Error::fetch_directory_error(directory_url))?;
        a.body_as_json::<Directory>()
            .await
            .map_err(|_| Error::fetch_directory_error(directory_url))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::letsencrypt::LetsEncrypt;
    use crate::Acme;

    #[tokio::test]
    async fn letsencrypt() {
        let acme = Acme::default();
        let directory = acme
            .directory(LetsEncrypt::ProductionEnvironment.directory_url())
            .await
            .unwrap();
        assert_eq!(
            directory.new_account,
            format!(
                "https://{}/acme/new-acct",
                LetsEncrypt::ProductionEnvironment.domain()
            )
        );
    }
}
