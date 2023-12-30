use crate::account::AccountMaterial;
use crate::challenge::Challenge;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::{Error, Result};
use crate::jose::jose;
use crate::order::Identifier;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "status")]
pub(crate) enum Authorization {
    #[serde(rename = "pending")]
    Pending {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    #[serde(rename = "valid")]
    Valid {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    #[serde(rename = "invalid")]
    Invalid {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    #[serde(rename = "revoked")]
    Revoked {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    #[serde(rename = "expired")]
    Expired {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
    #[serde(rename = "deactivated")]
    Deactivated {
        identifier: Identifier,
        challenges: Vec<Challenge>,
    },
}

impl Authorization {
    pub(crate) async fn authorize<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        url: impl AsRef<str>,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<Authorization> {
        let url = url.as_ref();
        let nonce = directory.new_nonce(client).await?;
        let body = jose(&account.keypair, None, Some(&account.kid), &nonce, url);
        let response = client
            .post_jose(url, &body)
            .await
            .map_err(|_| Error::GetAuthorization)?;
        if response.is_success() {
            response
                .body_as_json::<Authorization>()
                .await
                .map_err(|_| Error::GetAuthorization)
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(Error::GetAuthorization)
        }
    }
}
