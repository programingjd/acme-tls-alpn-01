use crate::account::AccountMaterial;
use crate::challenge::Challenge;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::{ErrorKind, Result};
use crate::jose::jose;
use serde::Deserialize;
use std::fmt::Debug;
#[cfg(feature = "tracing")]
use tracing::debug;

/// [RFC 8555 Authorization](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.4)
#[derive(Deserialize, Debug)]
pub(crate) struct Authorization {
    pub(crate) identifier: crate::order::Identifier,
    pub(crate) challenges: Vec<Challenge>,
    #[serde(flatten)]
    pub(crate) status: AuthorizationStatus,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "status")]
pub(crate) enum AuthorizationStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "revoked")]
    Revoked,
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "deactivated")]
    Deactivated,
}

impl Authorization {
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "authorize",
        skip(account,directory,client),
        level = tracing::Level::DEBUG,
        ret(level = tracing::Level::DEBUG),
        err(level = tracing::Level::WARN)
    )]
    pub(crate) async fn authorize<C: HttpClient<R>, R: Response>(
        url: impl AsRef<str> + Debug,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<Authorization> {
        let url = url.as_ref();
        let nonce = directory.new_nonce(client).await?;
        let body = jose(
            &account.keypair,
            None,
            Some(&account.url),
            Some(&nonce),
            url,
        );
        let response = client
            .post_jose(url, &body)
            .await
            .map_err(|err| ErrorKind::GetAuthorization.wrap(err))?;
        if response.is_success() {
            response
                .body_as_json::<Authorization>()
                .await
                .map_err(|err| ErrorKind::GetAuthorization.wrap(err))
        } else {
            #[cfg(feature = "tracing")]
            if let Ok(text) = response.body_as_text().await {
                debug!(body = ?text);
            }
            #[cfg(not(feature = "tracing"))]
            let _ = response.body_as_text();
            Err(ErrorKind::GetAuthorization.into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::challenge::{ChallengeStatus, ChallengeType};
    use crate::letsencrypt::LetsEncrypt;
    use crate::order::{Identifier, LocatedOrder};
    use crate::Acme;
    use serde_json::json;
    use test_tracing::test;

    #[test]
    fn test_order_deserialization() {
        let json = serde_json::to_string_pretty(&json!({
            "status": "pending",
            "expires": "2016-01-02T14:09:30Z",
            "identifier": {
                "type": "dns",
                "value": "www.example.org"
            },
            "challenges": [
                {
                    "type": "http-01",
                    "url": "https://example.com/acme/chall/prV_B7yEyA4",
                    "status": "valid",
                    "token": "DGyRejmCefe7v4NfDGDKfA",
                    "validated": "2014-12-01T12:05:58.16Z"
                },
                {
                    "type": "dns-01",
                    "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
                    "status": "pending",
                    "token": "DGyRejmCefe7v4NfDGDKfA",
                },
                {
                    "type": "tls-alpn-01",
                    "url": "https://example.com/acme/chall/PCt92wr-oA",
                    "status": "pending",
                    "token": "DGyRejmCefe7v4NfDGDKfA"
                }
            ],
            "wildcard": false
        }))
        .unwrap();
        let deserialized = serde_json::from_str::<Authorization>(json.as_str()).unwrap();
        assert_eq!(deserialized.status, AuthorizationStatus::Pending);
        assert_eq!(
            deserialized.identifier,
            Identifier::Dns("www.example.org".to_string())
        );
        assert_eq!(deserialized.challenges.len(), 3);
        assert_eq!(
            deserialized.challenges[0],
            Challenge {
                url: "https://example.com/acme/chall/prV_B7yEyA4".to_string(),
                status: ChallengeStatus::Valid,
                token: "DGyRejmCefe7v4NfDGDKfA".to_string(),
                kind: ChallengeType::Http01,
            }
        );
        assert_eq!(
            deserialized.challenges[1],
            Challenge {
                url: "https://example.com/acme/chall/Rg5dV14Gh1Q".to_string(),
                status: ChallengeStatus::Pending,
                token: "DGyRejmCefe7v4NfDGDKfA".to_string(),
                kind: ChallengeType::Dns01,
            }
        );
        assert_eq!(
            deserialized.challenges[2],
            Challenge {
                url: "https://example.com/acme/chall/PCt92wr-oA".to_string(),
                status: ChallengeStatus::Pending,
                token: "DGyRejmCefe7v4NfDGDKfA".to_string(),
                kind: ChallengeType::TlsAlpn01
            }
        );
    }

    #[test(tokio::test)]
    async fn test_authorize() {
        let acme = Acme::from_domain_names(vec!["void.programingjd.me"].into_iter());
        let directory = Directory::from(
            LetsEncrypt::StagingEnvironment.directory_url(),
            &acme.client,
        )
        .await
        .unwrap();
        let account = acme
            .new_account("void@programingjd.me", &directory)
            .await
            .unwrap();
        let order = LocatedOrder::new_order(
            Some("void.programingjd.me")
                .iter()
                .map(|&it| it.to_string()),
            &account,
            &directory,
            &acme.client,
        )
        .await
        .unwrap();
        let authorizations = order.order.authorizations;
        assert_eq!(authorizations.len(), 1);
        let authorization = Authorization::authorize(
            authorizations[0].as_str(),
            &account,
            &directory,
            &acme.client,
        )
        .await
        .unwrap();
        assert_eq!(authorization.status, AuthorizationStatus::Pending);
        assert_eq!(
            authorization.identifier,
            Identifier::Dns("void.programingjd.me".to_string())
        );
        assert!(authorization.challenges.len() >= 3);
        assert_eq!(
            authorization
                .challenges
                .iter()
                .cloned()
                .find_map(|it| match it.kind {
                    ChallengeType::Http01 => Some(it.status),
                    _ => None,
                }),
            Some(ChallengeStatus::Pending)
        );
        assert_eq!(
            authorization
                .challenges
                .iter()
                .cloned()
                .find_map(|it| match it.kind {
                    ChallengeType::Dns01 => Some(it.status),
                    _ => None,
                }),
            Some(ChallengeStatus::Pending)
        );
        assert_eq!(
            authorization
                .challenges
                .iter()
                .cloned()
                .find_map(|it| match it.kind {
                    ChallengeType::TlsAlpn01 => Some(it.status),
                    _ => None,
                }),
            Some(ChallengeStatus::Pending)
        );
    }
}
