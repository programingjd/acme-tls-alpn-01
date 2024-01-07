use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::ecdsa::{generate_pkcs8_ecdsa_keypair, keypair_from_pkcs8};
use crate::errors::{Error, ErrorKind, Result};
use crate::jose::jose;
use ring::signature::EcdsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::{Display, Formatter};
#[cfg(feature = "tracing")]
use tracing::debug;

/// Because we have only have an easy way to go from pkcs8 to keypair,
/// but not the other way around, we store the keypair in both its
/// EcdsaKeyPair deserialized version, and its PKCS8 serialized version.
#[derive(Serialize)]
pub struct AccountMaterial {
    #[serde(skip_serializing)]
    pub(crate) keypair: EcdsaKeyPair,
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    /// the account url is also referred to as `kid` in the RFC.
    pub(crate) url: String,
}

#[derive(Deserialize)]
struct PackedAccountMaterial {
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    url: String,
}

/// [RFC 8555 Account](https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2)
/// We only use the status field.
#[derive(Deserialize, Debug)]
pub(crate) struct Account {
    // contact: Vec<String>,
    #[serde(flatten)]
    status: AccountStatus,
}

/// [RFC 8555 Account State](https://datatracker.ietf.org/doc/html/rfc8555#page-33)
#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "status")]
pub(crate) enum AccountStatus {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "deactivated")]
    Deactivated,
    #[serde(rename = "revoked")]
    Revoked,
}

impl Display for AccountStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountStatus::Valid => f.write_str("valid"),
            AccountStatus::Deactivated => f.write_str("deactivated"),
            AccountStatus::Revoked => f.write_str("revoked"),
        }
    }
}

impl TryFrom<PackedAccountMaterial> for AccountMaterial {
    type Error = Error;
    fn try_from(value: PackedAccountMaterial) -> Result<Self> {
        Ok(Self {
            keypair: keypair_from_pkcs8(&value.pkcs8)?,
            pkcs8: value.pkcs8,
            url: value.url,
        })
    }
}

impl From<AccountMaterial> for PackedAccountMaterial {
    fn from(value: AccountMaterial) -> Self {
        Self {
            pkcs8: value.pkcs8,
            url: value.url,
        }
    }
}

impl AccountMaterial {
    /// Serialize to json
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "serialize_account_to_json",
        skip(self),
        level = tracing::Level::TRACE
    )]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("failed to serialize account material")
    }
    /// Deserialize from json and check with the acme server that the account status is valid.
    /// If the account is invalid, it might be because the terms of service need to be agreed to,
    /// in which case, update the account with the terms of service agreement.
    /// If the account is not found, then create a new one.
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "get_account_from_json",
        skip_all,
        level = tracing::Level::DEBUG,
        err(level = tracing::Level::WARN)
    )]
    pub async fn from_json<C: HttpClient<R>, R: Response>(
        json: impl AsRef<str>,
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<AccountMaterial> {
        // Restore account material from json
        let account: AccountMaterial = serde_json::from_str::<PackedAccountMaterial>(json.as_ref())
            .map_err(|_| ErrorKind::DeserializeAccount.into())
            .and_then(|it| it.try_into())?;
        // Get the existing account if it exists
        // [rfc8555#section-7.3.1](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1)
        let nonce = directory.new_nonce(client).await?;
        let payload = json!({
            "onlyReturnExisting": true
        });
        let body = jose(
            &account.keypair,
            Some(payload),
            Some(&account.url),
            Some(&nonce),
            &account.url,
        );
        let response = client
            .post_jose(&account.url, &body)
            .await
            .map_err(|err| ErrorKind::GetAccount.wrap(err))?;
        match response.status_code() {
            200 => {
                // Account found, check that its status is valid.
                let status = response
                    .body_as_json::<Account>()
                    .await
                    .map_err(|err| ErrorKind::GetAccount.wrap(err))?
                    .status;
                match status {
                    AccountStatus::Valid => {
                        account
                            .update_contact(contact_email, directory, client)
                            .await?;
                        Ok(account)
                    }
                    _ => Err(ErrorKind::GetAccount.with_msg(format!("account is {}", status))),
                }
            }
            403 => {
                // Try to update with the terms of service agreement.
                #[cfg(feature = "tracing")]
                if let Ok(text) = response.body_as_text().await {
                    debug!(body = ?text)
                }
                #[cfg(not(feature = "tracing"))]
                let _ = response.body_as_text();
                account
                    .update_contact(contact_email, directory, client)
                    .await?;
                Ok(account)
            }
            400 | 404 => {
                // Account not found, create a new one.
                Self::new_account(
                    account.pkcs8,
                    account.keypair,
                    contact_email,
                    directory,
                    client,
                )
                .await
            }
            _ => {
                #[cfg(feature = "tracing")]
                if let Ok(text) = response.body_as_text().await {
                    debug!(body = ?text)
                }
                #[cfg(not(feature = "tracing"))]
                let _ = response.body_as_text();
                Err(ErrorKind::GetAccount.into())
            }
        }
    }
    pub async fn from_pkcs8<C: HttpClient<R>, R: Response>(
        pkcs8: Vec<u8>,
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<AccountMaterial> {
        let keypair = keypair_from_pkcs8(&pkcs8)?;
        Self::new_account(pkcs8, keypair, contact_email, directory, client).await
    }
    pub(crate) async fn from<C: HttpClient<R>, R: Response>(
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let pkcs8 = generate_pkcs8_ecdsa_keypair();
        let keypair = keypair_from_pkcs8(&pkcs8).expect("failed to extract keypair");
        Self::new_account(pkcs8, keypair, contact_email, directory, client).await
    }

    /// [RFC8555 Account Update](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.2)
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "update_account_contact",
        skip_all,
        level = tracing::Level::DEBUG,
        err(level = tracing::Level::WARN)
    )]
    pub async fn update_contact<C: HttpClient<R>, R: Response>(
        &self,
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<()> {
        let nonce = directory.new_nonce(client).await?;
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": vec![format!("mailto:{}", contact_email.as_ref())]
        });
        let body = jose(
            &self.keypair,
            Some(payload),
            Some(&self.url),
            Some(&nonce),
            &self.url,
        );
        let response = client
            .post_jose(&self.url, &body)
            .await
            .map_err(|err| ErrorKind::GetAccount.wrap(err))?;
        if response.is_success() {
            let status = response
                .body_as_json::<Account>()
                .await
                .map_err(|err| ErrorKind::NewAccount.wrap(err))?
                .status;
            match status {
                AccountStatus::Valid => Ok(()),
                _ => Err(ErrorKind::GetAccount.with_msg(format!("account is {}", status))),
            }
        } else {
            #[cfg(feature = "tracing")]
            if let Ok(text) = response.body_as_text().await {
                debug!(body = ?text)
            }
            #[cfg(not(feature = "tracing"))]
            let _ = response.body_as_text();
            Err(ErrorKind::GetAccount.into())
        }
    }
    /// [RFC8555 Account Key Rollover](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5)
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "update_account_key",
        skip_all,
        level = tracing::Level::DEBUG,
        err(level = tracing::Level::WARN)
    )]
    pub async fn update_key<C: HttpClient<R>, R: Response>(
        &self,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let pkcs8 = generate_pkcs8_ecdsa_keypair();
        let keypair = keypair_from_pkcs8(&pkcs8).expect("failed to extract keypair");
        let nonce = directory.new_nonce(client).await?;
        let payload = json!({
            "account": &self.url,
            "oldKey": crate::jose::jwk(&self.keypair)
        });
        let payload = jose(&keypair, Some(payload), None, None, &directory.key_change);
        let body = jose(
            &self.keypair,
            Some(payload),
            Some(&self.url),
            Some(&nonce),
            &directory.key_change,
        );
        let response = client
            .post_jose(&directory.key_change, &body)
            .await
            .map_err(|err| ErrorKind::ChangeAccountKey.wrap(err))?;
        if response.is_success() {
            let account = response
                .body_as_json::<Account>()
                .await
                .map_err(|err| ErrorKind::ChangeAccountKey.wrap(err))?;
            match account.status {
                AccountStatus::Valid { .. } => Ok(AccountMaterial {
                    keypair,
                    pkcs8,
                    url: self.url.clone(),
                }),
                _ => {
                    Err(ErrorKind::ChangeAccountKey
                        .with_msg(format!("account is {}", account.status)))
                }
            }
        } else {
            #[cfg(feature = "tracing")]
            if let Ok(text) = response.body_as_text().await {
                debug!(body = ?text);
            }
            #[cfg(not(feature = "tracing"))]
            let _ = response.body_as_text();
            Err(ErrorKind::ChangeAccountKey.into())
        }
    }
    /// [RFC 8555 Nonce](https://datatracker.ietf.org/doc/html/rfc8555#section-7.2)
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "new_account",
        skip_all,
        level = tracing::Level::DEBUG,
        err(level = tracing::Level::WARN)
    )]
    async fn new_account<C: HttpClient<R>, R: Response>(
        pkcs8: Vec<u8>,
        keypair: EcdsaKeyPair,
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let nonce = directory.new_nonce(client).await?;
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": vec![format!("mailto:{}", contact_email.as_ref())]
        });
        let body = jose(
            &keypair,
            Some(payload),
            None,
            Some(&nonce),
            &directory.new_account,
        );
        let response = client
            .post_jose(&directory.new_account, &body)
            .await
            .map_err(|err| ErrorKind::NewAccount.wrap(err))?;
        if response.is_success() {
            let kid = response
                .header_value("location")
                .ok_or(ErrorKind::NewAccount.with_msg("could not get account kid"))?;
            let account = response
                .body_as_json::<Account>()
                .await
                .map_err(|err| ErrorKind::NewAccount.wrap(err))?;
            match account.status {
                AccountStatus::Valid { .. } => Ok(AccountMaterial {
                    keypair,
                    pkcs8,
                    url: kid,
                }),
                _ => Err(ErrorKind::NewAccount.with_msg(format!("account is {}", account.status))),
            }
        } else {
            #[cfg(feature = "tracing")]
            if let Ok(text) = response.body_as_text().await {
                debug!(body = ?text);
            }
            #[cfg(not(feature = "tracing"))]
            let _ = response.body_as_text();
            Err(ErrorKind::NewAccount.into())
        }
    }
}

mod base64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(base64)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecdsa::{generate_pkcs8_ecdsa_keypair, keypair_from_pkcs8};
    use crate::letsencrypt::LetsEncrypt;
    use crate::Acme;
    use test_tracing::test;
    use tracing::trace;

    #[test]
    fn test_account_material_serialization() {
        let pkcs8 = generate_pkcs8_ecdsa_keypair();
        let keypair = keypair_from_pkcs8(&pkcs8).unwrap();
        let kid = "kid";
        let original = AccountMaterial {
            pkcs8,
            keypair,
            url: kid.into(),
        };
        let json = original.to_json();
        let deserialized: AccountMaterial =
            serde_json::from_str::<PackedAccountMaterial>(json.as_ref())
                .map_err(|_| ErrorKind::DeserializeAccount.into())
                .and_then(|it| it.try_into())
                .unwrap();
        assert_eq!(deserialized.url, kid);
        assert_eq!(&original.pkcs8, &deserialized.pkcs8);
        let _ = keypair_from_pkcs8(&deserialized.pkcs8).unwrap();
    }

    #[test]
    fn test_account_deserialization() {
        let json = serde_json::to_string_pretty(&json!({
            "status": "valid",
            "contact": [
                "mailto:cert-admin@example.org",
                "mailto:admin@example.org"
            ],
            "termsOfServiceAgreed": true,
            "orders": "https://example.com/acme/orders/rzGoeA"
        }))
        .unwrap();
        let deserialized = serde_json::from_str::<Account>(json.as_str()).unwrap();
        assert_eq!(deserialized.status, AccountStatus::Valid);
    }

    #[test(tokio::test)]
    async fn test_get_account_and_update_key() {
        let acme = Acme::empty();
        let directory = Directory::from(
            LetsEncrypt::StagingEnvironment.directory_url(),
            &acme.client,
        )
        .await
        .unwrap();
        let created = AccountMaterial::from("void@programingjd.me", &directory, &acme.client)
            .await
            .unwrap();
        trace!(account_url = &created.url);
        let account = AccountMaterial::from_pkcs8(
            created.pkcs8.clone(),
            "void@programingjd.me",
            &directory,
            &acme.client,
        )
        .await
        .unwrap();
        assert_eq!(account.url, created.url);
        assert_eq!(account.pkcs8, created.pkcs8);
        let updated = account.update_key(&directory, &acme.client).await.unwrap();
        assert_eq!(updated.url, created.url);
    }
}
