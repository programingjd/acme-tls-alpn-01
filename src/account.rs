use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::ecdsa::{generate_pkcs8_ecdsa_keypair, keypair_from_pkcs8};
use crate::errors::Error::DeserializeAccount;
use crate::errors::{Error, Result};
use crate::jose::jose;
use ring::signature::EcdsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize)]
pub struct AccountMaterial {
    #[serde(skip_serializing)]
    pub(crate) keypair: EcdsaKeyPair,
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    pub(crate) url: String,
}

#[derive(Deserialize)]
struct PackedAccountMaterial {
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    url: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct Account {
    // contact: Vec<String>,
    #[serde(flatten)]
    status: AccountStatus,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "status")]
pub(crate) enum AccountStatus {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "deactivated")]
    Deactivated {},
    #[serde(rename = "revoked")]
    Revoked {},
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
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
    pub async fn from_json<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        json: impl AsRef<str>,
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<AccountMaterial> {
        let account: AccountMaterial = serde_json::from_str::<PackedAccountMaterial>(json.as_ref())
            .map_err(|_| DeserializeAccount)
            .and_then(|it| it.try_into())?;
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
            .map_err(|_| Error::GetAccount)?;
        match response.status_code() {
            200 => {
                let status = response
                    .body_as_json::<Account>()
                    .await
                    .map_err(|_| Error::GetAccount)?
                    .status;
                match status {
                    AccountStatus::Valid => {
                        account
                            .update_contact(contact_email, directory, client)
                            .await?;
                        Ok(account)
                    }
                    _ => Err(Error::GetAccount),
                }
            }
            403 => {
                #[cfg(debug_assertions)]
                if let Ok(text) = response.body_as_text().await {
                    eprintln!("{text}")
                }
                #[cfg(not(debug_assertions))]
                let _ = response.body_as_text();
                account
                    .update_contact(contact_email, directory, client)
                    .await?;
                Ok(account)
            }
            400 | 404 => {
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
                #[cfg(debug_assertions)]
                if let Ok(text) = response.body_as_text().await {
                    eprintln!("{text}")
                }
                #[cfg(not(debug_assertions))]
                let _ = response.body_as_text();
                Err(Error::GetAccount)
            }
        }
    }
    pub async fn from_pkcs8<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        pkcs8: Vec<u8>,
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<AccountMaterial> {
        let keypair = keypair_from_pkcs8(&pkcs8)?;
        Self::new_account(pkcs8, keypair, contact_email, directory, client).await
    }
    pub(crate) async fn from<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let pkcs8 = generate_pkcs8_ecdsa_keypair();
        let keypair = keypair_from_pkcs8(&pkcs8).unwrap();
        Self::new_account(pkcs8, keypair, contact_email, directory, client).await
    }
    pub async fn update_contact<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
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
            .map_err(|_| Error::GetAccount)?;
        if response.is_success() {
            let status = response
                .body_as_json::<Account>()
                .await
                .map_err(|_| Error::NewAccount)?
                .status;
            match status {
                AccountStatus::Valid => Ok(()),
                _ => Err(Error::GetAccount),
            }
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(Error::GetAccount)
        }
    }
    pub async fn update_key<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        &self,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let pkcs8 = generate_pkcs8_ecdsa_keypair();
        let keypair = keypair_from_pkcs8(&pkcs8).unwrap();
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
            .map_err(|_| Error::ChangeAccountKey)?;
        if response.is_success() {
            let account = response
                .body_as_json::<Account>()
                .await
                .map_err(|_| Error::ChangeAccountKey)?;
            match account.status {
                AccountStatus::Valid { .. } => Ok(AccountMaterial {
                    keypair,
                    pkcs8,
                    url: self.url.clone(),
                }),
                _ => Err(Error::ChangeAccountKey),
            }
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(Error::ChangeAccountKey)
        }
    }
    async fn new_account<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
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
            .map_err(|_| Error::NewAccount)?;
        if response.is_success() {
            let kid = response.header_value("location").ok_or(Error::NewAccount)?;
            let account = response
                .body_as_json::<Account>()
                .await
                .map_err(|_| Error::NewAccount)?;
            match account.status {
                AccountStatus::Valid { .. } => Ok(AccountMaterial {
                    keypair,
                    pkcs8,
                    url: kid,
                }),
                _ => Err(Error::NewAccount),
            }
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(Error::NewAccount)
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
        println!("{json}");
        let deserialized: AccountMaterial =
            serde_json::from_str::<PackedAccountMaterial>(json.as_ref())
                .map_err(|_| DeserializeAccount)
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
        println!("{json}");
        let deserialized = serde_json::from_str::<Account>(json.as_str()).unwrap();
        assert_eq!(deserialized.status, AccountStatus::Valid);
    }

    #[tokio::test]
    async fn test_get_account_and_update_key() {
        let acme = Acme::default();
        let directory = Directory::from(
            LetsEncrypt::StagingEnvironment.directory_url(),
            &acme.client,
        )
        .await
        .unwrap();
        let created = AccountMaterial::from("void@programingjd.me", &directory, &acme.client)
            .await
            .unwrap();
        println!("{}", &created.url);
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
