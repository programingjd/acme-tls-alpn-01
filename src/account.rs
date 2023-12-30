use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::Error::DeserializeAccount;
use crate::errors::{Error, Result};
use crate::jose::jose;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::Display;
use std::str::FromStr;

#[derive(Serialize)]
pub struct AccountMaterial {
    #[serde(skip_serializing)]
    pub(crate) keypair: EcdsaKeyPair,
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    pub(crate) kid: String,
}

#[derive(Deserialize)]
struct PackedAccountMaterial {
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    kid: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct Account {
    contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
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

impl From<PackedAccountMaterial> for AccountMaterial {
    fn from(value: PackedAccountMaterial) -> Self {
        Self {
            keypair: Self::keypair_from_pkcs8(&value.pkcs8),
            pkcs8: value.pkcs8,
            kid: value.kid,
        }
    }
}

impl From<AccountMaterial> for PackedAccountMaterial {
    fn from(value: AccountMaterial) -> Self {
        Self {
            pkcs8: value.pkcs8,
            kid: value.kid,
        }
    }
}

impl Display for AccountMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

impl FromStr for AccountMaterial {
    type Err = Error;

    fn from_str(s: &str) -> Result<AccountMaterial> {
        serde_json::from_str::<PackedAccountMaterial>(s)
            .map(|it| it.into())
            .map_err(|_| DeserializeAccount)
    }
}

impl AccountMaterial {
    pub(crate) async fn from<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        contact_email: impl AsRef<str>,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let nonce = directory.new_nonce(client).await?;
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": vec![format!("mailto:{}", contact_email.as_ref())]
        });
        let pkcs8 = Self::generate_pkcs8();
        let keypair = Self::keypair_from_pkcs8(&pkcs8);
        let body = jose(
            &keypair,
            Some(payload),
            None,
            &nonce,
            &directory.new_account,
        );
        let response = client
            .post_jose(&directory.new_account, &body)
            .await
            .map_err(|_| Error::NewAccount)?;
        if response.is_success() {
            let kid = response.header_value("location").ok_or(Error::NewAccount)?;
            let acme_account = response
                .body_as_json::<AccountStatus>()
                .await
                .map_err(|_| Error::NewAccount)?;
            match acme_account {
                AccountStatus::Valid { .. } => Ok(AccountMaterial {
                    keypair,
                    pkcs8,
                    kid,
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
    fn generate_pkcs8() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        pkcs8.as_ref().to_vec()
    }
    fn keypair_from_pkcs8(pkcs8: &Vec<u8>) -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_slice(), &rng).unwrap()
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
            .map_err(|e| serde::de::Error::custom(e))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::letsencrypt::LetsEncrypt;
    use crate::Acme;

    #[test]
    fn test_account_material_serialization() {
        let pkcs8 = AccountMaterial::generate_pkcs8();
        let keypair = AccountMaterial::keypair_from_pkcs8(&pkcs8);
        let kid = "kid";
        let original = AccountMaterial {
            pkcs8,
            keypair,
            kid: kid.into(),
        };
        let json = original.to_string();
        println!("{json}");
        let deserialized = AccountMaterial::from_str(&json).unwrap();
        assert_eq!(deserialized.kid, kid);
        assert_eq!(&original.pkcs8, &deserialized.pkcs8);
        let _ = AccountMaterial::keypair_from_pkcs8(&deserialized.pkcs8);
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
        assert_eq!(deserialized.contact.len(), 2);
        assert_eq!(deserialized.contact[0], "mailto:cert-admin@example.org");
        assert_eq!(deserialized.contact[1], "mailto:admin@example.org");
        assert!(deserialized.terms_of_service_agreed);
    }

    #[tokio::test]
    async fn test_new_account() {
        let acme = Acme::default();
        let directory = Directory::from(
            LetsEncrypt::StagingEnvironment.directory_url(),
            &acme.client,
        )
        .await
        .unwrap();
        let _ = AccountMaterial::from("void@programingjd.me", &directory, &acme.client)
            .await
            .unwrap();
    }
}
