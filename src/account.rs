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
pub struct Account {
    #[serde(skip_serializing)]
    pub(crate) keypair: EcdsaKeyPair,
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    pub(crate) kid: String,
}

#[derive(Deserialize)]
struct PackedAccount {
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    kid: String,
}

impl From<PackedAccount> for Account {
    fn from(value: PackedAccount) -> Self {
        Self {
            keypair: Self::keypair_from_pkcs8(&value.pkcs8),
            pkcs8: value.pkcs8,
            kid: value.kid,
        }
    }
}

impl From<Account> for PackedAccount {
    fn from(value: Account) -> Self {
        Self {
            pkcs8: value.pkcs8,
            kid: value.kid,
        }
    }
}

impl Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

impl FromStr for Account {
    type Err = Error;

    fn from_str(s: &str) -> Result<Account> {
        serde_json::from_str::<PackedAccount>(s)
            .map(|it| it.into())
            .map_err(|_| DeserializeAccount)
    }
}

impl Account {
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
            let account = response
                .header_value("location")
                .map(|kid| Self {
                    keypair,
                    pkcs8,
                    kid,
                })
                .ok_or(Error::NewAccount)?;
            let _ = response.body_as_bytes();
            Ok(account)
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
    fn test_pcks8() {
        let pkcs8 = Account::generate_pkcs8();
        let keypair = Account::keypair_from_pkcs8(&pkcs8);
        let kid = "kid";
        let account = Account {
            pkcs8,
            keypair,
            kid: kid.into(),
        };
        let json = account.to_string();
        println!("{json}");
        let deserialized = Account::from_str(&json).unwrap();
        assert_eq!(deserialized.kid, kid);
        let _ = Account::keypair_from_pkcs8(&deserialized.pkcs8);
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
        let _ = Account::from("void@programingjd.me", &directory, &acme.client)
            .await
            .unwrap();
    }
}
