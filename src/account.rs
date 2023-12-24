use crate::errors::{Error, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Account {
    #[serde(with = "base64")]
    pkcs8: Vec<u8>,
    kid: String,
}

impl Account {
    fn generate_ecdsa() -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::GenerateAccountKeyPair)?;
        Ok(pkcs8.as_ref().to_vec())
    }
    fn keypair_from_pkcs8(pkcs8: &Vec<u8>) -> Result<EcdsaKeyPair> {
        let rng = SystemRandom::new();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_slice(), &rng)
            .map_err(|_| Error::GenerateAccountKeyPair)
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

    #[test]
    fn test_pcks8() {
        let kid = "kid";
        let account = Account {
            pkcs8: Account::generate_ecdsa().unwrap(),
            kid: kid.to_string(),
        };
        let json = serde_json::to_string(&account).unwrap();
        println!("{json}");
        let deserialized = serde_json::from_str::<Account>(&json).unwrap();
        assert_eq!(deserialized.kid, kid);
        let _ = Account::keypair_from_pkcs8(&deserialized.pkcs8).unwrap();
    }
}
