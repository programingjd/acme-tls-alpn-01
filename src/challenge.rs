use crate::account::AccountMaterial;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::{Error, ErrorKind, Result};
use crate::jose::{jose, jwk};
use rcgen::{Certificate, CertificateParams, CustomExtension, PKCS_ECDSA_P256_SHA256};
use ring::digest::{digest, SHA256};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use serde_json::json;
use std::str::from_utf8;

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub(crate) url: String,
    pub(crate) token: String,
    #[serde(flatten)]
    pub(crate) status: ChallengeStatus,
    #[serde(flatten, rename = "type")]
    pub(crate) kind: ChallengeType,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub(crate) enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "status")]
pub(crate) enum ChallengeStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "Invalid")]
    Invalid,
}

impl Challenge {
    pub(crate) fn authorization_key(&self, account: &AccountMaterial) -> String {
        let jwk = jwk(&account.keypair);
        let thumbprint = jwk.thumbprint();
        from_utf8(
            digest(
                &SHA256,
                format!("{}.{}", &self.token, &thumbprint).as_bytes(),
            )
            .as_ref(),
        )
        .unwrap()
        .to_string()
    }
    pub(crate) fn certificate(
        domain_name: impl Into<String>,
        authorization_key: String,
    ) -> Result<CertifiedKey> {
        let mut params = CertificateParams::new(vec![domain_name.into()]);
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(
            authorization_key.as_bytes(),
        )];
        let cert = Certificate::from_params(params).map_err(|_| {
            let error: Error = ErrorKind::Challenge.into();
            error
        })?;
        Ok(CertifiedKey::new(
            vec![cert
                .serialize_der()
                .expect("failed to serialize certificate")
                .into()],
            any_supported_type(&PrivateKeyDer::Pkcs8(
                cert.serialize_private_key_der().into(),
            ))
            .expect("failed to generate signing key"),
        ))
    }
    pub(crate) async fn accept<C: HttpClient<R>, R: Response>(
        &self,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<Challenge> {
        let nonce = directory.new_nonce(client).await?;
        let payload = json!({});
        let body = jose(
            &account.keypair,
            Some(payload),
            Some(&account.url),
            Some(&nonce),
            &self.url,
        );
        let response = client
            .post_jose(&self.url, &body)
            .await
            .map_err(|err| ErrorKind::Challenge.wrap(err))?;
        if response.is_success() {
            response
                .body_as_json::<Challenge>()
                .await
                .map_err(|err| ErrorKind::Challenge.wrap(err))
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(ErrorKind::Challenge.into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_order_deserialization() {
        let json = serde_json::to_string_pretty(&json!({
            "type": "http-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "pending",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        }))
        .unwrap();
        println!("{json}");
        let deserialized = serde_json::from_str::<Challenge>(json.as_str()).unwrap();
        assert_eq!(deserialized.status, ChallengeStatus::Pending);
        assert_eq!(deserialized.kind, ChallengeType::Http01);
        assert_eq!(
            deserialized.url,
            "https://example.com/acme/chall/prV_B7yEyA4"
        );
        assert_eq!(
            deserialized.token,
            "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        );
    }
}
