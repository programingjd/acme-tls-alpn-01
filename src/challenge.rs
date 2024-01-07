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
#[cfg(feature = "tracing")]
use tracing::debug;

/// [RFC 8555 Challenge](https://datatracker.ietf.org/doc/html/rfc8555#section-8)
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
    /// [RFC 8555 HTTP Challenge](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3)
    #[serde(rename = "http-01")]
    Http01,
    /// [RFC 8555 DNS Challenge](https://datatracker.ietf.org/doc/html/rfc8555#section-8.4)
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-sni-01")]
    TlsSNI01,
    #[serde(rename = "tls-sni-02")]
    TlsSNI02,
    /// [RFC 8737 TLS ALPN Challenge](https://datatracker.ietf.org/doc/html/rfc8737)
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// [RFC 8555 Challenge States](https://datatracker.ietf.org/doc/html/rfc8555#page-31)
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
    /// [RFC 8555 Key Authorizations](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1)
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
    /// [RFC 8737 Certificate](https://datatracker.ietf.org/doc/html/rfc8737#section-3-4)
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
    /// [RFC 8555 Responding to Challenges](https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1)
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "accept_challenge",
        skip(account,directory,client),
        level = tracing::Level::DEBUG,
        err(level = tracing::Level::WARN)
    )]
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
            #[cfg(feature = "tracing")]
            if let Ok(text) = response.body_as_text().await {
                debug!(body = ?text);
            }
            #[cfg(not(feature = "tracing"))]
            let _ = response.body_as_text();
            Err(ErrorKind::Challenge.into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    use test_tracing::test;

    #[test]
    fn test_order_deserialization() {
        let json = serde_json::to_string_pretty(&json!({
            "type": "http-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "pending",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        }))
        .unwrap();
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
