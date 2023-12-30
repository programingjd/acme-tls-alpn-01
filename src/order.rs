use crate::account::Account;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::{Error, Result};
use crate::jose::jose;
use rcgen::{Certificate, CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
#[serde(tag = "status")]
pub(crate) enum Order {
    #[serde(rename = "pending")]
    Pending {
        identifiers: Vec<Identifier>,
        authorizations: Vec<String>,
        finalize: String,
    },
    #[serde(rename = "ready")]
    Ready {
        identifiers: Vec<Identifier>,
        authorizations: Vec<String>,
        finalize: String,
    },
    #[serde(rename = "valid")]
    Valid {
        identifiers: Vec<Identifier>,
        authorizations: Vec<String>,
        finalize: String,
        certificate: String,
    },
    #[serde(rename = "invalid")]
    Invalid {
        identifiers: Vec<Identifier>,
        authorizations: Vec<String>,
        finalize: String,
    },
    #[serde(rename = "processing")]
    Processing {
        identifiers: Vec<Identifier>,
        authorizations: Vec<String>,
        finalize: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Identifier {
    #[serde(rename = "dns")]
    Dns(String),
}

impl Order {
    pub(crate) async fn new_order<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        domain_names: impl Iterator<Item = impl Into<String>>,
        account: &Account,
        directory: &Directory,
        client: &C,
    ) -> Result<Order> {
        let domain_names: Vec<String> = domain_names.map(|it| it.into()).collect();
        let nonce = directory.new_nonce(client).await?;
        let identifiers: Vec<Identifier> = domain_names
            .iter()
            .map(|it| Identifier::Dns(it.clone()))
            .collect();
        let payload = json!({
            "identifiers": identifiers
        });
        let body = jose(
            &account.keypair,
            Some(payload),
            Some(&account.kid),
            &nonce,
            &directory.new_order,
        );
        let response = client
            .post_jose(&directory.new_order, &body)
            .await
            .map_err(|_| Error::NewOrder)?;
        if response.is_success() {
            response
                .body_as_json::<Order>()
                .await
                .map_err(|_| Error::NewOrder)
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(Error::NewOrder)
        }
    }
    pub fn csr_der(domain_names: Vec<String>) -> Result<Vec<u8>> {
        let mut params = CertificateParams::new(domain_names.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        Certificate::from_params(params)
            .and_then(|cert| cert.serialize_der())
            .map_err(|_| crate::errors::Error::Csr {
                domains: domain_names,
            })
    }
}
