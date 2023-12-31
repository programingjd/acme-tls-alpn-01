use crate::account::AccountMaterial;
use crate::authorization::{Authorization, AuthorizationStatus};
use crate::challenge::Challenge;
use crate::client::{HttpClient, Response};
use crate::directory::Directory;
use crate::errors::{Error, Result};
use crate::jose::jose;
use futures_timer::Delay;
use rcgen::{Certificate, CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct LocatedOrder {
    url: String,
    pub(crate) order: Order,
}

#[derive(Deserialize, Debug)]
pub(crate) struct Order {
    pub(crate) identifiers: Vec<Identifier>,
    pub(crate) authorizations: Vec<String>,
    pub(crate) finalize: String,
    #[serde(flatten)]
    pub(crate) status: OrderStatus,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "status")]
pub(crate) enum OrderStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "valid")]
    Valid { certificate: String },
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "processing")]
    Processing,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum Identifier {
    #[serde(rename = "dns")]
    Dns(String),
}

impl LocatedOrder {
    pub(crate) async fn new_order<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        domain_names: impl Iterator<Item = impl Into<String>>,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<LocatedOrder> {
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
            let url = response.header_value("location").ok_or(Error::NewOrder)?;
            let order = response
                .body_as_json::<Order>()
                .await
                .map_err(|_| Error::NewOrder)?;
            Ok(LocatedOrder { url, order })
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
    pub(crate) async fn process<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        self,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<()> {
        match self.retry(account, directory, client).await {
            Ok(it) => Ok(it),
            Err(Error::OrderProcessing) => {
                Delay::new(Duration::from_secs(10u64)).await;
                let order = Self::try_get(self.url, account, directory, client).await?;
                match order.retry(account, directory, client).await {
                    Ok(it) => Ok(it),
                    Err(Error::OrderProcessing) => {
                        Delay::new(Duration::from_secs(150u64)).await;
                        Self::try_get(order.url, account, directory, client)
                            .await?
                            .retry(account, directory, client)
                            .await
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }
    async fn try_get<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        url: String,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let nonce = directory.new_nonce(client).await?;
        let body = jose(&account.keypair, None, Some(&account.kid), &nonce, &url);
        let response = client
            .post_jose(&url, &body)
            .await
            .map_err(|_| Error::GetOrder)?;
        if response.is_success() {
            let order = response
                .body_as_json::<Order>()
                .await
                .map_err(|_| Error::GetOrder)?;
            Ok(LocatedOrder { url, order })
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(Error::GetOrder)
        }
    }
    async fn retry<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        &self,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<()> {
        match &self.order.status {
            OrderStatus::Invalid => Err(Error::InvalidOrder {
                domains: self
                    .order
                    .identifiers
                    .iter()
                    .map(|it| match it {
                        Identifier::Dns(name) => name.clone(),
                    })
                    .collect(),
            }),
            OrderStatus::Ready => {
                Self::finalize(&self.order.finalize, account, directory, client).await
            }
            OrderStatus::Valid {
                certificate: url, ..
            } => Self::download_certificate(url, account, directory, client).await,
            OrderStatus::Processing => Err(Error::OrderProcessing),
            OrderStatus::Pending => {
                let futures: Vec<_> = self
                    .order
                    .authorizations
                    .iter()
                    .map(|url| Authorization::authorize(url, account, directory, client))
                    .collect();
                let authorizations = futures::future::try_join_all(futures).await?;
                if authorizations.iter().any(|it| match it.status {
                    AuthorizationStatus::Valid { .. } => false,
                    AuthorizationStatus::Pending { .. } => false,
                    _ => true,
                }) {
                    return Err(Error::InvalidAuthorization);
                }
                let pending_challenges = authorizations.into_iter().flat_map(|authorization| {
                    match authorization.status {
                        AuthorizationStatus::Pending => Some(
                            authorization
                                .challenges
                                .into_iter()
                                .filter(|it| matches!(it, Challenge::TlsAlpn01 { .. })),
                        ),
                        _ => None,
                    }
                });

                Ok(())
            }
        }
    }
    async fn finalize<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        url: impl AsRef<str>,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<()> {
        todo!()
    }
    async fn download_certificate<C: HttpClient<R, E>, R: Response<E>, E: std::error::Error>(
        url: impl AsRef<str>,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<()> {
        todo!()
    }

    fn csr_der(domain_names: Vec<String>) -> Result<Vec<u8>> {
        let mut params = CertificateParams::new(domain_names.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        Certificate::from_params(params)
            .and_then(|cert| cert.serialize_der())
            .map_err(|_| Error::Csr {
                domains: domain_names,
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::letsencrypt::LetsEncrypt;
    use crate::Acme;

    #[test]
    fn test_order_deserialization() {
        let json = serde_json::to_string_pretty(&json!({
            "status": "valid",
            "expires": "2016-01-20T14:09:07.99Z",
            "identifiers": [
                { "type": "dns", "value": "www.example.org" },
                { "type": "dns", "value": "example.org" }
            ],
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2016-01-08T00:00:00Z",
            "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis",
                "https://example.com/acme/authz/r4HqLzrSrpI"
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
            "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
        }))
        .unwrap();
        println!("{json}");
        let deserialized = serde_json::from_str::<Order>(json.as_str()).unwrap();
        assert_eq!(
            deserialized.status,
            OrderStatus::Valid {
                certificate: "https://example.com/acme/cert/mAt3xBGaobw".to_string()
            }
        );
        assert_eq!(deserialized.identifiers.len(), 2);
        assert_eq!(
            deserialized.identifiers[0],
            Identifier::Dns("www.example.org".to_string())
        );
        assert_eq!(
            deserialized.identifiers[1],
            Identifier::Dns("example.org".to_string())
        );
        assert_eq!(deserialized.authorizations.len(), 2);
        assert_eq!(
            deserialized.authorizations[0],
            "https://example.com/acme/authz/PAniVnsZcis"
        );
        assert_eq!(
            deserialized.authorizations[1],
            "https://example.com/acme/authz/r4HqLzrSrpI"
        );
        assert_eq!(
            deserialized.finalize,
            "https://example.com/acme/order/TOlocE8rfgo/finalize"
        )
    }

    #[tokio::test]
    async fn test_new_order() {
        let acme = Acme::default();
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
        println!("{}", order.url);
        assert_eq!(order.order.status, OrderStatus::Pending);
        assert_eq!(order.order.identifiers.len(), 1);
        assert_eq!(
            order.order.identifiers[0],
            Identifier::Dns("void.programingjd.me".to_string())
        );
        assert_eq!(order.order.authorizations.len(), 1);
    }
}
