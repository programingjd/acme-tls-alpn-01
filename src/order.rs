use crate::account::AccountMaterial;
use crate::authorization::{Authorization, AuthorizationStatus};
use crate::challenge::ChallengeType;
use crate::client::{HttpClient, Response};
use crate::csr::Csr;
use crate::directory::Directory;
use crate::errors::{Error, ErrorKind, Result};
use crate::jose::jose;
use base64::Engine;
use futures_timer::Delay;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::{Display, Formatter};
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

impl Display for OrderStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderStatus::Pending => f.write_str("pending"),
            OrderStatus::Ready => f.write_str("ready"),
            OrderStatus::Valid { .. } => f.write_str("valid"),
            OrderStatus::Invalid => f.write_str("invalid"),
            OrderStatus::Processing => f.write_str("processing"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum Identifier {
    #[serde(rename = "dns")]
    Dns(String),
}

impl LocatedOrder {
    pub(crate) async fn new_order<C: HttpClient<R>, R: Response>(
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
            Some(&account.url),
            Some(&nonce),
            &directory.new_order,
        );
        let response = client
            .post_jose(&directory.new_order, &body)
            .await
            .map_err(|err| ErrorKind::NewOrder.wrap(err))?;
        if response.is_success() {
            let url = response
                .header_value("location")
                .ok_or::<Error>(ErrorKind::NewOrder.into())?;
            let order = response
                .body_as_json::<Order>()
                .await
                .map_err(|err| ErrorKind::NewOrder.wrap(err))?;
            Ok(LocatedOrder { url, order })
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(ErrorKind::NewOrder.into())
        }
    }
    pub(crate) async fn process<C: HttpClient<R>, R: Response>(
        self,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<String> {
        match self.retry(account, directory, client, None).await {
            Ok(it) => Ok(it),
            Err(Error {
                kind: ErrorKind::OrderProcessing { csr },
                ..
            }) => {
                Delay::new(Duration::from_secs(10u64)).await;
                let order = Self::try_get(self.url, account, directory, client).await?;
                match order.retry(account, directory, client, Some(csr)).await {
                    Ok(it) => Ok(it),
                    Err(Error {
                        kind: ErrorKind::OrderProcessing { csr },
                        ..
                    }) => {
                        Delay::new(Duration::from_secs(150u64)).await;
                        Self::try_get(order.url, account, directory, client)
                            .await?
                            .retry(account, directory, client, Some(csr))
                            .await
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }
    async fn try_get<C: HttpClient<R>, R: Response>(
        url: String,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<Self> {
        let nonce = directory.new_nonce(client).await?;
        let body = jose(
            &account.keypair,
            None,
            Some(&account.url),
            Some(&nonce),
            &url,
        );
        let response = client
            .post_jose(&url, &body)
            .await
            .map_err(|err| ErrorKind::GetOrder.wrap(err))?;
        if response.is_success() {
            let order = response
                .body_as_json::<Order>()
                .await
                .map_err(|err| ErrorKind::GetOrder.wrap(err))?;
            Ok(LocatedOrder { url, order })
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(ErrorKind::GetOrder.into())
        }
    }
    async fn retry<C: HttpClient<R>, R: Response>(
        &self,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
        csr: Option<Csr>,
    ) -> Result<String> {
        match &self.order.status {
            OrderStatus::Invalid => Err(ErrorKind::InvalidOrder {
                domains: self
                    .order
                    .identifiers
                    .iter()
                    .map(|it| match it {
                        Identifier::Dns(name) => name.clone(),
                    })
                    .collect(),
            }
            .into()),
            OrderStatus::Ready => self.finalize(account, directory, client).await,
            OrderStatus::Valid {
                certificate: url, ..
            } => {
                if let Some(csr) = csr {
                    Self::download_certificate(url, &csr, account, directory, client).await
                } else {
                    Err(ErrorKind::NewOrder.into())
                }
            }
            OrderStatus::Processing => {
                if let Some(csr) = csr {
                    Err(ErrorKind::OrderProcessing { csr }.into())
                } else {
                    Err(ErrorKind::NewOrder.into())
                }
            }
            OrderStatus::Pending => {
                let futures: Vec<_> = self
                    .order
                    .authorizations
                    .iter()
                    .map(|url| Authorization::authorize(url, account, directory, client))
                    .collect();
                let authorizations = futures::future::try_join_all(futures).await?;
                if authorizations.iter().any(|it| {
                    !matches!(
                        it.status,
                        AuthorizationStatus::Valid | AuthorizationStatus::Pending
                    )
                }) {
                    return Err(ErrorKind::InvalidAuthorization.into());
                }
                let _pending_challenges = authorizations.into_iter().flat_map(|authorization| {
                    match authorization.status {
                        AuthorizationStatus::Pending => Some(
                            authorization
                                .challenges
                                .into_iter()
                                .filter(|it| matches!(it.kind, ChallengeType::TlsAlpn01)),
                        ),
                        _ => None,
                    }
                });
                todo!()
            }
        }
    }
    async fn finalize<C: HttpClient<R>, R: Response>(
        &self,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<String> {
        let url = &self.order.finalize;
        let nonce = directory.new_nonce(client).await?;
        let domain_names: Vec<String> = self
            .order
            .identifiers
            .iter()
            .filter_map(|identifier| match identifier {
                Identifier::Dns(domain_name) => Some(domain_name.clone()),
                #[allow(unreachable_patterns)]
                _ => None,
            })
            .collect();
        let csr: Csr = domain_names.try_into()?;
        let payload = json!({
           "csr": base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&csr.der)
        });
        let body = jose(
            &account.keypair,
            Some(payload),
            Some(&account.url),
            Some(&nonce),
            url,
        );
        let response = client
            .post_jose(&url, &body)
            .await
            .map_err(|err| ErrorKind::FinalizeOrder.wrap(err))?;
        if response.is_success() {
            let order = response
                .body_as_json::<Order>()
                .await
                .map_err(|err| ErrorKind::FinalizeOrder.wrap(err))?;
            todo!()
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(ErrorKind::FinalizeOrder.into())
        }
    }
    async fn download_certificate<C: HttpClient<R>, R: Response>(
        url: impl AsRef<str>,
        csr: &Csr,
        account: &AccountMaterial,
        directory: &Directory,
        client: &C,
    ) -> Result<String> {
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
            .post_jose(&url, &body)
            .await
            .map_err(|err| ErrorKind::DownloadCertificate.wrap(err))?;
        if response.is_success() {
            let pem_certificate_chain = response
                .body_as_text()
                .await
                .map_err(|err| ErrorKind::DownloadCertificate.wrap(err))?;
            Ok([csr.private_key_pem.clone(), pem_certificate_chain].join("\n"))
        } else {
            #[cfg(debug_assertions)]
            if let Ok(text) = response.body_as_text().await {
                eprintln!("{text}")
            }
            #[cfg(not(debug_assertions))]
            let _ = response.body_as_text();
            Err(ErrorKind::DownloadCertificate.into())
        }
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
