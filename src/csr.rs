use crate::ecdsa::generate_pkcs8_ecdsa_keypair;
use crate::errors::{Error, ErrorKind, Result};
use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};

#[derive(Debug)]
pub struct Csr {
    pub(crate) private_key_pem: String,
    pub(crate) der: Vec<u8>,
}

impl TryFrom<Vec<String>> for Csr {
    type Error = Error;
    #[cfg(feature = "tracing")]
    #[tracing::instrument(
        name = "create_csr",
        level = tracing::Level::TRACE,
        err(level = tracing::Level::WARN)
    )]
    fn try_from(domain_names: Vec<String>) -> Result<Self> {
        let pkcs8 = generate_pkcs8_ecdsa_keypair();
        let keypair = KeyPair::try_from(pkcs8).expect("failed to extract keypair");
        let mut params = CertificateParams::new(domain_names.clone());
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(keypair);
        params.distinguished_name = DistinguishedName::new();
        let certificate = Certificate::from_params(params).map_err(|_| {
            let error: Error = ErrorKind::Csr {
                domains: domain_names.clone(),
            }
            .into();
            error
        })?;
        Ok(Csr {
            private_key_pem: certificate.serialize_private_key_pem(),
            der: certificate.serialize_request_der().map_err(|_| {
                let error: Error = ErrorKind::Csr {
                    domains: domain_names,
                }
                .into();
                error
            })?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_tracing::test;

    #[test]
    fn test_csr() {
        let _: Csr = vec!["example.org".to_string(), "www.example.org".to_string()]
            .try_into()
            .unwrap();
    }
}
