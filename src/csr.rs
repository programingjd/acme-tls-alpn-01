use crate::ecdsa::generate_pkcs8_ecdsa_keypair;
use crate::errors::{Error, ErrorKind, Result};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};

/// [RFC 8555 CSR](https://datatracker.ietf.org/doc/html/rfc8555#page-46)
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

        let request = CertificateParams::new(domain_names.clone())
            .and_then(|mut params| {
                params.distinguished_name = DistinguishedName::new();
                params.serialize_request(&keypair)
            })
            .map_err(|_| {
                let error: Error = ErrorKind::Csr {
                    domains: domain_names.clone(),
                }
                .into();
                error
            })?;
        Ok(Csr {
            private_key_pem: keypair.serialize_pem(),
            der: request.der().to_vec(),
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
