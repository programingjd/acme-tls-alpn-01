use crate::ecdsa::generate_pkcs8_ecdsa_keypair;
use crate::errors::{Error, Result};
use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};

#[derive(Debug)]
pub(crate) struct Csr {
    pub(crate) private_key_pem: String,
    pub(crate) csr_der: Vec<u8>,
}

impl TryFrom<Vec<String>> for Csr {
    type Error = Error;
    fn try_from(domain_names: Vec<String>) -> Result<Self> {
        let pkcs8 = generate_pkcs8_ecdsa_keypair();
        let keypair = KeyPair::try_from(pkcs8).unwrap();
        let mut params = CertificateParams::new(domain_names.clone());
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(keypair);
        params.distinguished_name = DistinguishedName::new();
        let certificate = Certificate::from_params(params).map_err(|_| Error::Csr {
            domains: domain_names.clone(),
        })?;
        Ok(Csr {
            private_key_pem: certificate.serialize_private_key_pem(),
            csr_der: certificate
                .serialize_request_der()
                .map_err(|_| Error::Csr {
                    domains: domain_names,
                })?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_csr() {
        let csr: Csr = vec!["example.org".to_string(), "www.example.org".to_string()]
            .try_into()
            .unwrap();
    }
}
