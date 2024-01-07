use crate::errors::{ErrorKind, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

#[cfg(feature = "tracing")]
#[tracing::instrument(
    name = "generate_keypair_pkcs8",
    level = tracing::Level::TRACE
)]
pub fn generate_pkcs8_ecdsa_keypair() -> Vec<u8> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("failed to create keypair");
    pkcs8.as_ref().to_vec()
}
#[cfg(feature = "tracing")]
#[tracing::instrument(
    name = "deserialize_keypair_from_pkcs8",
    skip(pkcs8),
    level = tracing::Level::TRACE,
    err(level = tracing::Level::WARN)
)]
pub(crate) fn keypair_from_pkcs8(pkcs8: &Vec<u8>) -> Result<EcdsaKeyPair> {
    let rng = SystemRandom::new();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_slice(), &rng)
        .map_err(|_| ErrorKind::InvalidKey.into())
}
