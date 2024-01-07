use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::Serialize;
use serde_json::Value;

const ALGORITHM: &str = "ES256";
const CURVE: &str = "P-256";
const KEY_TYPE: &str = "EC";
const PUBLIC_KEY_USE: &str = "sig";

/// [RFC 8555 Request Authentication](https://datatracker.ietf.org/doc/html/rfc8555#section-6.2)
pub(crate) fn jose(
    keypair: &EcdsaKeyPair,
    payload: Option<Value>,
    kid: Option<&str>,
    nonce: Option<&str>,
    url: &str,
) -> Value {
    let jwk = match kid {
        None => Some(jwk(keypair)),
        _ => None,
    };
    let protected = Protected {
        alg: "ES256",
        jwk,
        kid,
        nonce,
        url,
    };
    let protected = BASE64_URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&protected).expect("failed to serialize jose"));
    let payload = match payload {
        Some(payload) => BASE64_URL_SAFE_NO_PAD.encode(payload.to_string()),
        None => String::new(),
    };
    let message = format!("{}.{}", protected, payload);
    let signature = keypair
        .sign(&SystemRandom::new(), message.as_bytes())
        .expect("failed to sign message");
    let signature = BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref());
    let body = Body {
        protected,
        payload,
        signature,
    };
    serde_json::to_value(body).expect("failed to serialize jose")
}

pub(crate) fn jwk(keypair: &EcdsaKeyPair) -> Jwk {
    let (x, y) = keypair.public_key().as_ref()[1..].split_at(32);
    Jwk {
        alg: ALGORITHM,
        crv: CURVE,
        kty: KEY_TYPE,
        u: PUBLIC_KEY_USE,
        x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
        y: BASE64_URL_SAFE_NO_PAD.encode(y),
    }
}

#[derive(Serialize)]
pub(crate) struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn thumbprint(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(digest(
            &SHA256,
            &serde_json::to_vec(&JwkThumb {
                crv: self.crv,
                kty: self.kty,
                x: &self.x,
                y: &self.y,
            })
            .expect("failed to serialize JwkThumb"),
        ))
    }
}

#[derive(Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    url: &'a str,
}

#[derive(Serialize)]
struct Body {
    protected: String,
    payload: String,
    signature: String,
}
