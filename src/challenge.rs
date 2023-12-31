use serde::Deserialize;

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

impl Challenge {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::letsencrypt::LetsEncrypt;
    use crate::Acme;
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
