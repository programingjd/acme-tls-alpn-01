use serde::Deserialize;

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub(crate) enum Challenge {
    #[serde(rename = "http-01")]
    Http01 {
        url: String,
        status: ChallengeStatus,
        token: String,
    },
    #[serde(rename = "dns-01")]
    Dns01 {
        url: String,
        status: ChallengeStatus,
        token: String,
    },
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01 {
        url: String,
        status: ChallengeStatus,
        token: String,
    },
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
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
