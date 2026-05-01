use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"S4C\x01";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    #[serde(with = "zeroizing_bytes")]
    pub value: Zeroizing<Vec<u8>>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrantFile {
    pub grants: BTreeMap<String, Grant>,
    #[serde(default)]
    pub version: u64,
}

impl GrantFile {
    pub fn prune_expired(&mut self) {
        let now = Utc::now();
        self.grants.retain(|_, g| g.expires_at > now);
    }
}

mod zeroizing_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(value: &Zeroizing<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Ok(Zeroizing::new(bytes.into_vec()))
    }
}
