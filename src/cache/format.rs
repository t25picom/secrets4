use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"S4C\x01";

#[derive(Clone, Serialize, Deserialize)]
pub struct Grant {
    #[serde(with = "zeroizing_bytes")]
    pub value: Zeroizing<Vec<u8>>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant")
            .field("value", &"<redacted>")
            .field("granted_at", &self.granted_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
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
