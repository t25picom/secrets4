use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAGIC: &[u8; 4] = b"S4C\x01";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
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
