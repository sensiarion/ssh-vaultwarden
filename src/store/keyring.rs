use crate::store::Store;
use crate::vault::SshEntry;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_SERVICE: &str = "ssh-vaultvarden";
const DEFAULT_ACCOUNT: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreData {
    #[serde(default)]
    entries: Vec<SshEntry>,
    #[serde(default)]
    sync_timestamp: Option<i64>,
}

/// Store encrypted data in the OS keyring (Keychain / Credential Manager / Secret Service).
///
/// Data is stored as a single JSON blob under (`service`, `account`).
pub struct KeyringStore {
    service: String,
    account: String,
}

fn keyring_error(context: &str, err: keyring::Error) -> Error {
    let mut message = format!("{}: {}", context, err);
    if !cfg!(target_os = "macos") {
        message.push_str(
            ". Keyring backend may be unavailable on this platform. \
Set STORE_API=file or set store_api=\"file\" in the config.",
        );
    }
    Error::Store(message)
}

impl KeyringStore {
    pub fn new<S: Into<String>, A: Into<String>>(service: S, account: A) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    pub fn default() -> Self {
        Self::new(DEFAULT_SERVICE, DEFAULT_ACCOUNT)
    }

    pub fn check_access(&self) -> Result<()> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keyring_error("Failed to access keyring", e)),
        }
    }

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, &self.account)
            .map_err(|e| keyring_error("Failed to initialize keyring entry", e))
    }

    fn load_data(&self) -> Result<StoreData> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(value) => match serde_json::from_str::<StoreData>(&value) {
                Ok(data) => Ok(data),
                Err(e) => Err(Error::Store(format!(
                    "Failed to parse keyring store JSON (corrupted?): {}",
                    e
                ))),
            },
            Err(keyring::Error::NoEntry) => Ok(StoreData::default()),
            Err(e) => Err(keyring_error("Failed to read from keyring", e)),
        }
    }

    fn save_data(&self, data: &StoreData) -> Result<()> {
        let entry = self.entry()?;
        let serialized = serde_json::to_string(data)
            .map_err(|e| Error::Store(format!("Failed to serialize keyring store: {}", e)))?;
        entry
            .set_password(&serialized)
            .map_err(|e| keyring_error("Failed to write to keyring", e))?;
        Ok(())
    }
}

impl Store for KeyringStore {
    fn load_entries(&self) -> Result<Vec<SshEntry>> {
        Ok(self.load_data()?.entries)
    }

    fn save_entries(&self, entries: &[SshEntry]) -> Result<()> {
        let mut data = self.load_data().unwrap_or_default();
        data.entries = entries.to_vec();
        self.save_data(&data)
    }

    fn get_sync_timestamp(&self) -> Result<Option<i64>> {
        Ok(self.load_data()?.sync_timestamp)
    }

    fn set_sync_timestamp(&self, timestamp: i64) -> Result<()> {
        let mut data = self.load_data().unwrap_or_default();
        data.sync_timestamp = Some(timestamp);
        self.save_data(&data)
    }
}
