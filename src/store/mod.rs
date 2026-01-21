use crate::Result;
use crate::vault::SshEntry;
use serde::{Deserialize, Serialize};

pub mod file;
pub mod keyring;



pub trait Store: Send + Sync {
    fn load_entries(&self) -> Result<Vec<SshEntry>>;
    fn save_entries(&self, entries: &[SshEntry]) -> Result<()>;
    fn get_sync_timestamp(&self) -> Result<Option<i64>>;
    fn set_sync_timestamp(&self, timestamp: i64) -> Result<()>;
}

/// Build the store backend based on `STORE_API`.
///
/// - `STORE_API=file` (default): store data in `~/.ssh-vaultvarden-secret.json`
/// - `STORE_API=keyring`: store data in the OS keyring (Keychain / Credential Manager / Secret Service)
pub fn store_from_env() -> Result<Box<dyn Store>> {
    match std::env::var("STORE_API") {
        Ok(v) if v == "file" => Ok(Box::new(file::FileStore::default()?)),
        Ok(v) if v == "keyring" => Ok(Box::new(keyring::KeyringStore::default())),
        Ok(v) => Err(crate::Error::Store(format!(
            "Invalid STORE_API value '{}'. Use 'file' or 'keyring'.",
            v
        ))),
        Err(_) => Ok(Box::new(keyring::KeyringStore::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::file::FileStore;
    use tempfile::TempDir;

    #[test]
    fn test_store_trait() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test-store.json");
        let store = FileStore::new(store_path.clone());

        let entries = vec![
            SshEntry {
                user: "test".to_string(),
                ip: "1.2.3.4".to_string(),
                password: "pass".to_string(),
                notes: None,
            },
        ];

        store.save_entries(&entries).unwrap();
        let loaded = store.load_entries().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].user, "test");
    }
}

