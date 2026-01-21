use crate::vault::SshEntry;
use crate::Result;

pub mod file;
pub mod keyring;

fn store_api_from_env_or_config() -> Result<Option<String>> {
    if let Ok(v) = std::env::var("STORE_API") {
        return Ok(Some(v));
    }

    // Config is optional for store selection (e.g. `sv init` not run yet).
    match crate::config::Config::load() {
        Ok(cfg) => Ok(cfg.store_api),
        Err(_) => Ok(None),
    }
}

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
    match store_api_from_env_or_config()?.as_deref() {
        Some("file") => Ok(Box::new(file::FileStore::default()?)),
        Some("keyring") => {
            let store = keyring::KeyringStore::default();
            store.check_access()?;
            maybe_migrate_from_file_store(&store)?;
            Ok(Box::new(store))
        }
        Some(v) => Err(crate::Error::Store(format!(
            "Invalid store backend '{}'. Use 'file' or 'keyring' (via STORE_API or config store_api).",
            v
        ))),
        None => {
            let store = keyring::KeyringStore::default();
            if let Err(err) = store.check_access() {
                eprintln!(
                    "Keyring backend unavailable ({}). Falling back to file store.",
                    err
                );
                return Ok(Box::new(file::FileStore::default()?));
            }
            maybe_migrate_from_file_store(&store)?;
            Ok(Box::new(store))
        }
    }
}

fn maybe_migrate_from_file_store(keyring_store: &keyring::KeyringStore) -> Result<()> {
    // If keyring already has data, do nothing.
    let has_ts = keyring_store.get_sync_timestamp()?.is_some();
    let has_entries = !keyring_store.load_entries()?.is_empty();
    if has_ts || has_entries {
        return Ok(());
    }

    // If file store has data, migrate it into keyring once.
    let file_store = file::FileStore::default()?;
    let entries = file_store.load_entries()?;
    let ts = file_store.get_sync_timestamp()?;
    if entries.is_empty() && ts.is_none() {
        return Ok(());
    }

    if !entries.is_empty() {
        keyring_store.save_entries(&entries)?;
    }
    if let Some(ts) = ts {
        keyring_store.set_sync_timestamp(ts)?;
    }

    eprintln!(
        "Migrated existing store data from file into keyring. You may want to delete ~/.ssh-vaultvarden-secret.json"
    );
    Ok(())
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

        let entries = vec![SshEntry {
            user: "test".to_string(),
            ip: "1.2.3.4".to_string(),
            password: "pass".to_string(),
            notes: None,
        }];

        store.save_entries(&entries).unwrap();
        let loaded = store.load_entries().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].user, "test");
    }
}
