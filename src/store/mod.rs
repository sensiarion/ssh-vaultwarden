use crate::Result;
use crate::vault::SshEntry;
use serde::{Deserialize, Serialize};

pub mod file;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreData {
    entries: Vec<SshEntry>,
}

pub trait Store: Send + Sync {
    fn load_entries(&self) -> Result<Vec<SshEntry>>;
    fn save_entries(&self, entries: &[SshEntry]) -> Result<()>;
    fn get_sync_timestamp(&self) -> Result<Option<i64>>;
    fn set_sync_timestamp(&self, timestamp: i64) -> Result<()>;
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

