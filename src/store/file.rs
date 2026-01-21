use crate::{Error, Result};
use crate::store::Store;
use crate::vault::SshEntry;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreData {
    entries: Vec<SshEntry>,
    #[serde(default)]
    sync_timestamp: Option<i64>,
}

pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Store("Could not find home directory".to_string()))?;
        Ok(home.join(".ssh-vaultvarden-secret.json"))
    }

    pub fn default() -> Result<Self> {
        Ok(Self::new(Self::default_path()?))
    }
}

impl Store for FileStore {
    fn load_entries(&self) -> Result<Vec<SshEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&self.path)?;
        let data: StoreData = serde_json::from_str(&content)?;
        Ok(data.entries)
    }

    fn save_entries(&self, entries: &[SshEntry]) -> Result<()> {
        // Load existing data to preserve sync_timestamp
        let mut data = if self.path.exists() {
            let content = std::fs::read_to_string(&self.path)?;
            serde_json::from_str::<StoreData>(&content).unwrap_or_else(|_| StoreData {
                entries: Vec::new(),
                sync_timestamp: None,
            })
        } else {
            StoreData {
                entries: Vec::new(),
                sync_timestamp: None,
            }
        };
        
        data.entries = entries.to_vec();
        // Note: sync_timestamp is updated separately via set_sync_timestamp
        let content = serde_json::to_string_pretty(&data)
            .map_err(|e| Error::Store(format!("Failed to serialize store: {}", e)))?;
        
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, content)?;
        Ok(())
    }

    fn get_sync_timestamp(&self) -> Result<Option<i64>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&self.path)?;
        let data: StoreData = serde_json::from_str(&content)?;
        Ok(data.sync_timestamp)
    }

    fn set_sync_timestamp(&self, timestamp: i64) -> Result<()> {
        // Load existing data to preserve entries
        let mut data = if self.path.exists() {
            let content = std::fs::read_to_string(&self.path)?;
            serde_json::from_str::<StoreData>(&content).unwrap_or_else(|_| StoreData {
                entries: Vec::new(),
                sync_timestamp: None,
            })
        } else {
            StoreData {
                entries: Vec::new(),
                sync_timestamp: None,
            }
        };
        
        data.sync_timestamp = Some(timestamp);
        let content = serde_json::to_string_pretty(&data)
            .map_err(|e| Error::Store(format!("Failed to serialize store: {}", e)))?;
        
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_file_store_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test.json");
        let store = FileStore::new(&store_path);

        let entries = vec![
            SshEntry {
                user: "user1".to_string(),
                ip: "1.1.1.1".to_string(),
                password: "pass1".to_string(),
                notes: None,
            },
            SshEntry {
                user: "user2".to_string(),
                ip: "2.2.2.2".to_string(),
                password: "pass2".to_string(),
                notes: None,
            },
        ];

        store.save_entries(&entries).unwrap();
        let loaded = store.load_entries().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].user, "user1");
        assert_eq!(loaded[1].user, "user2");
    }

    #[test]
    fn test_file_store_load_empty() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("nonexistent.json");
        let store = FileStore::new(&store_path);

        let loaded = store.load_entries().unwrap();
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn test_sync_timestamp() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test-sync.json");
        let store = FileStore::new(&store_path);

        // Initially no timestamp
        assert_eq!(store.get_sync_timestamp().unwrap(), None);

        // Set timestamp
        store.set_sync_timestamp(1234567890).unwrap();
        assert_eq!(store.get_sync_timestamp().unwrap(), Some(1234567890));

        // Save entries should preserve timestamp
        let entries = vec![
            SshEntry {
                user: "user1".to_string(),
                ip: "1.1.1.1".to_string(),
                password: "pass1".to_string(),
                notes: None,
            },
        ];
        store.save_entries(&entries).unwrap();
        assert_eq!(store.get_sync_timestamp().unwrap(), Some(1234567890));
    }
}

