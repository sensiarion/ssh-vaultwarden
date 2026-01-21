use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub vault_url: String,
    pub email: Option<String>,
    /// TTL in minutes for auto-sync. If None, sync never expires.
    #[serde(default)]
    pub ttl_minutes: Option<u64>,
    /// Collection IDs to filter items (None = all accessible collections)
    #[serde(default)]
    pub collection_ids: Option<Vec<String>>,
    /// Organization ID to filter items (None = all accessible organizations)
    #[serde(default)]
    pub organization_id: Option<String>,
}

impl Config {
    pub fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Config("Could not find home directory".to_string()))?;
        Ok(home.join(".ssh-vaultvarden.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Err(Error::Config(
                "Config file not found. Run 'sv init' first.".to_string(),
            ));
        }

        let content = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    pub fn default_template() -> Self {
        Self {
            vault_url: "https://yourinstance.com".to_string(),
            email: None,
            ttl_minutes: None,
            collection_ids: None,
            organization_id: None,
        }
    }

    pub fn exists() -> bool {
        Self::config_path().map(|p| p.exists()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_config_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join(".ssh-vaultvarden.toml");

        // Mock the home directory by using temp dir
        let config = Config {
            vault_url: "https://test.example.com".to_string(),
            email: Some("testuser@example.com".to_string()),
            ttl_minutes: None,
            collection_ids: Some(vec!["collection-1".to_string(), "collection-2".to_string()]),
            organization_id: Some("org-123".to_string()),
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        fs::write(&config_file, toml_str).unwrap();

        let loaded: Config = toml::from_str(&fs::read_to_string(&config_file).unwrap()).unwrap();
        assert_eq!(loaded.vault_url, "https://test.example.com");
        assert_eq!(loaded.email, Some("testuser@example.com".to_string()));
        assert_eq!(
            loaded.collection_ids,
            Some(vec!["collection-1".to_string(), "collection-2".to_string()])
        );
        assert_eq!(loaded.organization_id, Some("org-123".to_string()));
    }

    #[test]
    fn test_config_default_template() {
        let config = Config::default_template();
        assert_eq!(config.vault_url, "https://yourinstance.com");
        assert_eq!(config.email, None);
    }
}
