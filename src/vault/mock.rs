use crate::Result;
use crate::vault::{SshEntry, VaultApi};

pub struct MockVaultApi;

impl MockVaultApi {
    pub fn new() -> Self {
        Self
    }

    fn mock_entries() -> Vec<SshEntry> {
        vec![
            SshEntry {
                user: "admin".to_string(),
                ip: "192.168.1.1".to_string(),
                password: "admin123".to_string(),
            },
            SshEntry {
                user: "root".to_string(),
                ip: "10.0.0.1".to_string(),
                password: "rootpass".to_string(),
            },
            SshEntry {
                user: "deploy".to_string(),
                ip: "172.16.0.1".to_string(),
                password: "deploy456".to_string(),
            },
        ]
    }
}

impl VaultApi for MockVaultApi {
    fn authenticate(&mut self, _email: String, _password: String) -> Result<()> {
        // Mock doesn't need authentication
        Ok(())
    }

    fn search(&mut self, pattern: &str) -> Result<Vec<SshEntry>> {
        let entries = Self::mock_entries();
        let filtered: Vec<SshEntry> = entries
            .into_iter()
            .filter(|e| e.matches_pattern(pattern))
            .collect();
        Ok(filtered)
    }
}

impl Default for MockVaultApi {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_vault_search() {
        let mut vault = MockVaultApi::new();
        
        let results = vault.search("admin").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].user, "admin");
        
        let results = vault.search("192").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ip, "192.168.1.1");
        
        let results = vault.search("").unwrap();
        assert_eq!(results.len(), 3);
    }
}

