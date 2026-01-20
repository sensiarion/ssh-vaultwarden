use crate::Result;
use serde::{Deserialize, Serialize};

pub mod mock;
pub mod real;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshEntry {
    pub user: String,
    pub ip: String,
    pub password: String,
}

impl SshEntry {
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();
        self.user.to_lowercase().contains(&pattern_lower)
            || self.ip.to_lowercase().contains(&pattern_lower)
    }
}

pub trait VaultApi: Send + Sync {
    fn search(&mut self, pattern: &str) -> Result<Vec<SshEntry>>;
    fn authenticate(&mut self, email: String, password: String) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_entry_matches_pattern() {
        let entry = SshEntry {
            user: "admin".to_string(),
            ip: "192.168.1.1".to_string(),
            password: "secret".to_string(),
        };

        assert!(entry.matches_pattern("admin"));
        assert!(entry.matches_pattern("192"));
        assert!(entry.matches_pattern("168.1"));
        assert!(!entry.matches_pattern("nonexistent"));
    }
}

