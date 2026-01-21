use crate::config::Config;
use crate::store::{store_from_env, Store};
use crate::vault::SshEntry;
use crate::vault::{mock::MockVaultApi, real::RealVaultApi, VaultApi};
use crate::Result;
use clap::{ArgAction, Parser, Subcommand};
use inquire::{Password, Select, Text};
use std::env;
use std::io::{self, BufRead};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "sv")]
#[command(about = "SSH Vault - CLI tool to ease your work with ssh configs")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Connect to SSH server (short for 'connect')
    #[arg(short = 'c', long = "connect")]
    pub connect_pattern: Option<String>,

    /// Extra arguments passed to the underlying `ssh` command as-is.
    ///
    /// Examples:
    /// - `sv connect admin --opt -p 2222 -v`
    /// - `sv -c admin --opt -o StrictHostKeyChecking=no`
    #[arg(
        long = "opt",
        global = true,
        allow_hyphen_values = true,
        num_args = 1..,
        action = ArgAction::Append
    )]
    pub ssh_opts: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize configuration file
    Init {
        /// Overwrite existing config file if it exists
        #[arg(long)]
        overwrite: bool,
        /// Non-interactive mode: read from stdin or use defaults
        #[arg(long)]
        non_interactive: bool,
    },
    /// Search for SSH entries by pattern
    Search {
        /// Pattern to search for (matches user or IP)
        pattern: String,
    },
    /// Connect to SSH server
    Connect {
        /// Pattern to search for (matches user or IP)
        pattern: String,
    },
    /// Copy password of matching SSH entry to clipboard (does not run ssh)
    Pass {
        /// Pattern to search for (matches user or IP)
        pattern: String,
    },
    /// Sync entries from vault
    Sync,
}

pub struct App {
    #[allow(dead_code)] // Used for search/connect operations, but not directly accessed
    vault: Box<dyn VaultApi>,
    store: Box<dyn Store>,
}

impl App {
    pub fn new() -> Result<Self> {
        // Check environment variable for API selection
        let use_mock = env::var("SSH_VAULVARDE_API")
            .map(|v| v == "mock")
            .unwrap_or(false);

        let vault: Box<dyn VaultApi> = if use_mock {
            Box::new(MockVaultApi::new())
        } else {
            // Try to load config for real API
            match Config::load() {
                Ok(config) => Box::new(RealVaultApi::new(config)),
                Err(_) => {
                    // Config doesn't exist yet, use mock as fallback
                    Box::new(MockVaultApi::new())
                }
            }
        };

        let store = store_from_env()?;
        Ok(Self { vault, store })
    }

    pub fn run(
        &self,
        cmd: Option<Commands>,
        connect_pattern: Option<String>,
        ssh_opts: Vec<String>,
    ) -> Result<()> {
        // Handle -c/--connect flag (takes precedence)
        if let Some(pattern) = connect_pattern {
            if cmd.is_some() {
                eprintln!("Warning: --connect flag conflicts with subcommand. Using --connect.");
            }
            return self.handle_connect(&pattern, &ssh_opts);
        }

        // Handle subcommands
        match cmd {
            Some(Commands::Init {
                overwrite,
                non_interactive,
            }) => self.handle_init(overwrite, non_interactive),
            Some(Commands::Search { pattern }) => self.handle_search(&pattern),
            Some(Commands::Connect { pattern }) => self.handle_connect(&pattern, &ssh_opts),
            Some(Commands::Pass { pattern }) => self.handle_pass(&pattern),
            Some(Commands::Sync) => self.handle_sync(),
            None => {
                eprintln!("No command specified. Use 'sv --help' for usage information.");
                Ok(())
            }
        }
    }

    fn handle_init(&self, overwrite: bool, non_interactive: bool) -> Result<()> {
        if Config::exists() && !overwrite {
            println!("Config file already exists at {:?}", Config::config_path()?);
            println!("Use --overwrite flag to rewrite it.");
            return Ok(());
        }

        let (vault_url, email, ttl_minutes, collection_ids, organization_id) = if non_interactive
            || !atty::is(atty::Stream::Stdin)
        {
            // Non-interactive mode: read from stdin or use defaults
            self.read_from_stdin()?
        } else {
            // Interactive mode: use inquire prompts
            println!("Initializing SSH Vault configuration...");
            println!();

            let vault_url = Text::new("Vault URL:")
                .with_help_message(
                    "Enter your Vaultwarden instance URL (e.g., https://vault.example.com)",
                )
                .with_default("https://yourinstance.com")
                .prompt()
                .map_err(|e| crate::Error::Config(format!("Failed to read input: {}", e)))?;

            let email = Text::new("Email (optional):")
                .with_help_message("Enter your email address (leave empty to skip)")
                .prompt_skippable()
                .map_err(|e| crate::Error::Config(format!("Failed to read input: {}", e)))?
                .filter(|s| !s.trim().is_empty());

            let ttl_str = Text::new("TTL in minutes (optional):")
                .with_help_message(
                    "Enter TTL in minutes for auto-sync (leave empty for no auto-sync)",
                )
                .prompt_skippable()
                .map_err(|e| crate::Error::Config(format!("Failed to read input: {}", e)))?;

            let ttl_minutes = ttl_str
                .and_then(|s| s.trim().parse::<u64>().ok())
                .filter(|&v| v > 0);

            let collection_ids = Text::new("Collection IDs (optional):")
                .with_help_message("Enter collection IDs (comma-separated) to filter items")
                .prompt_skippable()
                .map_err(|e| crate::Error::Config(format!("Failed to read input: {}", e)))?
                .and_then(|s| Self::parse_collection_ids(&s));

            let organization_id = Text::new("Organization ID (optional):")
                .with_help_message("Enter organization ID to filter items (leave empty for all)")
                .prompt_skippable()
                .map_err(|e| crate::Error::Config(format!("Failed to read input: {}", e)))?
                .filter(|s| !s.trim().is_empty());

            (
                vault_url,
                email,
                ttl_minutes,
                collection_ids,
                organization_id,
            )
        };

        let config = Config {
            vault_url: vault_url.trim().to_string(),
            email,
            store_api: None,
            ttl_minutes,
            collection_ids,
            organization_id,
        };

        config.save()?;
        if !non_interactive {
            println!();
            println!("Config file created at {:?}", Config::config_path()?);
        }
        Ok(())
    }

    fn read_from_stdin(
        &self,
    ) -> Result<(
        String,
        Option<String>,
        Option<u64>,
        Option<Vec<String>>,
        Option<String>,
    )> {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        // Read vault URL (first line)
        let vault_url = lines
            .next()
            .transpose()
            .map_err(|e| crate::Error::Config(format!("Failed to read from stdin: {}", e)))?
            .unwrap_or_else(|| "https://yourinstance.com".to_string());

        // Read email (second line, optional)
        let email = lines
            .next()
            .transpose()
            .map_err(|e| crate::Error::Config(format!("Failed to read from stdin: {}", e)))?
            .and_then(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            });

        // Read TTL (third line, optional)
        let ttl_minutes = lines
            .next()
            .transpose()
            .ok()
            .flatten()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|&v| v > 0);

        // Read collection IDs (fourth line, optional)
        let collection_ids = lines
            .next()
            .transpose()
            .ok()
            .flatten()
            .and_then(|s| Self::parse_collection_ids(&s));

        // Read organization ID (fifth line, optional)
        let organization_id = lines.next().transpose().ok().flatten().and_then(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        Ok((
            vault_url,
            email,
            ttl_minutes,
            collection_ids,
            organization_id,
        ))
    }

    fn parse_collection_ids(input: &str) -> Option<Vec<String>> {
        let ids: Vec<String> = input
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect();

        if ids.is_empty() {
            None
        } else {
            Some(ids)
        }
    }

    fn handle_search(&self, pattern: &str) -> Result<()> {
        // Check if sync is needed
        self.check_and_prompt_sync()?;

        // Load entries from store
        let entries = self.store.load_entries()?;

        if entries.is_empty() {
            println!("Store is empty. Run 'sv sync' to fetch entries from vault.");
            return Ok(());
        }

        // Filter by pattern
        let matches: Vec<_> = entries
            .into_iter()
            .filter(|e| e.matches_pattern(pattern))
            .collect();

        if matches.is_empty() {
            println!("No entries found matching pattern: {}", pattern);
            return Ok(());
        }

        println!("Found {} matching entries:", matches.len());
        for entry in &matches {
            println!(
                "  ssh {}@{}{}",
                entry.user,
                entry.ip,
                self._display_notes(&entry.notes)
            );
        }

        Ok(())
    }

    fn _display_notes(&self, notes: &Option<String>) -> String {
        notes
            .as_ref()
            .map(|n| format!(" [{}]", n.replace("\n", " ")))
            .unwrap_or_default()
    }

    fn resolve_entry_by_pattern(&self, pattern: &str) -> Result<Option<SshEntry>> {
        // Check if sync is needed
        self.check_and_prompt_sync()?;

        // Load entries from store
        let entries = self.store.load_entries()?;

        if entries.is_empty() {
            println!("Store is empty. Run 'sv sync' to fetch entries from vault.");
            return Ok(None);
        }

        // Filter by pattern
        let matches: Vec<_> = entries
            .into_iter()
            .filter(|e| e.matches_pattern(pattern))
            .collect();

        if matches.is_empty() {
            println!("No entries found matching pattern: {}", pattern);
            return Ok(None);
        }

        // Select entry if multiple matches
        let entry = if matches.len() == 1 {
            matches[0].clone()
        } else {
            // Multiple matches - let user choose (or use first in non-interactive mode)
            if !atty::is(atty::Stream::Stdout) {
                // Non-interactive: use first match
                println!("Found {} matching entries, using first:", matches.len());
                for (i, e) in matches.iter().enumerate() {
                    println!(
                        "  {}. {}@{}{}",
                        i + 1,
                        e.user,
                        e.ip,
                        self._display_notes(&e.notes)
                    );
                }
                matches[0].clone()
            } else {
                // Interactive: let user choose
                println!("Found {} matching entries:", matches.len());
                let options: Vec<String> = matches
                    .iter()
                    .map(|e| format!("{}@{}{}", e.user, e.ip, self._display_notes(&e.notes)))
                    .collect();

                let selection = Select::new("Select entry:", options)
                    .prompt()
                    .map_err(|e| crate::Error::Config(format!("Failed to select entry: {}", e)))?;

                matches
                    .iter()
                    .find(|e| {
                        format!("{}@{}{}", e.user, e.ip, self._display_notes(&e.notes)) == selection
                    })
                    .cloned()
                    .ok_or_else(|| crate::Error::Config("Selected entry not found".to_string()))?
            }
        };

        Ok(Some(entry))
    }

    fn handle_pass(&self, pattern: &str) -> Result<()> {
        let Some(entry) = self.resolve_entry_by_pattern(pattern)? else {
            return Ok(());
        };

        self.copy_to_clipboard(&entry.password)?;
        println!("Password copied to clipboard!");
        println!(
            "Entry: {}@{}{}",
            entry.user,
            entry.ip,
            self._display_notes(&entry.notes)
        );
        Ok(())
    }

    fn handle_connect(&self, pattern: &str, ssh_opts: &[String]) -> Result<()> {
        let Some(entry) = self.resolve_entry_by_pattern(pattern)? else {
            return Ok(());
        };

        // Copy password to clipboard
        self.copy_to_clipboard(&entry.password)?;
        println!("Password copied to clipboard!");
        println!();

        // Execute SSH command
        println!("Connecting to {}@{}...", entry.user, entry.ip);
        println!("Password is in your clipboard - paste it when prompted.");
        println!();

        // Execute the SSH command
        // Note: This will block until SSH session ends
        let mut ssh = Command::new("ssh");
        // ssh options must come before the destination (user@host)
        ssh.args(ssh_opts)
            .arg(format!("{}@{}", entry.user, entry.ip));

        match ssh.status() {
            Ok(status) => {
                if !status.success() {
                    eprintln!(
                        "SSH command exited with status: {}",
                        status.code().unwrap_or(-1)
                    );
                }
            }
            Err(e) => {
                // If SSH is not available or command fails, just print the command
                eprintln!("Warning: Could not execute SSH command: {}", e);
                if ssh_opts.is_empty() {
                    eprintln!("You can manually run: ssh {}@{}", entry.user, entry.ip);
                } else {
                    eprintln!(
                        "You can manually run: ssh {} {}@{}",
                        ssh_opts.join(" "),
                        entry.user,
                        entry.ip
                    );
                }
                eprintln!("Password is already in your clipboard.");
            }
        }

        Ok(())
    }

    fn copy_to_clipboard(&self, text: &str) -> Result<()> {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|e| crate::Error::Config(format!("Failed to initialize clipboard: {}", e)))?;
        clipboard
            .set_text(text)
            .map_err(|e| crate::Error::Config(format!("Failed to copy to clipboard: {}", e)))?;
        Ok(())
    }

    fn handle_sync(&self) -> Result<()> {
        let config = Config::load()?;

        let cache_exists = {
            #[cfg(feature = "debug")]
            {
                std::path::Path::new(".ssh-vaultvarden-sync.json").is_file()
            }
            #[cfg(not(feature = "debug"))]
            {
                false
            }
        };
        #[cfg(feature = "debug")]
        if cache_exists {
            println!("Using cached vault data from .ssh-vaultvarden-sync.json");
        }

        // Get email if needed
        let email = if cache_exists {
            String::new()
        } else if let Some(ref cfg_email) = config.email {
            cfg_email.clone()
        } else {
            // Prompt for email if not in config
            if atty::is(atty::Stream::Stdin) {
                Text::new("Email:")
                    .with_help_message("Enter your email address")
                    .prompt()
                    .map_err(|e| crate::Error::Config(format!("Failed to read input: {}", e)))?
            } else {
                // Non-interactive: read from stdin
                let mut lines = io::stdin().lock().lines();
                lines
                    .next()
                    .transpose()
                    .map_err(|e| crate::Error::Config(format!("Failed to read from stdin: {}", e)))?
                    .ok_or_else(|| {
                        crate::Error::Config("Email required but not provided".to_string())
                    })?
            }
        };

        // Always prompt for password (never store it) - no confirmation
        let password = if cache_exists {
            String::new()
        } else if atty::is(atty::Stream::Stdin) {
            Password::new("Password:")
                .with_help_message("Enter your vault password")
                .without_confirmation()
                .prompt()
                .map_err(|e| crate::Error::Config(format!("Failed to read input: {}", e)))?
        } else {
            // Non-interactive: read from stdin
            let mut lines = io::stdin().lock().lines();
            // Skip email line if we just read it
            if config.email.is_none() {
                lines.next();
            }
            lines
                .next()
                .transpose()
                .map_err(|e| crate::Error::Config(format!("Failed to read from stdin: {}", e)))?
                .ok_or_else(|| {
                    crate::Error::Config("Password required but not provided".to_string())
                })?
        };

        if !cache_exists {
            println!("Authenticating with vault...");
        }

        // Authenticate with vault (mutable reference needed)
        // We need to get mutable access to vault
        // Since we can't mutate through trait object, we'll need to restructure
        // For now, we'll create a new vault instance for sync
        let use_mock = env::var("SSH_VAULVARDE_API")
            .map(|v| v == "mock")
            .unwrap_or(false);

        let mut vault: Box<dyn VaultApi> = if use_mock {
            Box::new(MockVaultApi::new())
        } else {
            Box::new(RealVaultApi::new(config.clone()))
        };

        if !cache_exists {
            vault.authenticate(email, password)?;
        }

        println!("Syncing entries from vault...");

        // Fetch entries from vault
        let entries = vault.search("")?;
        self.store.save_entries(&entries)?;

        // Update sync timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| crate::Error::Config(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;
        self.store.set_sync_timestamp(timestamp)?;

        println!("Synced {} entries from vault", entries.len());
        Ok(())
    }

    fn check_and_prompt_sync(&self) -> Result<()> {
        // Load config to check TTL
        let config = match Config::load() {
            Ok(cfg) => cfg,
            Err(_) => {
                // Config doesn't exist, that's okay - no auto-sync
                return Ok(());
            }
        };

        // If no TTL configured, skip check
        let ttl_minutes = match config.ttl_minutes {
            Some(ttl) => ttl,
            None => return Ok(()),
        };

        // Get last sync timestamp
        let last_sync = match self.store.get_sync_timestamp()? {
            Some(ts) => ts,
            None => {
                // Never synced - prompt user
                if atty::is(atty::Stream::Stdout) {
                    println!("Store has never been synced. Run 'sv sync' to fetch entries.");
                }
                return Ok(());
            }
        };

        // Calculate if sync is expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| crate::Error::Config(format!("Failed to get timestamp: {}", e)))?
            .as_secs() as i64;

        let elapsed_minutes = (now - last_sync) / 60;

        if elapsed_minutes >= ttl_minutes as i64 {
            // Sync expired - prompt user
            if atty::is(atty::Stream::Stdout) {
                println!(
                    "Store is {} minutes old (TTL: {} minutes). Run 'sv sync' to update.",
                    elapsed_minutes, ttl_minutes
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::file::FileStore;
    use tempfile::TempDir;

    #[test]
    fn test_search_handles_empty_store() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test-store.json");
        let store = FileStore::new(store_path);
        let vault = MockVaultApi::new();
        let app = App {
            vault: Box::new(vault),
            store: Box::new(store),
        };

        // Should not fetch from vault when store is empty - just report it
        let result = app.handle_search("admin");
        // This should succeed but report empty store
        assert!(result.is_ok());
    }

    #[test]
    fn cli_parses_opt_for_connect_subcommand() {
        let cli =
            Cli::try_parse_from(["sv", "connect", "admin", "--opt", "-p", "2222", "-v"]).unwrap();

        match cli.command {
            Some(Commands::Connect { pattern }) => assert_eq!(pattern, "admin"),
            other => panic!("expected Connect subcommand, got: {:?}", other),
        }
        assert_eq!(cli.connect_pattern, None);
        assert_eq!(cli.ssh_opts, vec!["-p", "2222", "-v"]);
    }

    #[test]
    fn cli_parses_opt_for_connect_short_flag() {
        let cli =
            Cli::try_parse_from(["sv", "-c", "admin", "--opt", "-o", "BatchMode=yes"]).unwrap();

        assert_eq!(cli.connect_pattern, Some("admin".to_string()));
        assert!(cli.command.is_none());
        assert_eq!(cli.ssh_opts, vec!["-o", "BatchMode=yes"]);
    }

    #[test]
    fn cli_parses_pass_subcommand() {
        let cli = Cli::try_parse_from(["sv", "pass", "admin"]).unwrap();

        match cli.command {
            Some(Commands::Pass { pattern }) => assert_eq!(pattern, "admin"),
            other => panic!("expected Pass subcommand, got: {:?}", other),
        }
        assert_eq!(cli.connect_pattern, None);
        assert!(cli.ssh_opts.is_empty());
    }
}
