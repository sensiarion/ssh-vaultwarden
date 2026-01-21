use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_init_command() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");

    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("init").arg("--non-interactive");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    // Provide input: vault URL and skip email
    cmd.write_stdin("https://test.example.com\n\n");
    cmd.assert().success();

    // Check that config file was created
    assert!(config_path.exists());

    // Check config content
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("vault_url"));
    assert!(content.contains("test.example.com"));
}

#[test]
fn test_init_command_existing_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");

    // Create existing config
    fs::write(&config_path, "vault_url = \"https://existing.com\"\n").unwrap();

    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("init");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    let output = cmd.assert().success();

    // Should report that config exists
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("already exists"));
}

#[test]
fn test_init_command_overwrite() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");

    // Create existing config
    fs::write(
        &config_path,
        "vault_url = \"https://old.com\"\nlogin = \"old@example.com\"\n",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("init").arg("--overwrite").arg("--non-interactive");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    // Provide new input
    cmd.write_stdin("https://new.example.com\nnewuser@example.com\n");
    cmd.assert().success();

    // Check that config was overwritten
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("new.example.com"));
    assert!(content.contains("newuser@example.com"));
    assert!(!content.contains("old.com"));
}

#[test]
fn test_search_command() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");
    let store_path = temp_dir.path().join(".ssh-vaultvarden-secret.json");

    // Create config
    fs::write(&config_path, "vault_url = \"https://test.com\"\n").unwrap();

    // Pre-populate store with entries
    let store_data = r#"{
  "entries": [
    {
      "user": "admin",
      "ip": "192.168.1.1",
      "password": "admin123"
    }
  ]
}"#;
    fs::write(&store_path, store_data).unwrap();

    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("search").arg("admin");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    let output = cmd.assert().success();

    // Should find admin entry from store
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("admin") || stdout.contains("Found"));
}

#[test]
fn test_search_command_no_matches() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");
    let store_path = temp_dir.path().join(".ssh-vaultvarden-secret.json");

    // Create config
    fs::write(&config_path, "vault_url = \"https://test.com\"\n").unwrap();

    // Pre-populate store with entries
    let store_data = r#"{
  "entries": [
    {
      "user": "user1",
      "ip": "1.1.1.1",
      "password": "pass1"
    }
  ]
}"#;
    fs::write(&store_path, store_data).unwrap();

    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("search").arg("nonexistent");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    let output = cmd.assert().success();

    // Should report no matches
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("No entries found"));
}

#[test]
fn test_connect_command_no_matches() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");

    // Create config
    fs::write(&config_path, "vault_url = \"https://test.com\"\n").unwrap();

    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("connect").arg("nonexistent");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    let output = cmd.assert().success();

    // With an empty store, should report that store is empty
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Store is empty"));
}

#[test]
fn test_connect_command_short_flag() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");
    let store_path = temp_dir.path().join(".ssh-vaultvarden-secret.json");

    // Create config
    fs::write(&config_path, "vault_url = \"https://test.com\"\n").unwrap();

    // Pre-populate store with entries
    let store_data = r#"{
  "entries": [
    {
      "user": "admin",
      "ip": "192.168.1.1",
      "password": "admin123"
    }
  ]
}"#;
    fs::write(&store_path, store_data).unwrap();

    // Test -c short flag
    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("-c").arg("admin");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    // The command will try to execute SSH which will fail, but that's okay
    // We just want to verify it finds the entry and copies password
    let output = cmd.assert();

    // Should find the entry (SSH execution will fail in test env, but that's expected)
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    // The command should at least try to connect (even if SSH fails)
    assert!(
        stdout.contains("admin")
            || stdout.contains("Connecting")
            || stdout.contains("Password copied")
    );
}

#[test]
fn test_pass_command_empty_store() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".ssh-vaultvarden.toml");

    // Create config
    fs::write(&config_path, "vault_url = \"https://test.com\"\n").unwrap();

    let mut cmd = Command::cargo_bin("ssh-vaultvarden").unwrap();
    cmd.arg("pass").arg("admin");
    cmd.env("HOME", temp_dir.path().to_str().unwrap());
    cmd.env("STORE_API", "file");
    let output = cmd.assert().success();

    // With an empty store, should report that store is empty
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Store is empty"));
}
