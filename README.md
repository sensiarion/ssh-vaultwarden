# SSH Vault

`sv` is a small CLI that syncs SSH login entries from Vaultwarden/Bitwarden, lets you search them fast, and helps you connect
by copying the password to your clipboard.

To get started: install `sv`, run `sv init`, then `STORE_API=keyring sv sync`, and finally `sv search <pattern>` /
`sv -c <pattern>` (or copy only the password via `sv pass <pattern>`).

Example:

```bash
sv init
STORE_API=keyring sv sync
sv search admin
sv connect admin --opt -p 2222 -v
sv pass admin
```

Example output:

```text
Syncing entries from vault...
Synced 42 entries from vault
Found 1 matching entries:
  ssh admin@192.168.1.1
```

I have ton of ssh configs to work with servers like `ssh <user>@<ip>` with storing email and password in Vaultwarden.
And every time i should:

1. find specific config in my storage
2. copy paste ssh connection command
3. insert it
4. copy paste password

All of that takes small, but still measurable time, to end with it, this tool:

1. offers completion for your terminal (just type ip or user)
2. after you suggest, it will execute ssh command in your shell and paste password from vault to your copypaste buffer
3. That's it. you prepared to work on your server on connect

## Install

Releases are built and published to GitHub with cargo-dist.

- **macOS / Linux (shell installer)**:

```bash
curl -LsSf https://github.com/sensiarion/ssh-vaultwarden/releases/latest/download/ssh-vaultvarden-installer.sh | sh
sv --version
```

**WSL warning**: to run this util on wsl, you need to install keyring into your wsl.

Ubuntu/Debian

```
apt-get update
apt install -y gnome-keyring python3-venv python3-dev
pip3 install --upgrade pip
pip3 install keyring

# to check it's working
echo 'somecredstorepass' | gnome-keyring-daemon --unlock
```

install tutorial adapted from [here](https://github.com/jaraco/keyring#using-keyring-on-headless-linux-systems)

- **Windows (PowerShell installer)**: (keyring is not supported, only file mode)

```powershell
irm https://github.com/sensiarion/ssh-vaultwarden/releases/latest/download/ssh-vaultvarden-installer.ps1 | iex
sv --version
```

- **From source (Rust)**:

```bash
git clone https://github.com/sensiarion/ssh-vaultwarden.git
cd ssh-vaultwarden
cargo install --path .
sv --version
```

## Configuration

To connect to your vault you should specify config in `~/.ssh-vaultvarden.toml`. The easiest way is to use the `sv init`
command.

### Generating Config

Run the interactive setup command:

```bash
sv init
```

This will prompt you for:

- **Vault URL**: Your Vaultwarden/Bitwarden instance URL (e.g., `https://vault.example.com`)
- **Email** (optional): Your email address (if not provided, will be asked during sync)
- **TTL in minutes** (optional): Auto-sync expiration time (leave empty for no expiration)
- **Collection IDs** (optional): Comma-separated collection IDs to filter items
- **Organization ID** (optional): Organization ID to filter items

### Example

After running `sv init`, you'll get a config file at `~/.ssh-vaultvarden.toml`:

```toml
vault_url = "https://vault.example.com"
email = "your.email@example.com"
store_api = "keyring"
ttl_minutes = 60
organization_id = "org-123"
```

### Manual Configuration

You can also create the config file manually:

```toml
vault_url = "https://yourinstance.com"
email = "your.email@example.com" # optional, if not specified, will be required on sync command
store_api = "keyring" # optional, "keyring" or "file" (can also be set via STORE_API env var)
ttl_minutes = 60 # optional, TTL in minutes for auto-sync
organization_id = "org-123" # optional, filters items by organization ID
```

## Storage (store backend)

This tool caches synced SSH entries (including passwords). Choose where that cache is stored via:

- `STORE_API=file|keyring` (env var, **overrides config**)
- `store_api = "file" | "keyring"` in `~/.ssh-vaultvarden.toml`

- **Recommended (secure)**: `STORE_API=keyring`
    - Uses your OS keyring (macOS Keychain / Windows Credential Manager / Linux Secret Service).
    - Linux note: you typically need a Secret Service provider (e.g. GNOME Keyring / KWallet) running for keyring access
      to work.
- **Insecure fallback**: `STORE_API=file`
    - Writes plaintext JSON to `~/.ssh-vaultvarden-secret.json`.

Example (secure keyring store):

```bash
STORE_API=keyring sv sync
sv search admin
```

## Commands

- `sv init` - Creates base config interactively
- `sv sync` - Syncs SSH entries from vault
- `sv search <pattern>` - Search for SSH entries matching pattern
- `sv connect <pattern>` - Connect to SSH entry matching pattern and copy ssh password to clipboard
    - Pass extra ssh args with `--opt`, e.g. `sv connect admin --opt -p 2222 -o BatchMode=yes`
    - also can be used as `sv -c` shortcut
- `sv pass <pattern>` - Copy password of matching SSH entry to clipboard (does not run ssh)

## Developing

If you just want to hack on the code locally:

```bash
git clone https://github.com/sensiarion/ssh-vaultwarden.git
cd ssh-vaultwarden
cargo test
cargo run -- --help
```

Useful env vars / flags:

- `STORE_API=keyring|file` to choose where the cache is stored
- `RUST_LOG=debug` for verbose logs
- `--features debug` enables reading cached vault data from `.ssh-vaultvarden-sync.json` during `sv sync`

### cargo-dist (packaging / releases)

To validate packaging locally (same config as CI):

```bash
curl -LsSf https://github.com/axodotdev/cargo-dist/releases/download/v0.29.0/cargo-dist-installer.sh | sh
dist plan
dist build
```

Releases are produced by pushing a semver tag, for example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Features

- [x] config loading from toml
- [x] vault auth
- [x] vault decrypting
- [x] loading all configs by pattern `ssh <user>@<ip>` from vault with store in ~/.ssh-vaultvarden-secret.json file
- [x] init command support
- [x] search command support
- [x] manual working via `sv connect <pattern>` / `sv -c <pattern>`
    - finds configs by pattern
    - executes ssh command if founds any
    - pastes password in buffer
    - friendly messages
- [ ] ~~auto completion support~~
- [x] caching loaded configs in system keyring
- [ ] caching prelogin data, to prevent full relogin on sync (it causes 429 error)
- [ ] custom search pattern (specify your own, not just `ssh <user>@<ip>`)
- [x] provide additional args to ssh (`--opt`)
- [ ] fix opt parsing
- [x] pass command with same logic with connect, but just insert password in buffer
- [x] complete readme (with usage and developing blocks, talking about env vars and debug)
