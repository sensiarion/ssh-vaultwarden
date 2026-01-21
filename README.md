# SSH Vault

CLI tool to ease your work with ssh configs, storing in vaultvarden/bitwarden.

To get started: run `sv init`, then `STORE_API=keyring sv sync`, and finally search/connect via `sv search <pattern>` /
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

I have ton of ssh configs to work with servers like `ssh <user>@<ip>` with storing email and password in vaultvarden.
And every time i should:

1. find specific config in my storage
2. copy paste ssh connection command
3. insert it
4. copy paste password

All of that takes small, but still measurable time, to end with it, this tool:

1. offers completion for your terminal (just type ip or user)
2. after you suggest, it will execute ssh command in your shell and paste password from vault to your copypaste buffer
3. That's it. you prepared to work on your server on connect

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
ttl_minutes = 60
organization_id = "org-123"
```

### Manual Configuration

You can also create the config file manually:

```toml
vault_url = "https://yourinstance.com"
email = "your.email@example.com" # optional, if not specified, will be required on sync command
ttl_minutes = 60 # optional, TTL in minutes for auto-sync
organization_id = "org-123" # optional, filters items by organization ID
```

## Storage (store backend)

This tool caches synced SSH entries (including passwords). Choose where that cache is stored via `STORE_API`:

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
- [ ] complete readme (with usage and developing blocks, talking about env vars and debug)
