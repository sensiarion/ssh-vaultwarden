# SSH Vault

CLI tool to ease your work with ssh configs, storing in vaultvarden/bitwarden.

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

To connect to your vault you should specify config in `~/.ssh-vaultvarden.toml`. The easiest way is to use the `sv init` command.

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

## Commands

- `sv init` - Creates base config interactively
- `sv sync` - Syncs SSH entries from vault
- `sv search <pattern>` - Search for SSH entries matching pattern
- `sv connect <pattern>` - Connect to SSH entry matching pattern

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
- [ ] auto completion support
- [ ] caching loaded configs in system keyring
- [ ] caching prelogin data, to prevent full relogin on sync (it causes 429 error)
- [ ] custom search pattern (specify your own, not just `ssh <user>@<ip>`)

