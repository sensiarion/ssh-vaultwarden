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

To connect to your vault you should specify config in `~/.ssh-vaultvarden.toml` or use `sv init` command

```toml
vault_url = "https://yourinstance.com"
email = "your.email@example.com" # optional, if not specified, will be required on sync command
collection_ids = ["collection-1", "collection-2"] # optional, filters items by collection IDs
organization_id = "org-123" # optional, filters items by organization ID
```

## Commands

- `sv init` - creates base config
- `sv init`

## Features

- [x] config loading from toml
- [ ] vault auth
- [ ] loading all configs by pattern `ssh <user>@<ip>` from vault with store in ~/.ssh-vaultvarden-secret.json file
- [ ] init command support
- [ ] search command support
- [ ] manual working via `sv connect <pattern>` / `sv -c <pattern>`
    - finds configs by pattern
    - executes ssh command if founds any
    - pastes password in buffer
    - friendly messages
- [ ] auto completion support
- [ ] caching loaded configs in system keyring
- [ ] caching prelogin data, to prevent full relogin on sync (it causes 429 error)
- [ ] custom search pattern (specify your own, not just `ssh <user>@<ip>`)

