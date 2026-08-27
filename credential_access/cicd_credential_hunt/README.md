# CI/CD Credential Hunt BOF

## Summary

Finds common CI/CD and developer credential artifacts in the current Windows user's profile. With no argument, it reports only the path and size of each artifact; it does not read file contents.

## Checks

- GitHub CLI: `%APPDATA%\GitHub CLI\hosts.yml`
- Package and container credentials: `%USERPROFILE%\.npmrc`, `.pypirc`, and `.docker\config.json`
- Git: `%USERPROFILE%\.git-credentials` and `.gitconfig`
- SSH: `.ssh\config`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `identity`, and up to eight top-level `*.pem` files

## Arguments

| Argument | Result |
|---|---|
| *(none)* | Presence mode: paths and sizes only; no file-content reads. |
| `-verbose` or `verbose` | Reads bounded text previews and SSH key headers. |

Any other value prints usage and exits without scanning.

## Usage

```text
beacon> inline-execute /path/to/cicd_credential_hunt.x64.o
beacon> inline-execute /path/to/cicd_credential_hunt.x64.o -verbose
```

## Example output

```text
[i] Enumerating CI/CD credential artifacts on Windows developer paths
[i] Mode: presence (existence only)
[+] GitHub CLI auth: C:\Users\alice\AppData\Roaming\GitHub CLI\hosts.yml
[i]   Size: 191 bytes
[+] SSH private key: C:\Users\alice\.ssh\id_ed25519
[i]   Size: 411 bytes
[i] Summary: fixed artifacts=1, ssh configs=0, ssh key candidates=1, previews=0, preview errors=0, truncated previews=0
```

## Operational notes and limits

- **Use presence mode first.** Verbose mode can display tokens or other secrets in Beacon output.
- Verbose previews read at most 640 bytes and emit at most three sanitized, non-empty lines; each line is capped at 127 characters.
- For private-key candidates, verbose mode reads up to 192 bytes and prints only a recognized PEM or OpenSSH header, never the key body.
- Discovery is read-only, limited to the current user's known paths, and does not recurse, decrypt artifacts, or inspect `.pem` files beyond the top level of `.ssh`.
