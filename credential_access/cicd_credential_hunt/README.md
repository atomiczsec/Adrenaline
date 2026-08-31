# CI/CD Credential Hunt BOF

## Summary

Finds common CI/CD, cloud, and developer credential artifacts in the current Windows user's profile. With no argument, it reports only the path and size of each artifact; it does not read file contents.

`.gitconfig` and `.ssh\config` are classified as configuration, not credential artifacts. Their presence is useful context, but normally does not mean credentials exist.

## Checks

- Cloud credentials: `%USERPROFILE%\.aws\credentials`, `.aws\config`, `.aws\cli\cache\`, `%APPDATA%\gcloud\application_default_credentials.json`, and `%USERPROFILE%\.config\gcloud\application_default_credentials.json`. These are documented credential locations. [AWS](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html), [Google Cloud](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
- Deployment credentials: `%USERPROFILE%\.kube\config`, `%APPDATA%\terraform.d\credentials.tfrc.json`, and `%USERPROFILE%\.terraform.d\credentials.tfrc.json`. [Kubernetes](https://kubernetes.io/docs/reference/kubectl/kubectl/), [Terraform](https://developer.hashicorp.com/terraform/cli/commands/login)
- GitHub CLI: `%APPDATA%\GitHub CLI\hosts.yml`
- GitLab CLI: `%APPDATA%\glab-cli\config.yml` and `%USERPROFILE%\.config\glab-cli\config.yml`. It can contain plaintext tokens when keyring storage is unavailable. [GitLab](https://docs.gitlab.com/cli/auth/login/)
- Package and container credentials: `%USERPROFILE%\.npmrc`, `.pypirc`, `.docker\config.json`, `.cargo\credentials.toml`, legacy `.cargo\credentials`, `.m2\settings.xml`, `.gradle\gradle.properties`, and `.gem\credentials`. [Cargo](https://doc.rust-lang.org/stable/cargo/reference/config.html)
- Git: `%USERPROFILE%\.git-credentials` (credential store) and `.gitconfig` (configuration)
- Generic authentication: `%USERPROFILE%\.netrc`, `_netrc`, `.config\containers\auth.json`, and `.vault-token`
- SSH: `.ssh\config` (configuration), `id_rsa`, `id_ed25519`, `id_ecdsa`, `identity`, and up to eight top-level `*.pem` files

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
[+] AWS credentials: C:\Users\alice\.aws\credentials
[i]   Size: 88 bytes
[+] GitHub CLI auth: C:\Users\alice\AppData\Roaming\GitHub CLI\hosts.yml
[i]   Size: 191 bytes
[i] Git config: C:\Users\alice\.gitconfig
[i]   Size: 412 bytes
[i]   Classification: configuration (not a credential artifact)
[+] SSH private key: C:\Users\alice\.ssh\id_ed25519
[i]   Size: 411 bytes
[i] Summary: credential artifacts=2, config artifacts=1, ssh key candidates=1, previews=0, preview errors=0, truncated previews=0
```

## Operational notes and limits

- **Use presence mode first.** Verbose mode can display tokens or other secrets in Beacon output.
- Verbose previews read at most 640 bytes and emit at most three sanitized, non-empty lines; each line is capped at 127 characters.
- For private-key candidates, verbose mode reads up to 192 bytes and prints only a recognized PEM or OpenSSH header, never the key body.
- Discovery is read-only, limited to the current user's known paths, and does not recurse, decrypt artifacts, or inspect `.pem` files beyond the top level of `.ssh`.
- AWS CLI cache enumeration is capped at eight files in `%USERPROFILE%\.aws\cli\cache`.
- Windows-native locations (`%APPDATA%\gcloud`, `%APPDATA%\terraform.d`, `%APPDATA%\glab-cli`) are checked in addition to the Unix-style profile paths.
