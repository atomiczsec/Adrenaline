# IDE Extension Surface BOF

## Summary

Enumerates installed IDE extension manifests for VS Code, Cursor, Windsurf, Insiders, OSS, and server/remote profiles from per-user roots and summarizes extension identity, activation events, and capability signals.

Supported roots:

- `%USERPROFILE%\.vscode\extensions`
- `%USERPROFILE%\.vscode-insiders\extensions`
- `%USERPROFILE%\.vscode-oss\extensions`
- `%USERPROFILE%\.cursor\extensions`
- `%USERPROFILE%\.windsurf\extensions`
- `%USERPROFILE%\.codeium\windsurf\extensions`
- `%USERPROFILE%\.vscode-server\extensions`
- `%USERPROFILE%\.cursor-server\extensions`
- `%USERPROFILE%\.vscode-remote\extensions`

## Usage

```text
beacon> inline-execute /path/to/ide_extension_surface.x64.o
```

The BOF takes no arguments.

## Example Output

```text
[i] IDE Extension Enumeration:

[i] VS Code: C:\Users\user\.vscode\extensions
[+] Manifest: C:\Users\user\.vscode\extensions\github.copilot-1.322.0\package.json
[i]   ID: github.copilot
[i]   Display Name: GitHub Copilot
[i]   Version: 1.322.0
[i]   Publisher: github
[i]   Activation: onStartupFinished, onView:github.copilot, onCommand:github.copilot.generate, ... (truncated)
[i]   Capabilities: apiProposals=lmTools, chatParticipants, languageModels, commands, main

[+] Manifest: C:\Users\user\.vscode\extensions\continue.continue-1.0.12\package.json
[i]   ID: continue.continue
[i]   Display Name: Continue
[i]   Version: 1.0.12
[i]   Publisher: continue
[i]   Activation: onStartupFinished
[i]   Capabilities: commands, authentication, main, mcp-adjacent

[i] Windsurf (Codeium root): C:\Users\user\.codeium\windsurf\extensions
[+] Manifest: C:\Users\user\.codeium\windsurf\extensions\codeium.codeium-1.28.4\package.json
[i]   ID: codeium.codeium
[i]   Version: 1.28.4
[i]   Publisher: codeium
[i]   Capabilities: extensionKind=workspace, commands, browser, terminal
```
- [MITRE ATT&CK T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [VS Code Extension Manifest](https://code.visualstudio.com/api/references/extension-manifest)
