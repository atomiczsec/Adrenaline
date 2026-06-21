# IDE Extension Surface BOF

## Summary

Enumerates installed IDE extension manifests for VS Code, Cursor, Windsurf, Insiders, OSS, and server/remote profiles from per-user roots and summarizes extension identity, activation events, and capability signals.

## Purpose

`ide_extension_surface` helps operators quickly understand what editor-side extension surface exists on a Windows developer endpoint without recursively crawling source trees or unpacking extension code. The BOF focuses on direct child extension directories under common per-user roots for desktop IDEs, Insiders/OSS variants, and server/remote extension caches, then reads each readable `package.json` with a bounded file-read model to extract operator-useful metadata.

This is useful when assessing whether a host has rich local developer tooling, chat assistant integrations, MCP-adjacent plugins, or extension capabilities that expand the local attack surface. The output is intentionally concise: one top-level line per discovered manifest path plus a few metadata lines only when relevant fields are present.

## How It Works

The BOF expands a small set of `%USERPROFILE%`-based extension roots, verifies each root exists, and enumerates only direct child directories with `FindFirstFileW` / `FindNextFileW`. For each child, it checks for `package.json`, reads up to 65535 bytes, and uses lightweight string-based helpers to extract fields such as `publisher`, `name`, `displayName`, `version`, `activationEvents`, `enabledApiProposals`, `extensionKind`, `permissions`, `main`, `browser`, and selected `contributes` categories.

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

## OPSEC Considerations

- Risk level: Low to Medium. This BOF performs only local filesystem enumeration and bounded file reads, but repeated access to developer profile directories may still be visible to EDR.
- File access telemetry on `package.json` files beneath the supported `%USERPROFILE%`-based extension roots can be logged by endpoint products.
- The BOF does not recurse beyond direct child extension directories, execute extension code, or unpack archives.
- Manifest reads are truncated at 65535 bytes, so very large manifests may produce incomplete activation or capability summaries.

## Detection Coverage

- Primary ATT&CK: [T1518 - Software Discovery](https://attack.mitre.org/techniques/T1518/)
- Secondary ATT&CK: [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- Telemetry ideas:
  - User-profile file enumeration focused on IDE extension roots
  - Process-level sequences of `FindFirstFileW` / `FindNextFileW` followed by `CreateFileW` / `ReadFile` on `package.json`
  - Correlation with other developer-surface discovery or follow-on collection from the same session

## Requirements

- Windows target
- User-context access to the target profile’s IDE extension roots
- x64 Beacon Object File execution

## Limitations

- Only direct child extension directories are inspected.
- The parser is heuristic and string-based rather than a full JSON parser.
- Capability summaries are best-effort and may miss nested or unusually formatted manifest content.
- The BOF reports installed extension metadata only; it does not inspect extension code or runtime state.

## Related BOFs

- [ai_surface](../ai_surface/) for broader AI tooling and MCP artifact mapping on Windows developer endpoints.

## References

- [MITRE ATT&CK T1518 - Software Discovery](https://attack.mitre.org/techniques/T1518/)
- [MITRE ATT&CK T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [VS Code Extension Manifest](https://code.visualstudio.com/api/references/extension-manifest)
