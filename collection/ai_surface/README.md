# AI Surface Map BOF

## Summary

Maps AI tooling on Windows developer endpoints and highlights MCP configuration artifacts that may expose server definitions, commands, arguments, and embedded credentials.

## Purpose

`ai_surface` helps operators quickly understand whether an endpoint is interesting for AI-related collection. The BOF reports common Copilot and desktop AI traces, then pivots into MCP configuration discovery to identify developer-side supply chain exposure such as local MCP server launch commands and plaintext environment variables.

## How It Works

The BOF performs lightweight filesystem and registry enumeration only.

It currently checks:

- Windows Copilot package and storage paths
- Office Copilot indicators and cache paths
- Edge profile storage locations
- GitHub Copilot VS Code storage paths
- Third-party AI desktop traces for ChatGPT, Claude, Cursor, LM Studio, Ollama, and Windsurf
- MCP-related configuration files:
  - `%APPDATA%\Claude\claude_desktop_config.json`
  - `%USERPROFILE%\.claude.json`
  - `%USERPROFILE%\.cursor\mcp.json`
  - `%USERPROFILE%\.codeium\windsurf\mcp_config.json`
  - Project `.mcp.json`
  - Project `.cursor\rules\mcp.json`
- Likely VS Code / VS Code Insiders extension storage folders whose names suggest MCP-backed integrations

For discovered MCP config files, the BOF reads and prints a truncated ASCII preview from the start of the file so operators can immediately spot server names, commands, arguments, and likely secrets without follow-on tooling.

Project config discovery is intentionally bounded. The BOF checks the root and direct children of common developer directories such as:

- `%USERPROFILE%\source`
- `%USERPROFILE%\src`
- `%USERPROFILE%\code`
- `%USERPROFILE%\repos`
- `%USERPROFILE%\projects`
- `%USERPROFILE%\Documents\GitHub`
- `%USERPROFILE%\Documents\Repos`
- `%USERPROFILE%\Documents\Projects`
- `%USERPROFILE%\Desktop`

## Usage

```
beacon> inline-execute /path/to/ai_surface.x64.o
```

The BOF takes no arguments.

## Example Output

```text
[i] Mapping AI developer surface:

[i] Windows Copilot:
[+] Package: MicrosoftWindows.Client.CBS_cw5n1h2txyewy
[+] LocalState: C:\Users\user\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState
[+] Copilot: C:\Users\user\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\Copilot
[i] Copilot visible in taskbar

[i] GitHub Copilot:
[+] VS Code Copilot: C:\Users\user\AppData\Roaming\Code\User\globalStorage\github.copilot
[+] VS Code Copilot Chat: C:\Users\user\AppData\Roaming\Code\User\globalStorage\github.copilot-chat
[+] VS Code workspaceStorage: C:\Users\user\AppData\Roaming\Code\User\workspaceStorage

[i] Third-party AI:
[+] Claude: C:\Users\user\AppData\Roaming\Claude\Local Storage\leveldb
[+] Cursor: C:\Users\user\AppData\Roaming\Cursor\Local Storage\leveldb
[+] Windsurf: C:\Users\user\AppData\Roaming\Codeium\Windsurf

[i] MCP Configuration Discovery:
[+] Claude Desktop MCP Config: C:\Users\user\AppData\Roaming\Claude\claude_desktop_config.json
[i]   Size: 612 bytes
[i]   Preview:
[i]     {  "mcpServers": {    "filesystem": {      "command": "npx",      "args": [ "-y",
[i]     "@modelcontextprotocol/server-filesystem", "C:\\Users\\user\\Documents" ],      "env":
[i]     { "OPENAI_API_KEY": "sk-..." } } } }
[+] Cursor Global MCP Config: C:\Users\user\.cursor\mcp.json
[i]   Size: 304 bytes
[i]   Preview:
[i]     { "mcpServers": { "github": { "command": "docker", "args": [ "run", "--rm", ... ] } } }
[+] Project Cursor MCP: C:\Users\user\source\demo\.cursor\rules\mcp.json
[i]   Size: 211 bytes
[i]   Preview:
[i]     { "mcpServers": { "internal-api": { "command": "python", "args": [ "server.py" ] } } }
[i] MCP summary: 3 artifacts, 3 previews, 0 preview errors
```

## OPSEC Considerations

- MCP config previews may contain secrets, API keys, bearer tokens, internal hostnames, and developer workflow details directly in the callback output.
- Project-root scanning is bounded to reduce noise and filesystem churn, but it still touches a set of common developer directories that may be monitored.
- This BOF does not attempt ACL checks, network connections, or deep recursive crawling.
- File previews are truncated to the start of each config. Secrets further into large files may not be shown on the first run.

## Detection Coverage

- File access telemetry on MCP config paths and AI desktop storage locations
- EDR visibility into repeated `FindFirstFileW` / `FindNextFileW` enumeration in user profile directories
- Registry access to Office and taskbar Copilot indicators
- Possible DLP or content inspection if callback output is captured downstream

## Requirements

- Windows target
- User-context access to the relevant profile and project directories
- x64 Beacon Object File execution

## Limitations

- This implementation is Windows-focused; the macOS and Linux locations from the broader blueprint are not included in this BOF.
- Project MCP discovery is limited to direct children of common repo roots to keep runtime bounded.
- VS Code MCP coverage is heuristic because integrations are extension-defined and not standardized to a single config path.
- Only the start of each discovered config file is previewed.
