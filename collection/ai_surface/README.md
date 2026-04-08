# AI Surface Map BOF

## Summary

Maps AI tooling on Windows developer endpoints and highlights MCP, agent, and tool configuration artifacts that may expose server definitions, commands, arguments, local rules, and embedded credentials.

Checks:

- Windows Copilot package and storage paths
- Office Copilot indicators and cache paths
- Edge profile storage locations
- GitHub Copilot VS Code storage paths
- Third-party AI desktop traces for ChatGPT, Claude, Cursor, LM Studio, Ollama, and Windsurf
- Likely VS Code / VS Code Insiders extension storage folders whose names suggest MCP-backed integrations

Additional AI configuration and agent artifacts:

Claude:
- `%APPDATA%\Claude\claude_desktop_config.json`
- `%USERPROFILE%\.claude.json`
- `%USERPROFILE%\.claude\settings.json`
- `%USERPROFILE%\.claude\agents\`
- Project `.claude\settings.json`
- Project `.claude\settings.local.json`
- Project `CLAUDE.md`

Cursor:
- `%USERPROFILE%\.cursor\mcp.json`
- `%APPDATA%\Cursor\User\globalStorage\state.vscdb`
- `%APPDATA%\Cursor\User\globalStorage\*\state.vscdb`
- Project `.cursor\rules\`
- Project `.cursor\rules\mcp.json`
- Project `.cursor\environment.json`
- Project `.cursorrules`

Codex CLI:
- `%USERPROFILE%\.codex\config.toml`
- `%USERPROFILE%\.codex\AGENTS.md`
- `%USERPROFILE%\.codex\skills\`
- `%USERPROFILE%\.codex\rules\`
- `%USERPROFILE%\.codex\history\`
- Project `AGENTS.md`
- Project `AGENTS.override.md`

Gemini CLI:
- `%USERPROFILE%\.gemini\`
- Project `.gemini\`

Shared MCP-style project config:
- Project `.mcp.json`

Windsurf:
- `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

Additional Claude/Codex/Cursor/Gemini and agent-document paths in this list were derived from `preludeorg/cua-kit` `cua-enum` coverage:
https://github.com/preludeorg/cua-kit/tree/main/cua-enum


Project artifact discovery checks the root and direct children of common developer directories such as:

- `%USERPROFILE%\source`
- `%USERPROFILE%\src`
- `%USERPROFILE%\code`
- `%USERPROFILE%\repos`
- `%USERPROFILE%\projects`
- `%USERPROFILE%\Documents\GitHub`
- `%USERPROFILE%\Documents\Repos`
- `%USERPROFILE%\Documents\Projects`
- `%USERPROFILE%\Desktop`

It does not recursively enumerate drives or full-disk discovery.

## Usage

```
beacon> inline-execute /path/to/ai_surface.x64.o
```

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

[i] AI Configuration and Agent Artifact Discovery:
[+] Claude Desktop MCP Config: C:\Users\user\AppData\Roaming\Claude\claude_desktop_config.json
[i]   Size: 612 bytes
[i]   Preview:
[i]     {  "mcpServers": {    "filesystem": {      "command": "npx",      "args": [ "-y",
[i]     "@modelcontextprotocol/server-filesystem", "C:\\Users\\user\\Documents" ],      "env":
[i]     { "OPENAI_API_KEY": "sk-..." } } } }
[+] Claude User Settings: C:\Users\user\.claude\settings.json
[+] Codex Config: C:\Users\user\.codex\config.toml
[+] Project AGENTS.md: C:\Users\user\source\demo\AGENTS.md
[+] Cursor Global MCP Config: C:\Users\user\.cursor\mcp.json
[+] Project Cursor MCP: C:\Users\user\source\demo\.cursor\rules\mcp.json
[+] Project Gemini Directory: C:\Users\user\source\demo\.gemini
[i] Artifact summary: 7 hits
```
