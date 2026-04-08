# AI Surface Map BOF

## Summary

Maps AI tooling on Windows developer endpoints and highlights MCP configuration artifacts that may expose server definitions, commands, arguments, and embedded credentials.

Checks:

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

The BOF checks the root and direct children of common developer directories such as:

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