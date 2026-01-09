# AI Surface Map BOF

## Summary

Maps which AI/Copilot tools are present on an endpoint and reports their key storage locations.

## What It Checks

- Windows Copilot
- Office Copilot
- Edge Copilot
- GitHub Copilot
- Third-party AI
  - ChatGPT desktop LevelDB store
  - Claude desktop LevelDB store
  - Cursor IDE desktop LevelDB store


```
[i] Mapping AI/Copilot tool presence:

[i] Windows Copilot:
[+] Package: MicrosoftWindows.Client.CBS_cw5n1h2txyewy
[+] LocalState: C:\Users\user\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState
[+] Copilot: C:\Users\user\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\Copilot
[i] Copilot visible in taskbar

[i] Office Copilot:
[+] Office installed
[+] Copilot: C:\Users\user\AppData\Local\Microsoft\Office\Copilot

[i] Edge Copilot:
[+] Default profile: C:\Users\user\AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb
[+] Profile 1: C:\Users\user\AppData\Local\Microsoft\Edge\User Data\Profile 1\Local Storage\leveldb

[i] GitHub Copilot:
[+] VS Code Copilot: C:\Users\user\AppData\Roaming\Code\User\globalStorage\github.copilot
[+] VS Code Copilot Chat: C:\Users\user\AppData\Roaming\Code\User\globalStorage\github.copilot-chat
[+] VS Code workspaceStorage: C:\Users\user\AppData\Roaming\Code\User\workspaceStorage

[i] Third-party AI:
[+] Cursor: C:\Users\user\AppData\Roaming\Cursor\Local Storage\leveldb
```
