# Process Token Lister BOF

## Summary

This Beacon Object File (BOF) enumerates accessible tokens from running processes, showing user context, token type (primary/impersonation), and impersonation level. Supports optional filtering by PID or process name. SeDebugPrivilege is disabled by default for OPSEC.

### Example Output

```
[i] skipping seDebugPrivilege (OPSEC default).
[i] enumerating tokens for 195 processes
[+] PID: 1512  | Process: lsass.exe                 | User: NT AUTHORITY\SYSTEM | Type: Primary
[+] PID: 1234  | Process: explorer.exe              | User: CORP\jdoe | Type: Primary
[+] PID: 4567  | Process: chrome.exe                | User: CORP\jdoe | Type: Primary

[i] high-value processes (top 1)
[*] pid: 1512  | process: lsass.exe | domain: NT AUTHORITY\user: SYSTEM | type: SYSTEM

[i] opened: 45, skipped: 150, success: 23
```
