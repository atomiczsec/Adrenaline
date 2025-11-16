# Window Handles Enum BOF

## Summary

This Beacon Object File (BOF) enumerates window handles across all system processes and uses a legitimate window handle to access the clipboard, potentially evading detection.

### Example Output

```
[+] Found 156 total processes
[+] Actionable window (HWND: 0x000A0B1C) PID: 5432
    Title: Microsoft Edge
[*] Actionable windows found: 23
[+] Using HWND 0x000A0B1C for clipboard access
[+] Clipboard contents: password123
```
