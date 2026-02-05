# Window List BOF

## Summary

Enumerates the titles of all visible windows on the current user's desktop, optionally including Process IDs (PIDs).

## Arguments

- `(none)`: List window titles only.
- `/pid`: List window titles with associated PID and process name.


## Example Output

```
[i] Enumerating window titles...
[i] Title: Inbox - hello@atomiczsec.net - Outlook
[i] Title: Adrenaline.docx - Word
[i] Title: New Tab - Google Chrome
[i] Found 3 visible windows with titles.
```

With `/pid`:
```
[i] Enumerating windows with process info...
[i] PID: 7892   | Process: OUTLOOK.EXE         | Title: Inbox - hello@atomiczsec.net - Outlook
[i] PID: 6543   | Process: WINWORD.EXE         | Title: Adrenaline.docx - Word
[i] PID: 8888   | Process: chrome.exe          | Title: New Tab - Google Chrome
[i] Found 3 visible windows with titles.
```
