# powershell_history

Collects PowerShell history artifacts from default PSReadLine and transcript locations. Useful for locating credentials or infrastructure. 

## Checks

- `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- `%APPDATA%\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt`
- `%USERPROFILE%\Documents\PowerShell_transcript*.txt`
- `%USERPROFILE%\Documents\PowerShell\Transcripts\*.txt`
- `%USERPROFILE%\My Documents\PowerShell_transcript*.txt`

## Example Output

```text
[*] Starting COFF Execution...

[+] PSReadLine history: C:\Users\gavin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
[i]   Size: 41291 bytes
[i]   start: (480 bytes)
[i]     irm https://get.atomiczsec.net | iex
[i]     git config --global user.name
[i]     ...
[i]   end: (480 bytes)
[i]     ...
[i]     cd discovery/asr_status

[i] No transcript files found in default Documents paths

[i] Summary: 1 PSReadLine, 0 transcripts, 0 errors

[*] COFF Finished.
```
