# Applications Count BOF

## Summary

This Beacon Object File (BOF) enumerates installed applications by querying the number of subkeys under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` in the Windows Registry and returns the total count.

### Example Output

```
[*] Tasked beacon to run BOF
[+] host called home, sent: 10 bytes
[+] received output:
Found 123 installed applications.
```
