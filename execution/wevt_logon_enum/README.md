# wevt_logon_enum BOF

## Summary
Enumerates recent Security log (successful/failed) logon events (Event IDs 4624,4625,4672) via the wevtapi API and prints remote workstation name/IP plus the target username.

## Notes
- Requires permission to read the Security log (typically admin or SYSTEM).

## Expected Output

```
[i] Querying Security log for logon events (EventID 4624,4625,4672)...
[+] user: alice               workstation: DESKTOP-1234
[+] user: bob                 workstation: 10.0.0.24
[+] user: carol               workstation: WORKSTATION-7F2A
[+] user: dave                workstation: 192.168.1.77
[i] Processed 4 logon events (max 64).
[i] wevt_logon_enum: done
```

- Only logon events that have a WorkstationName or IP Address are shown.
- Events with XML larger than 512 wide characters are skipped with a warning message.


