# net_use

Add, list, or remove mapped drives via MPR (`WNet*`). Arguments use the Beacon Data API (`short` command, then fields below).

| Cmd | Value | Arguments |
|-----|-------|-----------|
| Add | `1` | `share` (wstring, UNC), `username`, `password`, `device` (e.g. `Z:` or NULL for auto), `persist` (0/1), `requirePrivacy` (0/1, `CONNECT_ENCRYPTED`) |
| List | `2` | `target` (wstring, optional)—if set, **exact** local or remote name match, case-insensitive; omit or empty for all |
| Delete | `3` | `target` (wstring), `persist` (0/1), `force` (0/1) |

No args or buffer shorter than a command short → lists connections (same as list with no filter).

**Command layout example**

```
add (command=1):
  [1, "\\\\fileserver\\share", "CORP\\alice", "P@ssw0rd!", "Z:", 1, 0]
```

**Example**

```
[i] Enumerating connected network resources...
[+] Resource 1
    Status   : OK
    Type     : Disk
    Local    : Z:
    Remote   : \\fileserver\share
    Provider : Microsoft Windows Network
    User     : CORP\User
[i] Total resources listed: 1
```

**Credit:** Based on TrustedSec’s `netuse.c` from [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF).
