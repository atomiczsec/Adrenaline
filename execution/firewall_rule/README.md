# Firewall Rule BOF

Add, remove, or query Windows Firewall rules via the COM API (`INetFwPolicy2`) without spawning `netsh.exe` or `cmd.exe`. Useful for pivoting inside networks.

## Arguments

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `add` | `<name> <dir> <action> <protocol> [localport] [remoteport] [profile]` | Add a firewall rule |
| `remove` | `<name>` | Remove a firewall rule by name |
| `query` | `<name>` | Query details of a firewall rule |
| `list` | *(no arguments)* | Enumerate a deduplicated firewall rule view (capped at 200 unique rows) |

**Parameter values:**
- `dir`: `in` or `out`
- `action`: `allow` or `block`
- `protocol`: `tcp`, `udp`, or `any`
- `localport`: required for `tcp` and `udp`; leave empty or omit it for `any`
- `remoteport`: optional; if present, specify it before `profile`
- `profile`: `domain`, `private`, `public`, or `all` (default: `all`)


## Example Output

**Add rule:**
```
[+] Added firewall rule: name="pivot" dir=in action=allow proto=tcp localport=4444
```

**Query rule:**
```
[i] Rule: pivot
    Enabled:    Yes
    Direction:  IN
    Action:     ALLOW
    Protocol:   TCP
    LocalPort:  4444
    Profiles:   All
```

**List all rules:**
```
[i] Enumerating firewall rules (deduplicated view, cap: 200)
[+] Rule 1: Core Networking - DHCP (UDP-In)
    Direction: IN | Action: ALLOW | Protocol: UDP | Enabled: Yes
    LocalPort: 68 | RemotePort: -
[+] Rule 2: Core Networking - DNS (UDP-Out)
    Direction: OUT | Action: ALLOW | Protocol: UDP | Enabled: Yes
    LocalPort: - | RemotePort: 53
[+] Rule 3: pivot
    Direction: IN | Action: ALLOW | Protocol: TCP | Enabled: Yes
    LocalPort: 4444 | RemotePort: -
[+] Rule 4: Windows Remote Management (HTTP-In)
    Direction: IN | Action: ALLOW | Protocol: TCP | Enabled: Yes
    LocalPort: 5985 | RemotePort: -
  ...
[i] 187 firewall rules total, 173 unique rows
[i] Suppressed 14 duplicate rows
```

`list` collapses rows that share the same name, direction, action, protocol, enabled state, and displayed ports.

**Remove rule:**
```
[+] Removed firewall rule: "pivot"
```

**Rule not found:**
```
[-] Rule "pivot" not found: 0x80070002
```

**Error (insufficient privileges):**
```
[-] Failed to add rule "pivot": 0x80070005
```
