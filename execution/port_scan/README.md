# Port Scan BOF

## Summary

Performs a bounded IPv4 port scan against one host using standard Winsock sockets. TCP checks use non-blocking `connect()` and report confirmed open ports. UDP checks send an empty datagram and only report ports that respond.

## Arguments

```text
port_scan <target> [ports] [protocol] [timeout_ms]
```

| Argument | Required | Description |
|---|---:|---|
| `target` | yes | IPv4 address or resolvable hostname |
| `ports` | no | `top20`, `top100`, one port, comma/space list, or `start-end`; default is `top20` |
| `protocol` | no | `0` TCP, `1` UDP, `2` both; default is TCP |
| `timeout_ms` | no | Per-port timeout from 1 to 30000 ms; default is 1000 |

## Usage

```text
beacon> inline-execute /path/to/port_scan.x64.o 192.168.1.100
beacon> inline-execute /path/to/port_scan.x64.o fileserver.corp.local 22,80,443,445,3389 0 1000
beacon> inline-execute /path/to/port_scan.x64.o 192.168.1.10 53,161 1 2000
```

## Example Output

```text
[i] Port scan target=192.168.1.100 protocol=tcp timeout_ms=1000 ports=20
[+] tcp/22 open
[+] tcp/80 open
[+] tcp/443 open
[+] tcp/3389 open
[i] Summary target=192.168.1.100 checks=20 tcp_open=4 tcp_closed=16 tcp_errors=0 udp_responsive=0 udp_no_response=0 udp_errors=0
```

## Limitations

- IPv4 only.
- One target per execution.
- No banner grabbing, service fingerprinting, SYN scanning, or OS detection.
- Runtime scales with `ports * protocol checks * timeout_ms`.