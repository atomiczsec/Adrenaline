# Proxy Enum BOF

Enumerates Windows proxy state from the main places that affect browser, service, and tooling egress. It gives one read-only snapshot of how a host is likely to reach the network.

## What It Checks

- `HKCU` WinINET proxy settings: `ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`
- Machine and policy-backed Internet Settings in `HKLM` and `HKCU`
- Hidden `ProxyMgr` cache entries under `HKLM\\SYSTEM\\CurrentControlSet\\Services\\iphlpsvc\\Parameters\\ProxyMgr`
  > Reference: [@awakecoding](https://x.com/awakecoding) on X and [AwakeCoding blog](https://awakecoding.com/posts/deleting-hidden-proxy-settings-that-break-windows-apps/).
- WinHTTP default proxy via `WinHttpGetDefaultProxyConfiguration()`
- WinHTTP binary connection settings: `WinHttpSettings`, `DefaultConnectionSettings`, `SavedLegacySettings`
- User-process environment variables: `http_proxy`, `https_proxy`, `ALL_PROXY`, `NO_PROXY`
- System-wide environment variables from `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment`
- Telemetry/service proxy value: `TelemetryProxyServer`
- WPAD / auto-discovery indicators and related WinHTTP settings
- Chrome proxy configuration from policy keys and local profile `Preferences`
- `.NET Framework` `machine.config` `defaultProxy` settings in standard `Framework` and `Framework64` paths

## Usage

The BOF takes no arguments.

```text
beacon> inline-execute /path/to/proxy_enum.x64.o
```

## Typical Output

When a proxy is configured, output can include:

- WinINET proxy server, bypass list, and PAC URL
- Per-user vs per-machine policy scope
- Hidden `ProxyMgr` `StaticProxy` values that can survive GUI disablement
- WinHTTP access type: direct, named proxy, or automatic proxy
- Presence of stored WinHTTP connection blobs
- User or system proxy-related environment variables
- WPAD autodetect state
- Chrome enforced, recommended, or profile-level proxy settings
- `.NET` `defaultProxy` attributes such as `enabled`, `usesystemdefault`, `proxyaddress`, `scriptlocation`, `bypassonlocal`, `autodetect`, and `bypasslist`

### Example Output

```text
[i] Starting proxy enumeration...

[i] Querying Registry (HKCU) / WinINET Proxy Settings...
  - Proxy Enabled: Yes
  - Proxy Server: http=proxy.corp.local:8080;https=proxy.corp.local:8080
  - Proxy Bypass: <local>;*.corp.local
  - PAC File (AutoConfigURL): http://wpad.corp.local/proxy.pac

[i] Querying WinHTTP Default Proxy...
  - Access Type: Named Proxy
  - Proxy Server: proxy.corp.local:8080
  - Proxy Bypass: <local>

[i] Querying WPAD (Web Proxy Auto-Discovery) Configuration...
  - AutoDetect: Enabled
  - AutoConfigURL: http://wpad.corp.local/proxy.pac

[i] Checking Chrome Proxy Configuration...
  - HKLM Chrome Policy ProxyMode: fixed_servers
  - HKLM Chrome Policy ProxyServer: proxy.corp.local:8080

[i] Checking .NET Framework Proxy Configuration...
  - .NET Framework v4.0.30319 machine.config defaultProxy section present
    enabled=true
    usesystemdefault=false
    proxyaddress=http://proxy.corp.local:8080
    bypassonlocal=true

[+] Proxy enumeration complete
```

If little is configured, the BOF still reports direct-access states such as `Proxy Enabled: No`, `Access Type: Direct`, or `AutoDetect: Disabled`.

## Limitations

- Environment-variable results are for the current process context, not every running process
- The BOF reports configuration state, not whether a proxy is reachable or actually enforced
