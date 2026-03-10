# Proxy Enum BOF

Enumerates Windows proxy state from the main places that affect browser, service, and tooling egress. It gives one read-only snapshot of how a host is likely to reach the network.

## What It Checks

- `HKCU` WinINET proxy settings: `ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`
- Machine and policy-backed Internet Settings in `HKLM` and `HKCU`
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
- WinHTTP access type: direct, named proxy, or automatic proxy
- Presence of stored WinHTTP connection blobs
- User or system proxy-related environment variables
- WPAD autodetect state
- Chrome enforced, recommended, or profile-level proxy settings
- `.NET` `defaultProxy` attributes such as `enabled`, `usesystemdefault`, `proxyaddress`, `scriptlocation`, `bypassonlocal`, `autodetect`, and `bypasslist`

If little is configured, the BOF still reports direct-access states such as `Proxy Enabled: No`, `Access Type: Direct`, or `AutoDetect: Disabled`.

## Limitations

- Environment-variable results are for the current process context, not every running process
- The BOF reports configuration state, not whether a proxy is reachable or actually enforced
