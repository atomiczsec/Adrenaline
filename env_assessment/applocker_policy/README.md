# AppLocker Policy Analyzer BOF

## Summary

This Beacon Object File (BOF) enumerates AppLocker policy configurations, rule collections, and enforcement modes by scanning the relevant registry keys. Output is limited to high-level metadata to remain within BOF safety constraints; detailed rule contents should be reviewed offline.

## Example Output

```
[+] Executable Rules: Enforced, 5 rules
    {12345678-1234-1234-1234-123456789012}: Allow Program Files
    {87654321-4321-4321-4321-210987654321}: Allow Windows
    {11111111-1111-1111-1111-111111111111}: Allow Administrators
    {22222222-2222-2222-2222-222222222222}: Deny All
    {33333333-3333-3333-3333-333333333333}: Allow Signed
[-] DLL Rules: not configured
[+] Script Rules: AuditOnly, 3 rules
    {44444444-4444-4444-4444-444444444444}: Allow PowerShell
    {55555555-5555-5555-5555-555555555555}: Allow VBScript
    {66666666-6666-6666-6666-666666666666}: Deny Scripts
[+] MSI Rules: Enforced, 2 rules
    {77777777-7777-7777-7777-777777777777}: Allow MSI Installers
    {88888888-8888-8888-8888-888888888888}: Deny MSI
[-] AppX Rules: not configured
```
