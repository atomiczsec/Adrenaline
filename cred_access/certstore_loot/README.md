# certstore_loot BOF

## Summary
Enumerates local certificate stores to find certificates with exportable private keys and provides you with the path to export them.

## Usage

### Arguments (Optional)
- `<store_name> <CurrentUser|LocalMachine>` - Scan a specific store in a specific location
  - **Mythic:** Both arguments must be added as `string` data type
  - **Valid store names:** `MY`, `CA`, `ROOT`, `Disallowed`, `TrustedPeople`, `SmartCardRoot`
  - **Valid locations:** `CurrentUser`, `LocalMachine` (case-insensitive)

### Example Commands

**Mythic (Apollo execute-coff):**
```
execute_coff -Coff certstore_loot.x64.o -Function go -Timeout 30
execute_coff -Coff certstore_loot.x64.o -Function go -Timeout 30 -Arguments string:"MY" -Arguments string:"CurrentUser"
```


## Example Output
```
[+] CurrentUser\MY:
[!] High - [+] Thumbprint: 01:23:45:67:89:AB:CD:EF:...
[+] Subject: CN=User Cert
[i] EKU: ClientAuth
[+] Private key: PRESENT, EXPORTABLE
[!] Abuse: THEFT1 -> steal cert, use TokenCert/PassTheCert

[+] Summary: 1 exportable certificate(s) found (104 total scanned)
```

**When no exportable certificates are found:**
```
[i] Summary: No exportable certificates found (104 total scanned)
```

