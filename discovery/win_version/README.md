# win_version

Collects detailed Windows version information beyond basic OS version.

## Description

This BOF queries the registry and system APIs to provide a concise but detailed overview of the Windows installation. It is useful for security assessments to determine feature compatibility, patch level (via UBR), and installation age.

## Output

- **Product**: Full product name and display version (e.g., Windows 11 Pro 23H2).
- **Build**: Current build number and Update Build Revision (UBR).
- **Edition**: Edition ID and Installation Type.
- **Arch**: System architecture (x64, ARM64, etc.).
- **InstallDate**: Original installation date (Unix timestamp).

### Example Output

```
[+] Product     : Windows 11 Pro 23H2
[+] Build       : 22631 (UBR: 3235)
[+] Edition     : Professional Workstation / Client
[+] Arch        : x64
[+] InstallDate : 1614959917
```
