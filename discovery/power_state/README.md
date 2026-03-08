# Power State BOF

Identifies the host form factor as `Laptop`, `Desktop`, `Tablet`, `Server`, `Embedded`, or `Unknown`.

The BOF prefers SMBIOS enclosure data and falls back to Windows power status when firmware information is missing or inconclusive.

## Usage

```text
power_state
```

No arguments are required.

## Example Output

```text
[+] Form: Laptop
```

```text
[+] Form: Desktop
```

## Notes

- Uses `GetSystemFirmwareTable` to read SMBIOS chassis information.
- Falls back to `GetSystemPowerStatus` to distinguish battery-backed systems from fixed desktops.
- Returns a single concise value intended for quick host posture triage.
