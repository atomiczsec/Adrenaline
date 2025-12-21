# Community BOF Modernizations

The `community/` directory collects BOFs that are from outside this repository (the community) and have been fit to follow the framework constraints:

- No dependency on repository specific framework headers, implementations, or utility libraries
- No CRT
- Standardized output
- Safety caps to avoid hanging

## Current Community Ports

### [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)

| BOF | Description | Original |
| --- | --- | --- |
| [`schtask_enum/`](/community/schtask_enum) | Enumerate scheduled tasks w COM Task Scheduler API, clean output (no xml, which caused BOF to hang) | `schtaskenum` |


