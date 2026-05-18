# Service Control BOF

## Summary

`service_control` manages local Windows services through the Service Control Manager. It can query services, create a service, start or stop it, delete it, and update service failure actions.

## Arguments

```text
service_control query [service_name]
service_control create <service_name> <bin_path> [display_name] [start_type] [service_type] [error_control]
service_control start <service_name>
service_control stop <service_name>
service_control delete <service_name>
service_control failure <service_name> <reset_seconds> [reboot_msg] [command] [actions]
```

`query` without a service name lists local Win32 services and caps display at 200 rows. The optional `create` values are raw Windows constants for `dwStartType`, `dwServiceType`, and `dwErrorControl`; omitted values default to demand start, own-process service, and normal error control.

Failure actions use comma-separated `type:delay_ms` pairs. Valid types are `restart`, `reboot`, `run`, and `none`.

## Usage

```text
service_control query Spooler
service_control create DemoSvc C:\Windows\Temp\demo.exe "Demo Service"
service_control failure DemoSvc 86400 "" C:\Windows\Temp\recover.exe restart:5000,run:1000
```

## Example Output

```text
[i] Service: Spooler
    State:   RUNNING
    Type:    WIN32_OWN_PROCESS
    PID:     1284
    Display: Print Spooler
    Binary:  C:\Windows\System32\spoolsv.exe
    Start:   AUTO
    Account: LocalSystem
```

## Execution Notes

Local host services only. Creating, deleting, starting, stopping, or changing service configuration usually requires elevated rights.
