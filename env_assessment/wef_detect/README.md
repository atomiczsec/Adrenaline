# Windows Event Forwarding (WEF) Detector BOF

## Summary

This Beacon Object File (BOF) detects Windows Event Forwarding (WEF) configuration, which indicates centralized logging. If found, that indicates security events are being forwarded to a central server.

## Example Output

```
[*] Windows Event Forwarding (WEF) Detector
[*] Checking for centralized logging configuration...

=== WEF Policy Subscriptions ===
[+] WEF subscription policy registry found
    Subscription 1: Server=http://collector.domain.com:5985/wsman/SubscriptionManager/WEC
[*] Total policy subscriptions: 1

=== Event Collector Subscriptions ===
[+] Event Collector subscriptions found

[+] Subscription: {12345678-1234-1234-1234-123456789012}
    Description: Security Events Forwarding
    URI: http://collector.domain.com:5985/wsman/SubscriptionManager/WEC
    Configuration Mode: Normal
    Enabled: Yes
    Delivery Mode: Push (0)

[*] Total active subscriptions: 1

=== WEF Forwarder Configuration ===
[+] WEF forwarder policy registry found
    Resource Usage Configured: Yes

[*] WEF detection completed.
[!] If WEF is configured, logs are being forwarded to a central server
```
