# Power Status BOF

## Summary

This Beacon Object File (BOF) reports hardware posture and power state by inferring laptop vs desktop/tablet, AC vs battery, and likely sensitivity using low-friction Win32 signals (no WMI).

### Example Output

```
PLATFORM=Laptop POWER=Battery BATTERY=23 SENSITIVITY=High CONFIDENCE=0.9 NOTE=battery_low CHASSIS=Laptop CPU_PCT=38
```
