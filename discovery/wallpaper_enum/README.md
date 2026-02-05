# wallpaper_enum BOF

## Summary
Enumerates the current desktop wallpaper path for each attached monitor using the modern `IDesktopWallpaper` COM interface (Windows 8+).

## Purpose
Centralized wallpapers are sometimes on internal SMB shares or imaging servers. Enumerating the wallpaper targets can reveal network paths, domain trusts, and policy enforcement without touching disk or the network.

## Example Output
```
[i] Initializing COM (STA)...
[i] Found 2 monitor(s)
[+] Monitor 0 (\\\\.\\DISPLAY1): C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg
[+] Monitor 1 (\\\\.\\DISPLAY2): \\corp.acme.local\\sysvol\\wallpapers\\company_branded.jpg
[i] Enumeration complete
```

