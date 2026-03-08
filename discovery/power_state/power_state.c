#include <stddef.h>
#include "beacon.h"

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif
#ifndef WINAPI
#define WINAPI __stdcall
#endif
#ifndef __forceinline
#define __forceinline __inline__ __attribute__((always_inline))
#endif

typedef void *PVOID;
typedef unsigned char BYTE;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef int BOOL;

#ifdef _WIN64
typedef unsigned long long SIZE_T;
#else
typedef unsigned long SIZE_T;
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define MEM_COMMIT        0x00001000
#define MEM_RESERVE       0x00002000
#define MEM_RELEASE       0x00008000
#define PAGE_READWRITE    0x04

#define RSMB              0x52534D42u
#define SMBIOS_ENCLOSURE  3
#define SMBIOS_END        127

#define BATTERY_FLAG_NO_BATTERY 0x80
#define BATTERY_FLAG_UNKNOWN    0xFF
#define BATTERY_PERCENT_UNKNOWN 0xFF

DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$GetSystemPowerStatus(PVOID);
DECLSPEC_IMPORT UINT  WINAPI KERNEL32$GetSystemFirmwareTable(DWORD, DWORD, PVOID, DWORD);
DECLSPEC_IMPORT PVOID WINAPI KERNEL32$VirtualAlloc(PVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$VirtualFree(PVOID, SIZE_T, DWORD);

typedef struct {
    BYTE  ACLineStatus;
    BYTE  BatteryFlag;
    BYTE  BatteryLifePercent;
    BYTE  Reserved1;
    DWORD BatteryLifeTime;
    DWORD BatteryFullLifeTime;
} SYSTEM_POWER_STATUS_BOF;

static void *inline_memset(void *dst, int c, unsigned long len) {
    unsigned char *p = (unsigned char *)dst;
    while (len--) {
        *p++ = (unsigned char)c;
    }
    return dst;
}

static const char *classify_chassis(BYTE enclosureType) {
    switch (enclosureType) {
        case 8:
        case 9:
        case 10:
        case 14:
            return "Laptop";
        case 11:
        case 30:
        case 31:
        case 32:
            return "Tablet";
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 13:
        case 15:
        case 16:
        case 24:
            return "Desktop";
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 23:
        case 25:
        case 26:
        case 27:
        case 28:
        case 29:
            return "Server";
        case 33:
        case 34:
        case 35:
        case 36:
            return "Embedded";
        default:
            return NULL;
    }
}

static BYTE find_enclosure_type(const BYTE *table, DWORD len) {
    const BYTE *p = table;
    const BYTE *end = table + len;

    while (p + 4 <= end) {
        const BYTE type = p[0];
        const BYTE size = p[1];
        const BYTE *q;

        if (type == SMBIOS_END || size < 4) {
            break;
        }
        if (type == SMBIOS_ENCLOSURE && size > 5) {
            return p[5];
        }

        q = p + size;
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) {
            ++q;
        }
        q += 2;
        if (q <= p) {
            break;
        }
        p = q;
    }

    return 0;
}

static BYTE get_chassis_type(void) {
    UINT smbiosSize;
    PVOID buffer;
    BYTE chassis = 0;

    smbiosSize = KERNEL32$GetSystemFirmwareTable(RSMB, 0, NULL, 0);
    if (smbiosSize <= 8 || smbiosSize > 65536) {
        return 0;
    }

    buffer = KERNEL32$VirtualAlloc(NULL, smbiosSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        return 0;
    }

    if (KERNEL32$GetSystemFirmwareTable(RSMB, 0, buffer, smbiosSize) == smbiosSize) {
        BYTE *raw = (BYTE *)buffer;
        DWORD tableLen = *(DWORD *)(raw + 4);
        if (tableLen > 0 && tableLen <= (smbiosSize - 8)) {
            chassis = find_enclosure_type(raw + 8, tableLen);
        }
    }

    KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
    return chassis;
}

static const char *classify_from_power_status(void) {
    SYSTEM_POWER_STATUS_BOF powerStatus;
    BOOL hasBattery = FALSE;

    inline_memset(&powerStatus, 0, sizeof(powerStatus));
    if (!KERNEL32$GetSystemPowerStatus(&powerStatus)) {
        return NULL;
    }

    if (powerStatus.BatteryFlag != BATTERY_FLAG_UNKNOWN) {
        hasBattery = ((powerStatus.BatteryFlag & BATTERY_FLAG_NO_BATTERY) == 0);
    } else if (powerStatus.BatteryLifePercent != BATTERY_PERCENT_UNKNOWN) {
        hasBattery = TRUE;
    }

    return hasBattery ? "Laptop" : "Desktop";
}

void go(char *args, unsigned long alen) {
    const char *form;
    BYTE chassis;

    (void)args;
    (void)alen;

    chassis = get_chassis_type();
    form = classify_chassis(chassis);

    if (form == NULL) {
        form = classify_from_power_status();
    }
    if (form == NULL) {
        form = "Unknown";
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Form: %s\n", form);
}
