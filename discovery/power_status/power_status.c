// Power State / Hardware Posture BOF
// Determines laptop vs desktop, power source, and likely sensitivity.

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif
#ifndef WINAPI
#define WINAPI __stdcall
#endif

#ifndef __forceinline
#define __forceinline __inline__ __attribute__((always_inline))
#endif

typedef void* PVOID;
typedef void* HANDLE;
typedef void* HMODULE;
typedef void* FARPROC;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned int UINT;
typedef int BOOL;
typedef const wchar_t* LPCWSTR;
typedef const char* LPCSTR;

#ifdef _WIN64
typedef unsigned long long ULONG_PTR;
#else
typedef unsigned long ULONG_PTR;
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

// Beacon API (minimal)
DECLSPEC_IMPORT void BeaconPrintf(int type, char *fmt, ...);
#ifndef CALLBACK_OUTPUT
#define CALLBACK_OUTPUT 0x0
#endif
#ifndef CALLBACK_ERROR
#define CALLBACK_ERROR 0x0d
#endif

// Kernel32 imports
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$GetSystemPowerStatus(PVOID);
DECLSPEC_IMPORT UINT  WINAPI KERNEL32$GetSystemFirmwareTable(DWORD, DWORD, PVOID, DWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT void  WINAPI KERNEL32$GetSystemInfo(PVOID);

typedef struct _SYSTEM_POWER_STATUS_MIN {
    BYTE ACLineStatus;
    BYTE BatteryFlag;
    BYTE BatteryLifePercent;
    BYTE Reserved1;
    DWORD BatteryLifeTime;
    DWORD BatteryFullLifeTime;
} SYSTEM_POWER_STATUS_MIN, *PSYSTEM_POWER_STATUS_MIN;

typedef struct _SYSTEM_INFO_MIN {
    union {
        DWORD dwOemId;
        struct {
            WORD wProcessorArchitecture;
            WORD wReserved;
        };
    };
    DWORD   dwPageSize;
    PVOID   lpMinimumApplicationAddress;
    PVOID   lpMaximumApplicationAddress;
    ULONG_PTR dwActiveProcessorMask;
    DWORD   dwNumberOfProcessors;
    DWORD   dwProcessorType;
    DWORD   dwAllocationGranularity;
    WORD    wProcessorLevel;
    WORD    wProcessorRevision;
} SYSTEM_INFO_MIN, *PSYSTEM_INFO_MIN;

typedef struct _RAW_SMBIOS_DATA {
    BYTE  Used20CallingMethod;
    BYTE  SMBIOSMajorVersion;
    BYTE  SMBIOSMinorVersion;
    BYTE  DmiRevision;
    DWORD Length;
    BYTE  SMBIOSTableData[1];
} RAW_SMBIOS_DATA, *PRAW_SMBIOS_DATA;

typedef struct _PROCESSOR_POWER_INFORMATION {
    ULONG Number;
    ULONG MaxMhz;
    ULONG CurrentMhz;
    ULONG MhzLimit;
    ULONG MaxIdleState;
    ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, *PPROCESSOR_POWER_INFORMATION;

typedef DWORD (WINAPI *pfnCallNtPowerInformation)(ULONG, PVOID, ULONG, PVOID, ULONG);

#define BATTERY_FLAG_NO_BATTERY 0x80
#define BATTERY_FLAG_UNKNOWN    0xFF
#define BATTERY_PERCENT_UNKNOWN 0xFF

#define AC_LINE_OFFLINE 0
#define AC_LINE_ONLINE  1
#define AC_LINE_UNKNOWN 255

#define FIRMWARE_TABLE_SIGNATURE_RSMB 0x52534D42u
#define SMBIOS_TYPE_SYSTEM_ENCLOSURE 3
#define SMBIOS_TYPE_END_OF_TABLE 127

#define POWER_INFO_PROCESSOR_INFORMATION 11

static __forceinline FARPROC gp(LPCWSTR modW, LPCSTR nameA) {
    HMODULE m = KERNEL32$GetModuleHandleW(modW);
    if (!m) m = KERNEL32$LoadLibraryW(modW);
    if (!m) return (FARPROC)0;
    return KERNEL32$GetProcAddress(m, nameA);
}

static __forceinline void inline_memset(void* dst, int c, unsigned long len) {
    unsigned char* p = (unsigned char*)dst;
    while (len--) *p++ = (unsigned char)c;
}

static __forceinline unsigned int inline_strlen(const char* s) {
    unsigned int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static __forceinline void inline_strcpy(char* dst, unsigned int cap, const char* src) {
    unsigned int i = 0;
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = 0; return; }
    for (i = 0; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = 0;
}

static __forceinline void inline_strcat(char* dst, unsigned int cap, const char* src) {
    unsigned int len = inline_strlen(dst);
    unsigned int i = 0;
    if (!src || cap == 0 || len >= cap) return;
    for (i = 0; len + i + 1 < cap && src[i]; i++) dst[len + i] = src[i];
    dst[len + i] = 0;
}

static __forceinline void inline_utoa(char* dst, unsigned int cap, unsigned int val) {
    char tmp[16];
    unsigned int i = 0;
    unsigned int j = 0;
    if (!dst || cap == 0) return;
    if (val == 0) {
        if (cap > 1) { dst[0] = '0'; dst[1] = 0; }
        else dst[0] = 0;
        return;
    }
    while (val > 0 && i + 1 < sizeof(tmp)) {
        tmp[i++] = (char)('0' + (val % 10));
        val /= 10;
    }
    if (i == 0) { dst[0] = 0; return; }
    if (i >= cap) i = cap - 1;
    for (j = 0; j < i; j++) dst[j] = tmp[i - j - 1];
    dst[j] = 0;
}

static __forceinline void append_note(char* note, unsigned int cap, const char* add) {
    unsigned int len = inline_strlen(note);
    if (!add || add[0] == 0) return;
    if (len == 0) {
        inline_strcpy(note, cap, add);
        return;
    }
    inline_strcat(note, cap, ",");
    inline_strcat(note, cap, add);
}

static const char* chassis_class_from_type(BYTE t) {
    if (t == 30 || t == 31 || t == 32) return "Tablet";
    if (t == 8 || t == 9 || t == 10 || t == 14) return "Laptop";
    if (t == 3 || t == 4 || t == 6) return "Desktop";
    return "Unknown";
}

static BYTE find_chassis_type(const BYTE* table, unsigned int len) {
    const BYTE* p = table;
    const BYTE* end = table + len;
    while (p + 4 <= end) {
        BYTE type = p[0];
        BYTE size = p[1];
        if (type == SMBIOS_TYPE_END_OF_TABLE) break;
        if (size < 4) break;
        if (type == SMBIOS_TYPE_SYSTEM_ENCLOSURE && size > 5) {
            return p[5];
        }
        {
            const BYTE* q = p + size;
            while (q + 1 < end) {
                if (q[0] == 0 && q[1] == 0) {
                    q += 2;
                    break;
                }
                q++;
            }
            if (q <= p) break;
            p = q;
        }
    }
    return 0;
}

static BOOL get_smbios_chassis(BYTE* out_type) {
    BYTE buffer[4096];
    UINT size = 0;

    if (!out_type) return FALSE;
    *out_type = 0;
    size = KERNEL32$GetSystemFirmwareTable(FIRMWARE_TABLE_SIGNATURE_RSMB, 0, 0, 0);
    if (size == 0 || size > sizeof(buffer)) return FALSE;

    inline_memset(buffer, 0, sizeof(buffer));
    if (KERNEL32$GetSystemFirmwareTable(FIRMWARE_TABLE_SIGNATURE_RSMB, 0, buffer, size) != size)
        return FALSE;

    if (size < 8) return FALSE;
    {
        RAW_SMBIOS_DATA* raw = (RAW_SMBIOS_DATA*)buffer;
        if (raw->Length == 0 || raw->Length > (size - 8)) return FALSE;
        *out_type = find_chassis_type(raw->SMBIOSTableData, raw->Length);
        return (*out_type != 0);
    }
}

static BOOL get_processor_throttling(BOOL ac_online, BOOL* out_throttling, UINT* out_avg_pct) {
    SYSTEM_INFO_MIN si;
    PROCESSOR_POWER_INFORMATION ppi[64];
    DWORD count = 0;
    DWORD i = 0;
    ULONG sum_max = 0;
    ULONG sum_cur = 0;
    UINT avg_pct = 0;
    pfnCallNtPowerInformation CallNtPowerInformation_ =
        (pfnCallNtPowerInformation)gp(L"PowrProf.dll", "CallNtPowerInformation");

    if (out_throttling) *out_throttling = FALSE;
    if (out_avg_pct) *out_avg_pct = 0;
    if (!ac_online || !CallNtPowerInformation_) return FALSE;

    inline_memset(&si, 0, sizeof(si));
    KERNEL32$GetSystemInfo(&si);
    count = si.dwNumberOfProcessors;
    if (count == 0) return FALSE;
    if (count > 64) count = 64;

    inline_memset(ppi, 0, sizeof(ppi));
    if (CallNtPowerInformation_(POWER_INFO_PROCESSOR_INFORMATION, 0, 0, ppi, count * sizeof(ppi[0])) != 0)
        return FALSE;

    for (i = 0; i < count; i++) {
        if (ppi[i].MaxMhz == 0) continue;
        sum_max += ppi[i].MaxMhz;
        sum_cur += ppi[i].CurrentMhz;
    }
    if (sum_max == 0) return FALSE;

    avg_pct = (UINT)((sum_cur * 100u) / sum_max);
    if (out_avg_pct) *out_avg_pct = avg_pct;
    if (out_throttling) *out_throttling = (avg_pct < 70);
    return TRUE;
}

void go(char *args, unsigned long alen) {
    SYSTEM_POWER_STATUS_MIN sps;
    BOOL sps_ok = FALSE;
    BOOL ac_online = FALSE;
    BOOL on_battery = FALSE;
    BOOL has_battery = FALSE;
    BOOL battery_low = FALSE;
    BOOL throttling = FALSE;
    BYTE chassis_type = 0;
    const char* chassis_class = "Unknown";
    const char* platform = "Unknown";
    const char* power_state = "Unknown";
    int battery_percent = -1;
    int confidence = 0;
    int sensitivity = 0; // 0=Low 1=Medium 2=High
    char note[64];
    char battery_str[16];
    int conf_tenths = 0;
    UINT avg_pct = 0;

    (void)args; (void)alen;

    inline_memset(&sps, 0, sizeof(sps));
    sps_ok = KERNEL32$GetSystemPowerStatus(&sps);

    inline_memset(note, 0, sizeof(note));
    inline_memset(battery_str, 0, sizeof(battery_str));

    if (sps_ok) {
        if (sps.ACLineStatus == AC_LINE_ONLINE) ac_online = TRUE;
        else if (sps.ACLineStatus == AC_LINE_OFFLINE) on_battery = TRUE;

        if (sps.BatteryFlag != BATTERY_FLAG_UNKNOWN) {
            has_battery = ((sps.BatteryFlag & BATTERY_FLAG_NO_BATTERY) == 0);
        } else if (sps.BatteryLifePercent != BATTERY_PERCENT_UNKNOWN) {
            has_battery = TRUE;
        }

        if (sps.BatteryLifePercent != BATTERY_PERCENT_UNKNOWN)
            battery_percent = (int)sps.BatteryLifePercent;
    }

    if (get_smbios_chassis(&chassis_type))
        chassis_class = chassis_class_from_type(chassis_type);

    if (chassis_type == 30 || chassis_type == 31 || chassis_type == 32)
        platform = "Tablet";
    else if (chassis_type == 8 || chassis_type == 9 || chassis_type == 10 || chassis_type == 14)
        platform = "Laptop";
    else if (has_battery)
        platform = "Laptop";
    else if (chassis_type == 3 || chassis_type == 4 || chassis_type == 6)
        platform = "Desktop";

    if (ac_online) power_state = "AC";
    else if (on_battery) power_state = "Battery";

    if (has_battery) confidence += 60;
    if (chassis_type == 8 || chassis_type == 9 || chassis_type == 10 || chassis_type == 14) confidence += 30;
    if (chassis_type == 30 || chassis_type == 31 || chassis_type == 32) confidence += 30;
    if (chassis_type == 3 || chassis_type == 4 || chassis_type == 6) confidence += 30;

    if (has_battery && (chassis_type == 3 || chassis_type == 4 || chassis_type == 6)) {
        confidence -= 20;
        append_note(note, sizeof(note), "anomalous_battery_desktop");
    }

    if (confidence < 0) confidence = 0;
    if (confidence > 100) confidence = 100;

    if (on_battery) {
        if (battery_percent >= 0) {
            if (battery_percent < 30) {
                sensitivity = 2;
                battery_low = TRUE;
            } else if (battery_percent < 70) {
                sensitivity = 1;
            } else {
                sensitivity = 1;
            }
        } else {
            sensitivity = 1;
        }
    } else if (ac_online && has_battery) {
        sensitivity = 1;
    } else if (ac_online && !has_battery) {
        sensitivity = 0;
    } else {
        sensitivity = 1;
    }

    if (battery_low) append_note(note, sizeof(note), "battery_low");

    if (get_processor_throttling(ac_online, &throttling, &avg_pct) && throttling) {
        if (sensitivity < 2) sensitivity++;
        append_note(note, sizeof(note), "likely_throttling");
    }

    if (note[0] == 0) inline_strcpy(note, sizeof(note), "none");
    if (battery_percent < 0) inline_strcpy(battery_str, sizeof(battery_str), "N/A");
    else inline_utoa(battery_str, sizeof(battery_str), (unsigned int)battery_percent);

    conf_tenths = (confidence + 5) / 10;

    BeaconPrintf(
        CALLBACK_OUTPUT,
        "PLATFORM=%s POWER=%s BATTERY=%s SENSITIVITY=%s CONFIDENCE=%d.%d NOTE=%s CHASSIS=%s CPU_PCT=%u",
        platform,
        power_state,
        battery_str,
        (sensitivity == 2 ? "High" : (sensitivity == 1 ? "Medium" : "Low")),
        (conf_tenths / 10),
        (conf_tenths % 10),
        note,
        chassis_class,
        avg_pct
    );
}
