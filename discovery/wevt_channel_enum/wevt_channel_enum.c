#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

typedef HANDLE EVT_HANDLE;

#define MY_EVT_VT_STRING                 0x0001
#define MY_EVT_VT_UINT32                 0x0008
#define MY_EVT_VT_UINT64                 0x000A
#define MY_EVT_VT_BOOLEAN                0x000D
#define MY_EVT_VT_ARRAY                  0x0080

#define MY_ERROR_NO_MORE_ITEMS           0x00000103
#define MY_ERROR_INSUFFICIENT_BUFFER     122

#define MY_EVT_CHANNEL_CONFIG_ENABLED              0
#define MY_EVT_CHANNEL_CONFIG_ISOLATION            1
#define MY_EVT_CHANNEL_CONFIG_TYPE                 2
#define MY_EVT_CHANNEL_CONFIG_OWNING_PUBLISHER     3
#define MY_EVT_CHANNEL_CONFIG_CLASSIC_EVENTLOG     4
#define MY_EVT_CHANNEL_CONFIG_ACCESS               5
#define MY_EVT_CHANNEL_LOGGING_RETENTION           6
#define MY_EVT_CHANNEL_LOGGING_AUTO_BACKUP         7
#define MY_EVT_CHANNEL_LOGGING_MAX_SIZE            8
#define MY_EVT_CHANNEL_LOGGING_LOG_FILE_PATH       9
#define MY_EVT_CHANNEL_PUBLISHING_LEVEL            10
#define MY_EVT_CHANNEL_PUBLISHING_KEYWORDS         11

#define MY_EVT_CHANNEL_TYPE_ADMIN        0
#define MY_EVT_CHANNEL_TYPE_OPERATIONAL  1
#define MY_EVT_CHANNEL_TYPE_ANALYTIC     2
#define MY_EVT_CHANNEL_TYPE_DEBUG        3

#define MY_EVT_CHANNEL_ISOLATION_APPLICATION 0
#define MY_EVT_CHANNEL_ISOLATION_SYSTEM      1
#define MY_EVT_CHANNEL_ISOLATION_CUSTOM      2

#define DEFAULT_MAX_CHANNELS 256
#define HARD_MAX_CHANNELS 512
#define CHANNEL_PATH_CHARS 512
#define PROPERTY_BUF_BYTES 2048
#define FLAG_VERBOSE 0x1

typedef struct {
    union {
        BOOL BooleanVal;
        INT8 SByteVal;
        UINT8 ByteVal;
        INT16 Int16Val;
        UINT16 UInt16Val;
        INT32 Int32Val;
        UINT32 UInt32Val;
        INT64 Int64Val;
        UINT64 UInt64Val;
        float SingleVal;
        double DoubleVal;
        ULONGLONG FileTimeVal;
        SYSTEMTIME SysTimeVal;
        GUID GuidVal;
        LPCWSTR StringVal;
        LPCSTR AnsiStringVal;
        PBYTE BinaryVal;
        PSID SidVal;
        size_t SizeTVal;
        PVOID PtrVal;
    };
    DWORD Count;
    DWORD Type;
} EVT_VARIANT, *PEVT_VARIANT;

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

typedef BOOL (WINAPI *pfnEvtClose)(EVT_HANDLE Object);
typedef EVT_HANDLE (WINAPI *pfnEvtOpenChannelEnum)(EVT_HANDLE Session, DWORD Flags);
typedef BOOL (WINAPI *pfnEvtNextChannelPath)(
    EVT_HANDLE ChannelEnum,
    DWORD ChannelPathBufferSize,
    LPWSTR ChannelPathBuffer,
    PDWORD ChannelPathBufferUsed
);
typedef EVT_HANDLE (WINAPI *pfnEvtOpenChannelConfig)(
    EVT_HANDLE Session,
    LPCWSTR ChannelPath,
    DWORD Flags
);
typedef BOOL (WINAPI *pfnEvtGetChannelConfigProperty)(
    EVT_HANDLE ChannelConfig,
    DWORD PropertyId,
    DWORD Flags,
    DWORD PropertyValueBufferSize,
    PEVT_VARIANT PropertyValueBuffer,
    PDWORD PropertyValueBufferUsed
);

typedef struct {
    HMODULE module;
    BOOL unloadModule;
    pfnEvtClose EvtClose;
    pfnEvtOpenChannelEnum EvtOpenChannelEnum;
    pfnEvtNextChannelPath EvtNextChannelPath;
    pfnEvtOpenChannelConfig EvtOpenChannelConfig;
    pfnEvtGetChannelConfigProperty EvtGetChannelConfigProperty;
} EvtApis;

static void *inline_memset(void *dest, int val, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)val;
    }
    return dest;
}

static int wide_len(LPCWSTR text) {
    int len = 0;
    if (text == NULL) {
        return 0;
    }
    while (text[len] != L'\0') {
        len++;
    }
    return len;
}

static wchar_t lower_wide(wchar_t c) {
    if (c >= L'A' && c <= L'Z') {
        return (wchar_t)(c + 32);
    }
    return c;
}

static int wide_contains_ci(LPCWSTR haystack, LPCWSTR needle) {
    int i = 0;
    int j = 0;
    int nlen = 0;
    if (haystack == NULL || needle == NULL || needle[0] == L'\0') {
        return 1;
    }
    nlen = wide_len(needle);
    while (haystack[i] != L'\0') {
        j = 0;
        while (j < nlen && haystack[i + j] != L'\0' &&
               lower_wide(haystack[i + j]) == lower_wide(needle[j])) {
            j++;
        }
        if (j == nlen) {
            return 1;
        }
        i++;
    }
    return 0;
}

static int valid_packed_wstring(LPCWSTR value, int bytes) {
    int i;
    int chars;
    if (value == NULL || bytes < (int)sizeof(wchar_t) ||
        (bytes % (int)sizeof(wchar_t)) != 0 || bytes > 8192) {
        return 0;
    }
    chars = bytes / (int)sizeof(wchar_t);
    for (i = 0; i < chars; i++) {
        if (value[i] == L'\0') {
            return 1;
        }
    }
    return 0;
}

static int resolve_wevtapi_functions(EvtApis *apis) {
    HMODULE hMod;
    if (apis == NULL) {
        return 0;
    }
    inline_memset(apis, 0, sizeof(*apis));
    hMod = KERNEL32$GetModuleHandleW(L"wevtapi.dll");
    if (!hMod) {
        hMod = KERNEL32$LoadLibraryW(L"wevtapi.dll");
        if (hMod) {
            apis->unloadModule = TRUE;
        }
    }
    if (!hMod) {
        return 0;
    }
    apis->module = hMod;
    apis->EvtClose = (pfnEvtClose)(void *)KERNEL32$GetProcAddress(hMod, "EvtClose");
    apis->EvtOpenChannelEnum = (pfnEvtOpenChannelEnum)(void *)KERNEL32$GetProcAddress(hMod, "EvtOpenChannelEnum");
    apis->EvtNextChannelPath = (pfnEvtNextChannelPath)(void *)KERNEL32$GetProcAddress(hMod, "EvtNextChannelPath");
    apis->EvtOpenChannelConfig = (pfnEvtOpenChannelConfig)(void *)KERNEL32$GetProcAddress(hMod, "EvtOpenChannelConfig");
    apis->EvtGetChannelConfigProperty = (pfnEvtGetChannelConfigProperty)(void *)KERNEL32$GetProcAddress(hMod, "EvtGetChannelConfigProperty");
    if (!apis->EvtClose || !apis->EvtOpenChannelEnum || !apis->EvtNextChannelPath ||
        !apis->EvtOpenChannelConfig || !apis->EvtGetChannelConfigProperty) {
        if (apis->unloadModule) {
            KERNEL32$FreeLibrary(hMod);
        }
        inline_memset(apis, 0, sizeof(*apis));
        return 0;
    }
    return 1;
}

static void release_wevtapi_functions(EvtApis *apis) {
    if (apis != NULL && apis->unloadModule && apis->module) {
        KERNEL32$FreeLibrary(apis->module);
    }
    if (apis != NULL) {
        inline_memset(apis, 0, sizeof(*apis));
    }
}

static const char *channel_type_label(UINT32 type) {
    if (type == MY_EVT_CHANNEL_TYPE_ADMIN) {
        return "Admin";
    }
    if (type == MY_EVT_CHANNEL_TYPE_OPERATIONAL) {
        return "Operational";
    }
    if (type == MY_EVT_CHANNEL_TYPE_ANALYTIC) {
        return "Analytic";
    }
    if (type == MY_EVT_CHANNEL_TYPE_DEBUG) {
        return "Debug";
    }
    return "Unknown";
}

static const char *channel_isolation_label(UINT32 isolation) {
    if (isolation == MY_EVT_CHANNEL_ISOLATION_APPLICATION) {
        return "Application";
    }
    if (isolation == MY_EVT_CHANNEL_ISOLATION_SYSTEM) {
        return "System";
    }
    if (isolation == MY_EVT_CHANNEL_ISOLATION_CUSTOM) {
        return "Custom";
    }
    return "Unknown";
}

static int get_property(
    EvtApis *apis,
    EVT_HANDLE hConfig,
    DWORD propertyId,
    PEVT_VARIANT buf,
    DWORD bufSize,
    PDWORD used
) {
    DWORD needed = 0;
    if (!apis->EvtGetChannelConfigProperty(hConfig, propertyId, 0, bufSize, buf, &needed)) {
        return 0;
    }
    if (used != NULL) {
        *used = needed;
    }
    return 1;
}

static int prop_bool(EvtApis *apis, EVT_HANDLE hConfig, DWORD propertyId, int *out) {
    BYTE storage[sizeof(EVT_VARIANT) + 16];
    PEVT_VARIANT var = (PEVT_VARIANT)storage;
    DWORD used = 0;
    inline_memset(storage, 0, sizeof(storage));
    if (!get_property(apis, hConfig, propertyId, var, (DWORD)sizeof(storage), &used)) {
        return 0;
    }
    if ((var->Type & ~MY_EVT_VT_ARRAY) != MY_EVT_VT_BOOLEAN) {
        return 0;
    }
    *out = var->BooleanVal ? 1 : 0;
    return 1;
}

static int prop_u32(EvtApis *apis, EVT_HANDLE hConfig, DWORD propertyId, UINT32 *out) {
    BYTE storage[sizeof(EVT_VARIANT) + 16];
    PEVT_VARIANT var = (PEVT_VARIANT)storage;
    DWORD used = 0;
    inline_memset(storage, 0, sizeof(storage));
    if (!get_property(apis, hConfig, propertyId, var, (DWORD)sizeof(storage), &used)) {
        return 0;
    }
    if ((var->Type & ~MY_EVT_VT_ARRAY) != MY_EVT_VT_UINT32) {
        return 0;
    }
    *out = var->UInt32Val;
    return 1;
}

static int prop_u64(EvtApis *apis, EVT_HANDLE hConfig, DWORD propertyId, UINT64 *out) {
    BYTE storage[sizeof(EVT_VARIANT) + 16];
    PEVT_VARIANT var = (PEVT_VARIANT)storage;
    DWORD used = 0;
    inline_memset(storage, 0, sizeof(storage));
    if (!get_property(apis, hConfig, propertyId, var, (DWORD)sizeof(storage), &used)) {
        return 0;
    }
    if ((var->Type & ~MY_EVT_VT_ARRAY) != MY_EVT_VT_UINT64) {
        return 0;
    }
    *out = var->UInt64Val;
    return 1;
}

static int prop_string(
    EvtApis *apis,
    EVT_HANDLE hConfig,
    DWORD propertyId,
    PEVT_VARIANT heapBuf,
    DWORD heapSize,
    LPCWSTR *out
) {
    DWORD used = 0;
    if (heapBuf == NULL || out == NULL) {
        return 0;
    }
    inline_memset(heapBuf, 0, heapSize);
    if (!get_property(apis, hConfig, propertyId, heapBuf, heapSize, &used)) {
        return 0;
    }
    if ((heapBuf->Type & ~MY_EVT_VT_ARRAY) != MY_EVT_VT_STRING || heapBuf->StringVal == NULL) {
        return 0;
    }
    *out = heapBuf->StringVal;
    return 1;
}

static void print_channel_config(EvtApis *apis, LPCWSTR channelPath, int verbose) {
    EVT_HANDLE hConfig = NULL;
    HANDLE heap = NULL;
    PEVT_VARIANT strBuf = NULL;
    int enabled = -1;
    int classic = -1;
    int retention = -1;
    int autobackup = -1;
    UINT32 type = 0;
    UINT32 isolation = 0;
    UINT32 level = 0;
    UINT64 maxSize = 0;
    UINT64 keywords = 0;
    LPCWSTR owner = NULL;
    LPCWSTR path = NULL;
    LPCWSTR access = NULL;
    int haveType = 0;
    int haveIsolation = 0;

    hConfig = apis->EvtOpenChannelConfig(NULL, channelPath, 0);
    if (hConfig == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!]   config open failed err=%lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return;
    }

    heap = KERNEL32$GetProcessHeap();
    if (heap == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcessHeap failed for property buffer\n");
        apis->EvtClose(hConfig);
        return;
    }
    strBuf = (PEVT_VARIANT)KERNEL32$HeapAlloc(heap, 0, PROPERTY_BUF_BYTES);
    if (strBuf == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed for property buffer\n");
        apis->EvtClose(hConfig);
        return;
    }

    prop_bool(apis, hConfig, MY_EVT_CHANNEL_CONFIG_ENABLED, &enabled);
    haveType = prop_u32(apis, hConfig, MY_EVT_CHANNEL_CONFIG_TYPE, &type);
    haveIsolation = prop_u32(apis, hConfig, MY_EVT_CHANNEL_CONFIG_ISOLATION, &isolation);
    prop_bool(apis, hConfig, MY_EVT_CHANNEL_CONFIG_CLASSIC_EVENTLOG, &classic);
    prop_bool(apis, hConfig, MY_EVT_CHANNEL_LOGGING_RETENTION, &retention);
    prop_bool(apis, hConfig, MY_EVT_CHANNEL_LOGGING_AUTO_BACKUP, &autobackup);
    prop_u64(apis, hConfig, MY_EVT_CHANNEL_LOGGING_MAX_SIZE, &maxSize);

    BeaconPrintf(CALLBACK_OUTPUT, "[i]   enabled=%d type=%s isolation=%s classic=%d\n",
                 enabled,
                 haveType ? channel_type_label(type) : "?",
                 haveIsolation ? channel_isolation_label(isolation) : "?",
                 classic);

    if (prop_string(apis, hConfig, MY_EVT_CHANNEL_CONFIG_OWNING_PUBLISHER, strBuf,
                    PROPERTY_BUF_BYTES, &owner)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   owner=%ls\n", owner);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   owner=\n");
    }

    if (!prop_string(apis, hConfig, MY_EVT_CHANNEL_LOGGING_LOG_FILE_PATH, strBuf,
                     PROPERTY_BUF_BYTES, &path)) {
        path = L"";
    }
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[i]   path=%ls max=%llu retain=%d autobackup=%d\n",
                 path,
                 (unsigned long long)maxSize,
                 retention,
                 autobackup);

    if (verbose) {
        if (prop_string(apis, hConfig, MY_EVT_CHANNEL_CONFIG_ACCESS, strBuf,
                        PROPERTY_BUF_BYTES, &access)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i]   access=%ls\n", access);
        }
        if (prop_u32(apis, hConfig, MY_EVT_CHANNEL_PUBLISHING_LEVEL, &level)) {
            if (prop_u64(apis, hConfig, MY_EVT_CHANNEL_PUBLISHING_KEYWORDS, &keywords)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[i]   level=%u keywords=0x%llx\n",
                             (unsigned int)level, (unsigned long long)keywords);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[i]   level=%u\n", (unsigned int)level);
            }
        }
    }

    KERNEL32$HeapFree(heap, 0, strBuf);
    apis->EvtClose(hConfig);
}

void go(char *args, unsigned long alen) {
    EvtApis apis;
    EVT_HANDLE hEnum = NULL;
    HANDLE heap = NULL;
    LPWSTR channelPath = NULL;
    DWORD pathUsed = 0;
    LPCWSTR filter = NULL;
    int filterBytes = 0;
    int maxChannels = DEFAULT_MAX_CHANNELS;
    int flags = 0;
    int verbose = 0;
    int listed = 0;
    int skippedFilter = 0;
    int truncated = 0;
    datap parser = {0};

    inline_memset(&apis, 0, sizeof(apis));

    if (alen > 0) {
        BeaconDataParse(&parser, args, (int)alen);
        filter = (LPCWSTR)BeaconDataExtract(&parser, &filterBytes);
        if (!valid_packed_wstring(filter, filterBytes)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] filter must be a bounded null-terminated wstring\n");
            return;
        }
        if (BeaconDataLength(&parser) > 0) {
            if (BeaconDataLength(&parser) < 4) {
                BeaconPrintf(CALLBACK_ERROR, "[-] max_channels must be a packed int\n");
                return;
            }
            maxChannels = BeaconDataInt(&parser);
        }
        if (BeaconDataLength(&parser) > 0) {
            if (BeaconDataLength(&parser) < 4) {
                BeaconPrintf(CALLBACK_ERROR, "[-] flags must be a packed int\n");
                return;
            }
            flags = BeaconDataInt(&parser);
        }
        if (BeaconDataLength(&parser) != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Unexpected trailing argument data\n");
            return;
        }
    }

    if (filter != NULL && filter[0] == L'\0') {
        filter = NULL;
    }
    if (maxChannels <= 0) {
        maxChannels = DEFAULT_MAX_CHANNELS;
    }
    if (maxChannels > HARD_MAX_CHANNELS) {
        maxChannels = HARD_MAX_CHANNELS;
    }
    verbose = (flags & FLAG_VERBOSE) ? 1 : 0;

    if (!resolve_wevtapi_functions(&apis)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve wevtapi.dll channel APIs\n");
        return;
    }
    heap = KERNEL32$GetProcessHeap();
    if (heap == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcessHeap failed for channel buffer\n");
        goto cleanup;
    }
    channelPath = (LPWSTR)KERNEL32$HeapAlloc(heap, 0, CHANNEL_PATH_CHARS * sizeof(wchar_t));
    if (channelPath == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed for channel buffer\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[i] wevt_channel_enum: enumerating channels\n");
    if (filter != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] filter=%ls max=%d verbose=%d\n",
                     filter, maxChannels, verbose);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[!] No filter set; host may have hundreds of channels. Prefer a substring filter (e.g. PowerShell, Sysmon, Defend).\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[i] filter=(none) max=%d verbose=%d\n",
                     maxChannels, verbose);
    }

    hEnum = apis.EvtOpenChannelEnum(NULL, 0);
    if (hEnum == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] EvtOpenChannelEnum failed err=%lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        goto cleanup;
    }

    for (;;) {
        LPCWSTR activePath = channelPath;
        LPWSTR heapPath = NULL;

        inline_memset(channelPath, 0, CHANNEL_PATH_CHARS * sizeof(wchar_t));
        pathUsed = 0;
        if (!apis.EvtNextChannelPath(hEnum, CHANNEL_PATH_CHARS, channelPath, &pathUsed)) {
            DWORD err = KERNEL32$GetLastError();
            if (err == MY_ERROR_NO_MORE_ITEMS) {
                break;
            }
            if (err == MY_ERROR_INSUFFICIENT_BUFFER) {
                DWORD needChars = pathUsed;
                if (needChars == 0 || needChars > 4096) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] channel path too long; stopping enum\n");
                    break;
                }
                heapPath = (LPWSTR)KERNEL32$HeapAlloc(heap, 0, needChars * sizeof(wchar_t));
                if (heapPath == NULL) {
                    BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed for channel path\n");
                    break;
                }
                inline_memset(heapPath, 0, needChars * sizeof(wchar_t));
                pathUsed = 0;
                if (!apis.EvtNextChannelPath(hEnum, needChars, heapPath, &pathUsed)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] EvtNextChannelPath retry err=%lu\n",
                                 (unsigned long)KERNEL32$GetLastError());
                    KERNEL32$HeapFree(heap, 0, heapPath);
                    break;
                }
                activePath = heapPath;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] EvtNextChannelPath err=%lu\n",
                             (unsigned long)err);
                break;
            }
        }

        if (filter != NULL && !wide_contains_ci(activePath, filter)) {
            skippedFilter++;
            if (heapPath != NULL) {
                KERNEL32$HeapFree(heap, 0, heapPath);
            }
            continue;
        }

        if (listed >= maxChannels) {
            truncated = 1;
            if (heapPath != NULL) {
                KERNEL32$HeapFree(heap, 0, heapPath);
            }
            break;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Channel: %ls\n", activePath);
        print_channel_config(&apis, activePath, verbose);
        listed++;
        if (heapPath != NULL) {
            KERNEL32$HeapFree(heap, 0, heapPath);
        }
    }

    apis.EvtClose(hEnum);
    hEnum = NULL;
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[i] Summary: listed=%d skipped_filter=%d truncated=%d\n",
                 listed, skippedFilter, truncated);

cleanup:
    if (hEnum != NULL) {
        apis.EvtClose(hEnum);
    }
    if (channelPath != NULL) {
        KERNEL32$HeapFree(heap, 0, channelPath);
    }
    release_wevtapi_functions(&apis);
}
