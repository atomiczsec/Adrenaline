#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

typedef HANDLE EVT_HANDLE;

#define EVT_CHANNEL_CONFIG_ENABLED 0
#define EVT_CHANNEL_CONFIG_ISOLATION 1
#define EVT_CHANNEL_CONFIG_TYPE 2
#define EVT_CHANNEL_CONFIG_OWNING_PUBLISHER 3
#define EVT_CHANNEL_CONFIG_CLASSIC 4
#define EVT_CHANNEL_CONFIG_ACCESS 5
#define EVT_CHANNEL_LOGGING_RETENTION 6
#define EVT_CHANNEL_LOGGING_AUTO_BACKUP 7
#define EVT_CHANNEL_LOGGING_MAX_SIZE 8
#define EVT_CHANNEL_LOGGING_FILE_PATH 9
#define EVT_CHANNEL_PUBLISHING_LEVEL 10
#define EVT_CHANNEL_PUBLISHING_KEYWORDS 11
#define EVT_CHANNEL_PUBLISHING_CONTROL_GUID 12
#define EVT_CHANNEL_PUBLISHING_BUFFER_SIZE 13
#define EVT_CHANNEL_PUBLISHING_MIN_BUFFERS 14
#define EVT_CHANNEL_PUBLISHING_MAX_BUFFERS 15
#define EVT_CHANNEL_PUBLISHING_LATENCY 16
#define EVT_CHANNEL_PUBLISHING_CLOCK_TYPE 17
#define EVT_CHANNEL_PUBLISHING_SID_TYPE 18
#define EVT_CHANNEL_PUBLISHER_LIST 19
#define EVT_CHANNEL_PUBLISHING_FILE_MAX 20

#define EVT_VAR_TYPE_STRING 1
#define EVT_VAR_TYPE_UINT32 8
#define EVT_VAR_TYPE_UINT64 10
#define EVT_VAR_TYPE_BOOLEAN 13
#define EVT_VAR_TYPE_GUID 15
#define EVT_VAR_TYPE_ARRAY 128

#define EVT_CHANNEL_TYPE_ADMIN 0
#define EVT_CHANNEL_TYPE_OPERATIONAL 1
#define EVT_CHANNEL_TYPE_ANALYTIC 2
#define EVT_CHANNEL_TYPE_DEBUG 3

#define EVT_CHANNEL_ISOLATION_APPLICATION 0
#define EVT_CHANNEL_ISOLATION_SYSTEM 1
#define EVT_CHANNEL_ISOLATION_CUSTOM 2

#define ERROR_EVT_CHANNEL_NOT_FOUND_VALUE 15007
#define DEFAULT_LOG_SIZE 1048576UL
#define MIN_LOG_SIZE 65536UL
#define MAX_LOG_SIZE 1073741824UL
#define EVENT_TYPES_SUPPORTED 7UL
#define WRITE_EVENT_ID 2UL
#define MAX_WRITE_PAYLOAD_BYTES 12288UL
#define MAX_WRITE_RAW_BYTES 8192UL
#define MAX_SOURCE_PRINT 64UL
#define EVENTLOG_KEY_PREFIX L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\"
#define OWNER_VALUE L"CustomBOFsOwner"
#define SOURCE_VALUE L"CustomBOFsSource"
#define OWNER_MARKER L"event_log_manage-v1"

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
        SYSTEMTIME *SysTimeVal;
        GUID *GuidVal;
        LPCWSTR StringVal;
        LPCWSTR *StringArr;
        LPCSTR AnsiStringVal;
        PBYTE BinaryVal;
        PSID SidVal;
        size_t SizeTVal;
        PVOID PtrVal;
    };
    DWORD Count;
    DWORD Type;
} EVT_VARIANT, *PEVT_VARIANT;

typedef BOOL (WINAPI *pfnEvtClose)(EVT_HANDLE);
typedef EVT_HANDLE (WINAPI *pfnEvtOpenChannelConfig)(EVT_HANDLE, LPCWSTR, DWORD);
typedef BOOL (WINAPI *pfnEvtGetChannelConfigProperty)(EVT_HANDLE, DWORD, DWORD, DWORD, PEVT_VARIANT, PDWORD);
typedef BOOL (WINAPI *pfnEvtClearLog)(EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD);

typedef struct {
    HMODULE module;
    BOOL unloadModule;
    pfnEvtClose EvtClose;
    pfnEvtOpenChannelConfig EvtOpenChannelConfig;
    pfnEvtGetChannelConfigProperty EvtGetChannelConfigProperty;
    pfnEvtClearLog EvtClearLog;
} EvtApis;

typedef struct {
    char action[16];
    wchar_t name[256];
    wchar_t source[256];
    wchar_t backup[512];
    wchar_t registryPath[640];
    wchar_t filePath[640];
} Params;

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT UINT WINAPI KERNEL32$GetWindowsDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeleteFileW(LPCWSTR);

DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteTreeW(HKEY, LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$RegisterEventSourceW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ReportEventW(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCWSTR *, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DeregisterEventSource(HANDLE);

static void *inline_memset(void *dest, int value, size_t count) {
    unsigned char *out = (unsigned char *)dest;
    while (count--) {
        *out++ = (unsigned char)value;
    }
    return dest;
}

static size_t wide_len(LPCWSTR value) {
    size_t length = 0;
    if (!value) {
        return 0;
    }
    while (value[length] != L'\0') {
        length++;
    }
    return length;
}

static char lower_ansi(char value) {
    if (value >= 'A' && value <= 'Z') {
        return (char)(value + ('a' - 'A'));
    }
    return value;
}

static wchar_t lower_wide(wchar_t value) {
    if (value >= L'A' && value <= L'Z') {
        return (wchar_t)(value + (L'a' - L'A'));
    }
    return value;
}

static int ansi_eq_ci(const char *left, const char *right) {
    size_t i = 0;
    if (!left || !right) {
        return 0;
    }
    while (left[i] && right[i]) {
        if (lower_ansi(left[i]) != lower_ansi(right[i])) {
            return 0;
        }
        i++;
    }
    return left[i] == '\0' && right[i] == '\0';
}

static int wide_eq_ci(LPCWSTR left, LPCWSTR right) {
    size_t i = 0;
    if (!left || !right) {
        return 0;
    }
    while (left[i] && right[i]) {
        if (lower_wide(left[i]) != lower_wide(right[i])) {
            return 0;
        }
        i++;
    }
    return left[i] == L'\0' && right[i] == L'\0';
}

static int wide_starts_ci(LPCWSTR value, LPCWSTR prefix) {
    size_t i = 0;
    if (!value || !prefix) {
        return 0;
    }
    while (prefix[i]) {
        if (!value[i] || lower_wide(value[i]) != lower_wide(prefix[i])) {
            return 0;
        }
        i++;
    }
    return 1;
}

static int wide_ends_ci(LPCWSTR value, LPCWSTR suffix) {
    size_t valueLength = wide_len(value);
    size_t suffixLength = wide_len(suffix);
    if (suffixLength > valueLength) {
        return 0;
    }
    return wide_eq_ci(value + valueLength - suffixLength, suffix);
}

static int wide_contains_ci(LPCWSTR value, LPCWSTR needle) {
    size_t i = 0;
    size_t j = 0;
    size_t needleLength = wide_len(needle);
    if (!value || !needle || needleLength == 0) {
        return 0;
    }
    while (value[i]) {
        j = 0;
        while (j < needleLength && value[i + j] && lower_wide(value[i + j]) == lower_wide(needle[j])) {
            j++;
        }
        if (j == needleLength) {
            return 1;
        }
        i++;
    }
    return 0;
}

static int wide_copy(LPWSTR destination, size_t capacity, LPCWSTR source) {
    size_t i = 0;
    if (!destination || capacity == 0 || !source) {
        return 0;
    }
    while (source[i]) {
        if (i + 1 >= capacity) {
            destination[0] = L'\0';
            return 0;
        }
        destination[i] = source[i];
        i++;
    }
    destination[i] = L'\0';
    return 1;
}

static int wide_append(LPWSTR destination, size_t capacity, LPCWSTR source) {
    size_t used = wide_len(destination);
    size_t i = 0;
    if (!destination || !source || used >= capacity) {
        return 0;
    }
    while (source[i]) {
        if (used + i + 1 >= capacity) {
            return 0;
        }
        destination[used + i] = source[i];
        i++;
    }
    destination[used + i] = L'\0';
    return 1;
}

static int copy_ansi(char *destination, size_t capacity, const char *source) {
    size_t i = 0;
    if (!destination || capacity == 0 || !source) {
        return 0;
    }
    while (source[i]) {
        if (i + 1 >= capacity) {
            destination[0] = '\0';
            return 0;
        }
        destination[i] = source[i];
        i++;
    }
    destination[i] = '\0';
    return 1;
}

static int ansi_to_wide(const char *source, LPWSTR destination, int capacity) {
    int converted;
    if (!source || !destination || capacity <= 0) {
        return 0;
    }
    converted = KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, -1, destination, capacity);
    if (converted == 0) {
        converted = KERNEL32$MultiByteToWideChar(CP_ACP, 0, source, -1, destination, capacity);
    }
    return converted > 0;
}

static int packed_string_length(const char *value, int packedSize, DWORD *length) {
    int i = 0;
    if (!value || packedSize <= 0 || !length || packedSize > (int)(MAX_WRITE_PAYLOAD_BYTES + 1)) {
        return 0;
    }
    while (i < packedSize && value[i] != '\0') {
        i++;
    }
    if (i == 0 || i >= packedSize || i > (int)MAX_WRITE_PAYLOAD_BYTES) {
        return 0;
    }
    *length = (DWORD)i;
    return 1;
}

static int has_more(datap *parser) {
    return parser && BeaconDataLength(parser) > 0;
}

static int valid_custom_name(LPCWSTR name) {
    size_t i = 0;
    size_t length = wide_len(name);
    if (length == 0 || length > 128) {
        return 0;
    }
    if (wide_eq_ci(name, L"Application") || wide_eq_ci(name, L"System") ||
        wide_eq_ci(name, L"Security") || wide_eq_ci(name, L"Setup") ||
        wide_eq_ci(name, L"ForwardedEvents") || wide_starts_ci(name, L"Microsoft-Windows-")) {
        return 0;
    }
    for (i = 0; i < length; i++) {
        wchar_t c = name[i];
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
              (c >= L'0' && c <= L'9') || c == L' ' || c == L'-' || c == L'_' || c == L'.')) {
            return 0;
        }
    }
    return 1;
}

static int protected_log(LPCWSTR name) {
    return wide_eq_ci(name, L"Application") || wide_eq_ci(name, L"System") || wide_eq_ci(name, L"Security");
}

static int absolute_backup_path(LPCWSTR path) {
    if (!path || !path[0]) {
        return 0;
    }
    return ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
           path[1] == L':' && path[2] == L'\\';
}

static int build_registry_path(Params *params) {
    if (!wide_copy(params->registryPath, sizeof(params->registryPath) / sizeof(params->registryPath[0]), EVENTLOG_KEY_PREFIX)) {
        return 0;
    }
    return wide_append(params->registryPath, sizeof(params->registryPath) / sizeof(params->registryPath[0]), params->name);
}

static int build_default_file_path(Params *params) {
    UINT length;
    size_t capacity = sizeof(params->filePath) / sizeof(params->filePath[0]);
    params->filePath[0] = L'\0';
    length = KERNEL32$GetWindowsDirectoryW(params->filePath, (UINT)capacity);
    if (length == 0 || length >= capacity) {
        params->filePath[0] = L'\0';
        return 0;
    }
    return wide_append(params->filePath, capacity, L"\\System32\\Winevt\\Logs\\") &&
           wide_append(params->filePath, capacity, params->name) &&
           wide_append(params->filePath, capacity, L".evtx");
}

static int safe_owned_file_path(LPCWSTR path) {
    return path && wide_contains_ci(path, L"\\System32\\Winevt\\Logs\\") && wide_ends_ci(path, L".evtx");
}

static int resolve_evt_apis(EvtApis *apis) {
    HMODULE module;
    if (!apis) {
        return 0;
    }
    inline_memset(apis, 0, sizeof(*apis));
    module = KERNEL32$GetModuleHandleW(L"wevtapi.dll");
    if (!module) {
        module = KERNEL32$LoadLibraryW(L"wevtapi.dll");
        if (module) {
            apis->unloadModule = TRUE;
        }
    }
    if (!module) {
        return 0;
    }
    apis->module = module;
    apis->EvtClose = (pfnEvtClose)(void *)KERNEL32$GetProcAddress(module, "EvtClose");
    apis->EvtOpenChannelConfig = (pfnEvtOpenChannelConfig)(void *)KERNEL32$GetProcAddress(module, "EvtOpenChannelConfig");
    apis->EvtGetChannelConfigProperty = (pfnEvtGetChannelConfigProperty)(void *)KERNEL32$GetProcAddress(module, "EvtGetChannelConfigProperty");
    apis->EvtClearLog = (pfnEvtClearLog)(void *)KERNEL32$GetProcAddress(module, "EvtClearLog");
    if (!apis->EvtClose || !apis->EvtOpenChannelConfig || !apis->EvtGetChannelConfigProperty || !apis->EvtClearLog) {
        if (apis->unloadModule) {
            KERNEL32$FreeLibrary(module);
        }
        inline_memset(apis, 0, sizeof(*apis));
        return 0;
    }
    return 1;
}

static void release_evt_apis(EvtApis *apis) {
    if (apis && apis->unloadModule && apis->module) {
        KERNEL32$FreeLibrary(apis->module);
    }
    if (apis) {
        inline_memset(apis, 0, sizeof(*apis));
    }
}

static int get_evt_property(EvtApis *apis, EVT_HANDLE channel, DWORD propertyId, PEVT_VARIANT value, DWORD valueSize) {
    DWORD used = 0;
    if (!apis->EvtGetChannelConfigProperty(channel, propertyId, 0, valueSize, value, &used)) {
        return 0;
    }
    return 1;
}

static int get_evt_bool(EvtApis *apis, EVT_HANDLE channel, DWORD propertyId, int *output) {
    EVT_VARIANT value;
    inline_memset(&value, 0, sizeof(value));
    if (!output || !get_evt_property(apis, channel, propertyId, &value, sizeof(value)) ||
        (value.Type & ~EVT_VAR_TYPE_ARRAY) != EVT_VAR_TYPE_BOOLEAN) {
        return 0;
    }
    *output = value.BooleanVal ? 1 : 0;
    return 1;
}

static int get_evt_u32(EvtApis *apis, EVT_HANDLE channel, DWORD propertyId, UINT32 *output) {
    EVT_VARIANT value;
    inline_memset(&value, 0, sizeof(value));
    if (!output || !get_evt_property(apis, channel, propertyId, &value, sizeof(value)) ||
        (value.Type & ~EVT_VAR_TYPE_ARRAY) != EVT_VAR_TYPE_UINT32) {
        return 0;
    }
    *output = value.UInt32Val;
    return 1;
}

static int get_evt_u64(EvtApis *apis, EVT_HANDLE channel, DWORD propertyId, UINT64 *output) {
    EVT_VARIANT value;
    inline_memset(&value, 0, sizeof(value));
    if (!output || !get_evt_property(apis, channel, propertyId, &value, sizeof(value)) ||
        (value.Type & ~EVT_VAR_TYPE_ARRAY) != EVT_VAR_TYPE_UINT64) {
        return 0;
    }
    *output = value.UInt64Val;
    return 1;
}

static const char *channel_type_label(UINT32 value) {
    if (value == EVT_CHANNEL_TYPE_ADMIN) return "Admin";
    if (value == EVT_CHANNEL_TYPE_OPERATIONAL) return "Operational";
    if (value == EVT_CHANNEL_TYPE_ANALYTIC) return "Analytic";
    if (value == EVT_CHANNEL_TYPE_DEBUG) return "Debug";
    return "Unknown";
}

static const char *channel_isolation_label(UINT32 value) {
    if (value == EVT_CHANNEL_ISOLATION_APPLICATION) return "Application";
    if (value == EVT_CHANNEL_ISOLATION_SYSTEM) return "System";
    if (value == EVT_CHANNEL_ISOLATION_CUSTOM) return "Custom";
    return "Unknown";
}

static int get_evt_string(EvtApis *apis, EVT_HANDLE channel, DWORD propertyId, LPWSTR output, size_t capacity) {
    DWORD used = 0;
    HANDLE heap = KERNEL32$GetProcessHeap();
    PEVT_VARIANT value = NULL;
    int result = 0;
    if (!output || capacity == 0 || !heap) {
        return 0;
    }
    output[0] = L'\0';
    apis->EvtGetChannelConfigProperty(channel, propertyId, 0, 0, NULL, &used);
    if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER || used < sizeof(EVT_VARIANT) || used > 16384) {
        return 0;
    }
    value = (PEVT_VARIANT)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, used);
    if (!value) {
        return 0;
    }
    if (apis->EvtGetChannelConfigProperty(channel, propertyId, 0, used, value, &used) &&
        (value->Type & ~EVT_VAR_TYPE_ARRAY) == EVT_VAR_TYPE_STRING && value->StringVal) {
        result = wide_copy(output, capacity, value->StringVal);
    }
    KERNEL32$HeapFree(heap, 0, value);
    return result;
}

static void print_evt_guid(EvtApis *apis, EVT_HANDLE channel, DWORD propertyId) {
    DWORD used = 0;
    HANDLE heap = KERNEL32$GetProcessHeap();
    PEVT_VARIANT value = NULL;
    apis->EvtGetChannelConfigProperty(channel, propertyId, 0, 0, NULL, &used);
    if (!heap || KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER || used < sizeof(EVT_VARIANT) || used > 1024) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] control_guid=<not configured>\n");
        return;
    }
    value = (PEVT_VARIANT)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, used);
    if (!value) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] control_guid=<allocation failed>\n");
        return;
    }
    if (apis->EvtGetChannelConfigProperty(channel, propertyId, 0, used, value, &used) &&
        (value->Type & ~EVT_VAR_TYPE_ARRAY) == EVT_VAR_TYPE_GUID && value->GuidVal) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[i] control_guid={%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
                     (unsigned long)value->GuidVal->Data1, (unsigned int)value->GuidVal->Data2,
                     (unsigned int)value->GuidVal->Data3, (unsigned int)value->GuidVal->Data4[0],
                     (unsigned int)value->GuidVal->Data4[1], (unsigned int)value->GuidVal->Data4[2],
                     (unsigned int)value->GuidVal->Data4[3], (unsigned int)value->GuidVal->Data4[4],
                     (unsigned int)value->GuidVal->Data4[5], (unsigned int)value->GuidVal->Data4[6],
                     (unsigned int)value->GuidVal->Data4[7]);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] control_guid=<not configured>\n");
    }
    KERNEL32$HeapFree(heap, 0, value);
}

static void print_evt_publishers(EvtApis *apis, EVT_HANDLE channel) {
    DWORD used = 0;
    DWORD i;
    DWORD limit;
    HANDLE heap = KERNEL32$GetProcessHeap();
    PEVT_VARIANT value = NULL;
    wchar_t publisher[256];
    apis->EvtGetChannelConfigProperty(channel, EVT_CHANNEL_PUBLISHER_LIST, 0, 0, NULL, &used);
    if (!heap || KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER || used < sizeof(EVT_VARIANT) || used > 16384) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] publishers=0\n");
        return;
    }
    value = (PEVT_VARIANT)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, used);
    if (!value) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] publishers=<allocation failed>\n");
        return;
    }
    if (!apis->EvtGetChannelConfigProperty(channel, EVT_CHANNEL_PUBLISHER_LIST, 0, used, value, &used) ||
        (value->Type & ~EVT_VAR_TYPE_ARRAY) != EVT_VAR_TYPE_STRING || !(value->Type & EVT_VAR_TYPE_ARRAY) ||
        !value->StringArr) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] publishers=0\n");
        KERNEL32$HeapFree(heap, 0, value);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i] publishers=%lu\n", (unsigned long)value->Count);
    limit = value->Count > 32 ? 32 : value->Count;
    for (i = 0; i < limit; i++) {
        if (value->StringArr[i]) {
            if (wide_copy(publisher, sizeof(publisher) / sizeof(publisher[0]), value->StringArr[i])) {
                BeaconPrintf(CALLBACK_OUTPUT, "[i] publisher[%lu]=%ls\n", (unsigned long)i, publisher);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[i] publisher[%lu]=<name exceeds 255 characters>\n", (unsigned long)i);
            }
        }
    }
    if (value->Count > limit) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Publisher list truncated after %lu entries\n", (unsigned long)limit);
    }
    KERNEL32$HeapFree(heap, 0, value);
}

static int query_registry_string(HKEY key, LPCWSTR valueName, LPWSTR output, DWORD outputBytes) {
    DWORD type = 0;
    DWORD size = outputBytes;
    LSTATUS status;
    if (!key || !output || outputBytes < sizeof(wchar_t)) {
        return 0;
    }
    inline_memset(output, 0, outputBytes);
    status = ADVAPI32$RegQueryValueExW(key, valueName, NULL, &type, (LPBYTE)output, &size);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        output[0] = L'\0';
        return 0;
    }
    output[(outputBytes / sizeof(wchar_t)) - 1] = L'\0';
    return 1;
}

static int registry_name_in_use(LPCWSTR candidate) {
    HKEY baseKey = NULL;
    HKEY candidateKey = NULL;
    wchar_t registryName[384];
    DWORD index = 0;
    DWORD nameLength;
    LSTATUS status;
    int incomplete = 0;
    status = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog", 0,
                                    KEY_ENUMERATE_SUB_KEYS, &baseKey);
    if (status != ERROR_SUCCESS) {
        return -1;
    }
    while (index < 16384) {
        nameLength = (DWORD)(sizeof(registryName) / sizeof(registryName[0]));
        inline_memset(registryName, 0, sizeof(registryName));
        status = ADVAPI32$RegEnumKeyExW(baseKey, index, registryName, &nameLength, NULL, NULL, NULL, NULL);
        if (status == ERROR_NO_MORE_ITEMS) {
            ADVAPI32$RegCloseKey(baseKey);
            return incomplete ? 2 : 0;
        }
        if (status != ERROR_SUCCESS) {
            ADVAPI32$RegCloseKey(baseKey);
            return -1;
        }
        if (wide_eq_ci(registryName, candidate)) {
            ADVAPI32$RegCloseKey(baseKey);
            return 1;
        }
        if (!wide_append(registryName, sizeof(registryName) / sizeof(registryName[0]), L"\\") ||
            !wide_append(registryName, sizeof(registryName) / sizeof(registryName[0]), candidate)) {
            incomplete = 1;
            index++;
            continue;
        }
        status = ADVAPI32$RegOpenKeyExW(baseKey, registryName, 0, KEY_QUERY_VALUE, &candidateKey);
        if (status == ERROR_SUCCESS) {
            ADVAPI32$RegCloseKey(candidateKey);
            ADVAPI32$RegCloseKey(baseKey);
            return 1;
        }
        if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) {
            incomplete = 1;
        }
        index++;
    }
    ADVAPI32$RegCloseKey(baseKey);
    return 2;
}

static DWORD normalize_log_size(int requested) {
    uint64_t value;
    if (requested <= 0) {
        return DEFAULT_LOG_SIZE;
    }
    value = (uint64_t)(uint32_t)requested;
    if (value < MIN_LOG_SIZE) {
        value = MIN_LOG_SIZE;
    }
    if (value > MAX_LOG_SIZE) {
        value = MAX_LOG_SIZE;
    }
    value = (value + (MIN_LOG_SIZE - 1)) & ~((uint64_t)MIN_LOG_SIZE - 1);
    return (DWORD)value;
}

static void print_usage(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_log_manage inspect <channel>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_log_manage create <log> <source> [max_size_bytes]\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_log_manage sources <log>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_log_manage write <log> <source> <text>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_log_manage write_raw <log> <source> <event_id> <category> <data>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_log_manage clear <channel> [backup_path]\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_log_manage destroy <log> <source>\n");
}

static void inspect_channel(EvtApis *apis, Params *params) {
    EVT_HANDLE channel;
    int enabled = -1;
    int classic = -1;
    int retention = -1;
    int autoBackup = -1;
    UINT32 type = 0;
    UINT32 isolation = 0;
    UINT32 level = 0;
    UINT32 bufferSize = 0;
    UINT32 minBuffers = 0;
    UINT32 maxBuffers = 0;
    UINT32 latency = 0;
    UINT32 clockType = 0;
    UINT32 sidType = 0;
    UINT32 fileMax = 0;
    UINT64 maxSize = 0;
    UINT64 keywords = 0;
    int haveType;
    int haveIsolation;
    int haveLevel;
    int haveKeywords;
    int haveBufferSize;
    int haveMinBuffers;
    int haveMaxBuffers;
    int haveLatency;
    int haveClockType;
    int haveSidType;
    int haveFileMax;
    channel = apis->EvtOpenChannelConfig(NULL, params->name, 0);
    if (!channel) {
        BeaconPrintf(CALLBACK_ERROR, "[-] EvtOpenChannelConfig failed for %ls: %lu\n", params->name, (unsigned long)KERNEL32$GetLastError());
        return;
    }
    get_evt_bool(apis, channel, EVT_CHANNEL_CONFIG_ENABLED, &enabled);
    get_evt_bool(apis, channel, EVT_CHANNEL_CONFIG_CLASSIC, &classic);
    get_evt_bool(apis, channel, EVT_CHANNEL_LOGGING_RETENTION, &retention);
    get_evt_bool(apis, channel, EVT_CHANNEL_LOGGING_AUTO_BACKUP, &autoBackup);
    haveType = get_evt_u32(apis, channel, EVT_CHANNEL_CONFIG_TYPE, &type);
    haveIsolation = get_evt_u32(apis, channel, EVT_CHANNEL_CONFIG_ISOLATION, &isolation);
    haveLevel = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_LEVEL, &level);
    haveKeywords = get_evt_u64(apis, channel, EVT_CHANNEL_PUBLISHING_KEYWORDS, &keywords);
    haveBufferSize = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_BUFFER_SIZE, &bufferSize);
    haveMinBuffers = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_MIN_BUFFERS, &minBuffers);
    haveMaxBuffers = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_MAX_BUFFERS, &maxBuffers);
    haveLatency = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_LATENCY, &latency);
    haveClockType = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_CLOCK_TYPE, &clockType);
    haveSidType = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_SID_TYPE, &sidType);
    haveFileMax = get_evt_u32(apis, channel, EVT_CHANNEL_PUBLISHING_FILE_MAX, &fileMax);
    get_evt_u64(apis, channel, EVT_CHANNEL_LOGGING_MAX_SIZE, &maxSize);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Channel: %ls\n", params->name);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] enabled=%d type=%s(%lu) isolation=%s(%lu) classic=%d\n",
                 enabled, haveType ? channel_type_label(type) : "?", (unsigned long)type,
                 haveIsolation ? channel_isolation_label(isolation) : "?", (unsigned long)isolation, classic);
    if (get_evt_string(apis, channel, EVT_CHANNEL_CONFIG_OWNING_PUBLISHER, params->filePath,
                       sizeof(params->filePath) / sizeof(params->filePath[0]))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] owning_publisher=%ls\n", params->filePath);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] owning_publisher=<not configured>\n");
    }
    if (get_evt_string(apis, channel, EVT_CHANNEL_CONFIG_ACCESS, params->filePath,
                       sizeof(params->filePath) / sizeof(params->filePath[0]))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] access=%ls\n", params->filePath);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] access=<not configured>\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i] retention=%d auto_backup=%d max_size_bytes=%llu\n",
                 retention, autoBackup, (unsigned long long)maxSize);
    if (get_evt_string(apis, channel, EVT_CHANNEL_LOGGING_FILE_PATH, params->filePath,
                       sizeof(params->filePath) / sizeof(params->filePath[0]))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] file=%ls\n", params->filePath);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] file=<not configured>\n");
    }
    if (haveLevel || haveKeywords) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] publishing_level=%lu publishing_keywords=0x%llx\n",
                     (unsigned long)level, (unsigned long long)keywords);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] publishing_level=<not configured> publishing_keywords=<not configured>\n");
    }
    print_evt_guid(apis, channel, EVT_CHANNEL_PUBLISHING_CONTROL_GUID);
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[i] buffer_size_kb=%ld min_buffers=%ld max_buffers=%ld latency_ms=%ld\n",
                 haveBufferSize ? (long)bufferSize : -1L, haveMinBuffers ? (long)minBuffers : -1L,
                 haveMaxBuffers ? (long)maxBuffers : -1L, haveLatency ? (long)latency : -1L);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] clock_type=%ld sid_type=%ld file_max=%ld\n",
                 haveClockType ? (long)clockType : -1L, haveSidType ? (long)sidType : -1L,
                 haveFileMax ? (long)fileMax : -1L);
    print_evt_publishers(apis, channel);
    apis->EvtClose(channel);
}

static void create_custom_log(Params *params, DWORD maxSize) {
    HKEY logKey = NULL;
    HKEY sourceKey = NULL;
    DWORD disposition = 0;
    DWORD retention = 0;
    DWORD autoBackup = 0;
    DWORD typesSupported = EVENT_TYPES_SUPPORTED;
    LSTATUS status;
    HANDLE eventSource = NULL;
    LPCWSTR strings[1];
    LPCWSTR creationText = L"Custom event log created by event_log_manage";
    int rootCreated = 0;
    int logNameUse;
    int sourceNameUse;

    if (!valid_custom_name(params->name) || !valid_custom_name(params->source) || wide_eq_ci(params->name, params->source)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid custom log/source name; use distinct letters, digits, spaces, '.', '-', or '_' only\n");
        return;
    }
    logNameUse = registry_name_in_use(params->name);
    sourceNameUse = registry_name_in_use(params->source);
    if (logNameUse < 0 || sourceNameUse < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unable to verify global log/source name uniqueness\n");
        return;
    }
    if (logNameUse == 1 || sourceNameUse == 1) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Log or source name is already registered on this host\n");
        return;
    }
    if (logNameUse == 2 || sourceNameUse == 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Some unrelated EventLog branches were unreadable; no matching log/source name was found\n");
    }
    if (!build_registry_path(params)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Registry path exceeds the module limit\n");
        return;
    }
    status = ADVAPI32$RegCreateKeyExW(HKEY_LOCAL_MACHINE, params->registryPath, 0, NULL, REG_OPTION_NON_VOLATILE,
                                      KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE, NULL, &logKey, &disposition);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] RegCreateKeyExW failed: %ld\n", (long)status);
        if (status == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[!] Permission denied: create requires an elevated Administrator or SYSTEM context with write access to HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\n");
        }
        return;
    }
    if (disposition != REG_CREATED_NEW_KEY) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Refusing to modify an existing log registration: %ls\n", params->name);
        ADVAPI32$RegCloseKey(logKey);
        return;
    }
    rootCreated = 1;
    status = ADVAPI32$RegSetValueExW(logKey, OWNER_VALUE, 0, REG_SZ, (const BYTE *)OWNER_MARKER, (DWORD)((wide_len(OWNER_MARKER) + 1) * sizeof(wchar_t)));
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegSetValueExW(logKey, SOURCE_VALUE, 0, REG_SZ, (const BYTE *)params->source, (DWORD)((wide_len(params->source) + 1) * sizeof(wchar_t)));
    }
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegSetValueExW(logKey, L"MaxSize", 0, REG_DWORD, (const BYTE *)&maxSize, sizeof(maxSize));
    }
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegSetValueExW(logKey, L"Retention", 0, REG_DWORD, (const BYTE *)&retention, sizeof(retention));
    }
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegSetValueExW(logKey, L"AutoBackupLogFiles", 0, REG_DWORD, (const BYTE *)&autoBackup, sizeof(autoBackup));
    }
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegCreateKeyExW(logKey, params->source, 0, NULL, REG_OPTION_NON_VOLATILE,
                                          KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &sourceKey, &disposition);
    }
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegSetValueExW(sourceKey, L"TypesSupported", 0, REG_DWORD, (const BYTE *)&typesSupported, sizeof(typesSupported));
    }
    if (sourceKey) {
        ADVAPI32$RegCloseKey(sourceKey);
    }
    if (logKey) {
        ADVAPI32$RegCloseKey(logKey);
    }
    if (status != ERROR_SUCCESS) {
        if (rootCreated) {
            ADVAPI32$RegDeleteTreeW(HKEY_LOCAL_MACHINE, params->registryPath);
        }
        BeaconPrintf(CALLBACK_ERROR, "[-] Custom log registration failed and was rolled back: %ld\n", (long)status);
        if (status == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[!] Permission denied: create requires an elevated Administrator or SYSTEM context with write access to the EventLog registry tree\n");
        }
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Registered custom log %ls with source %ls\n", params->name, params->source);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] max_size=%lu retention=overwrite owner=%ls\n", (unsigned long)maxSize, OWNER_MARKER);
    eventSource = ADVAPI32$RegisterEventSourceW(NULL, params->source);
    if (!eventSource) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Source registration is present, but RegisterEventSourceW failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    strings[0] = creationText;
    if (ADVAPI32$ReportEventW(eventSource, EVENTLOG_INFORMATION_TYPE, 0, 1, NULL, 1, 0, strings, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Submitted the initial materialization event\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Log registration succeeded, but the initial event write failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
    }
    ADVAPI32$DeregisterEventSource(eventSource);
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Event Log service caching can delay visibility of a newly registered source\n");
}

static int clear_channel(EvtApis *apis, Params *params, int deletingOwnedLog) {
    LPCWSTR backup = params->backup[0] ? params->backup : NULL;
    DWORD error;
    if (!deletingOwnedLog && protected_log(params->name) && !backup) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Clearing %ls requires an absolute backup path\n", params->name);
        return 0;
    }
    if (backup && !absolute_backup_path(backup)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Backup path must be an absolute local drive path\n");
        return 0;
    }
    if (apis->EvtClearLog(NULL, params->name, backup, 0)) {
        if (backup) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Cleared %ls after backing up to %ls\n", params->name, backup);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Cleared %ls\n", params->name);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Event-log clearing is auditable and may be forwarded off-host\n");
        return 1;
    }
    error = KERNEL32$GetLastError();
    if (deletingOwnedLog && (error == ERROR_EVT_CHANNEL_NOT_FOUND_VALUE || error == ERROR_FILE_NOT_FOUND)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No materialized channel was present; continuing owned-registration cleanup\n");
        return 1;
    }
    BeaconPrintf(CALLBACK_ERROR, "[-] EvtClearLog failed for %ls: %lu\n", params->name, (unsigned long)error);
    return 0;
}

static int verify_owned_registration(Params *params) {
    HKEY logKey = NULL;
    HKEY sourceKey = NULL;
    wchar_t owner[64];
    wchar_t registeredSource[256];
    LSTATUS status;

    if (!valid_custom_name(params->name) || !valid_custom_name(params->source) || !build_registry_path(params)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid custom log/source name\n");
        return 0;
    }
    status = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, params->registryPath, 0,
                                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &logKey);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Custom log registration not found: %ls (%ld)\n", params->name, (long)status);
        return 0;
    }
    if (!query_registry_string(logKey, OWNER_VALUE, owner, sizeof(owner)) || !wide_eq_ci(owner, OWNER_MARKER) ||
        !query_registry_string(logKey, SOURCE_VALUE, registeredSource, sizeof(registeredSource)) ||
        !wide_eq_ci(registeredSource, params->source)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Refusing operation on a log not owned by this BOF or with a mismatched source\n");
        ADVAPI32$RegCloseKey(logKey);
        return 0;
    }
    status = ADVAPI32$RegOpenKeyExW(logKey, params->source, 0, KEY_QUERY_VALUE, &sourceKey);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Owned source registration is missing: %ls (%ld)\n", params->source, (long)status);
        ADVAPI32$RegCloseKey(logKey);
        return 0;
    }
    ADVAPI32$RegCloseKey(sourceKey);
    ADVAPI32$RegCloseKey(logKey);
    return 1;
}

static int classic_log_exists(Params *params, HKEY *logKeyOut) {
    LSTATUS status;
    if (!logKeyOut) {
        return 0;
    }
    *logKeyOut = NULL;
    if (!params->name[0] || !build_registry_path(params)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid classic Event Log name\n");
        return 0;
    }
    status = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, params->registryPath, 0,
                                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, logKeyOut);
    if (status == ERROR_SUCCESS) {
        return 1;
    }
    BeaconPrintf(CALLBACK_ERROR, "[-] Classic Event Log registration not found: %ls (%ld)\n",
                 params->name, (long)status);
    if (wide_contains_ci(params->name, L"/") || wide_starts_ci(params->name, L"Microsoft-Windows-")) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[!] That name looks like a modern Event Channel. write, write_raw, and sources target classic EventLog registry keys, not provider-driven channels\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[!] write, write_raw, and sources target classic Event Logs under HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog, not modern Event Channels\n");
    }
    if (status == ERROR_ACCESS_DENIED) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Permission denied: reading EventLog source registrations requires access to HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\n");
    }
    return 0;
}

static int verify_registered_source(Params *params, int forWrite) {
    HKEY logKey = NULL;
    HKEY sourceKey = NULL;
    LSTATUS status;

    if (!params->source[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] A source name is required\n");
        return 0;
    }
    if (forWrite && wide_eq_ci(params->name, L"Security")) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ReportEvent cannot write to the Security log\n");
        return 0;
    }
    if (!classic_log_exists(params, &logKey)) {
        return 0;
    }
    status = ADVAPI32$RegOpenKeyExW(logKey, params->source, 0, KEY_QUERY_VALUE, &sourceKey);
    ADVAPI32$RegCloseKey(logKey);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Source %ls is not registered under classic log %ls (%ld)\n",
                     params->source, params->name, (long)status);
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[!] RegisterEventSource falls back to Application when the source is missing; this BOF refuses that fallback\n");
        if (status == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Permission denied: the current context cannot open the source registration\n");
        }
        return 0;
    }
    ADVAPI32$RegCloseKey(sourceKey);
    return 1;
}

static void list_classic_sources(Params *params) {
    HKEY logKey = NULL;
    DWORD index = 0;
    DWORD nameLength;
    DWORD printed = 0;
    DWORD total = 0;
    int incomplete = 0;
    LSTATUS status;

    if (!classic_log_exists(params, &logKey)) {
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Classic Event Log: %ls\n", params->name);
    while (index < 16384) {
        nameLength = (DWORD)(sizeof(params->source) / sizeof(params->source[0]));
        inline_memset(params->source, 0, sizeof(params->source));
        status = ADVAPI32$RegEnumKeyExW(logKey, index, params->source, &nameLength, NULL, NULL, NULL, NULL);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            incomplete = 1;
            index++;
            continue;
        }
        total++;
        if (printed < MAX_SOURCE_PRINT) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] source[%lu]=%ls\n", (unsigned long)printed, params->source);
            printed++;
        }
        index++;
    }
    ADVAPI32$RegCloseKey(logKey);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] sources=%lu\n", (unsigned long)total);
    if (total > printed) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Source list truncated after %lu entries\n", (unsigned long)printed);
    }
    if (incomplete) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Some source subkeys were unreadable\n");
    }
    if (index >= 16384) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Source enumeration stopped after 16384 keys\n");
    }
}

static void write_custom_event(Params *params, const char *payload, int packedSize) {
    HANDLE heap = KERNEL32$GetProcessHeap();
    HANDLE eventSource = NULL;
    LPWSTR widePayload = NULL;
    LPCWSTR strings[1];
    DWORD payloadBytes = 0;
    DWORD error;
    int wideChars;

    if (!packed_string_length(payload, packedSize, &payloadBytes)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] write requires 1-%lu bytes of null-terminated UTF-8 text\n",
                     (unsigned long)MAX_WRITE_PAYLOAD_BYTES);
        return;
    }
    if (!verify_registered_source(params, 1)) {
        return;
    }
    if (!heap) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcessHeap failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    wideChars = KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, payload, (int)payloadBytes, NULL, 0);
    if (wideChars <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] write payload is not valid UTF-8: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    widePayload = (LPWSTR)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, ((SIZE_T)wideChars + 1) * sizeof(wchar_t));
    if (!widePayload) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed for write payload: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    if (KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, payload, (int)payloadBytes,
                                     widePayload, wideChars) != wideChars) {
        BeaconPrintf(CALLBACK_ERROR, "[-] UTF-8 conversion failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        goto cleanup;
    }
    eventSource = ADVAPI32$RegisterEventSourceW(NULL, params->source);
    if (!eventSource) {
        error = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] RegisterEventSourceW failed: %lu\n", (unsigned long)error);
        if (error == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Permission denied: write requires access to the registered Event Log source\n");
        }
        goto cleanup;
    }
    strings[0] = widePayload;
    if (!ADVAPI32$ReportEventW(eventSource, EVENTLOG_INFORMATION_TYPE, 0, WRITE_EVENT_ID,
                               NULL, 1, 0, strings, NULL)) {
        error = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] ReportEventW failed: %lu\n", (unsigned long)error);
        if (error == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Permission denied: the current context cannot write to this Event Log source\n");
        }
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote event to %ls with source %ls\n", params->name, params->source);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_id=%lu payload_utf8_bytes=%lu payload_utf16_chars=%lu raw_bytes=0\n",
                 (unsigned long)WRITE_EVENT_ID, (unsigned long)payloadBytes, (unsigned long)wideChars);

cleanup:
    if (eventSource && !ADVAPI32$DeregisterEventSource(eventSource)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] DeregisterEventSource failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
    }
    if (widePayload) {
        inline_memset(widePayload, 0, ((size_t)wideChars + 1) * sizeof(wchar_t));
        KERNEL32$HeapFree(heap, 0, widePayload);
    }
}

static void write_raw_event(Params *params, DWORD eventId, WORD category, const char *data, int packedSize) {
    HANDLE eventSource = NULL;
    DWORD error;

    if (!data || packedSize <= 0 || packedSize > (int)MAX_WRITE_RAW_BYTES) {
        BeaconPrintf(CALLBACK_ERROR, "[-] write_raw requires 1-%lu bytes of binary data\n",
                     (unsigned long)MAX_WRITE_RAW_BYTES);
        return;
    }
    if (!verify_registered_source(params, 1)) {
        return;
    }
    eventSource = ADVAPI32$RegisterEventSourceW(NULL, params->source);
    if (!eventSource) {
        error = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] RegisterEventSourceW failed: %lu\n", (unsigned long)error);
        if (error == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Permission denied: write_raw requires access to the registered Event Log source\n");
        }
        return;
    }
    if (!ADVAPI32$ReportEventW(eventSource, EVENTLOG_INFORMATION_TYPE, category, eventId,
                               NULL, 0, (DWORD)packedSize, NULL, (LPVOID)data)) {
        error = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] ReportEventW failed: %lu\n", (unsigned long)error);
        if (error == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Permission denied: the current context cannot write to this Event Log source\n");
        }
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote raw event to %ls with source %ls\n", params->name, params->source);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] event_id=%lu category=0x%04x raw_bytes=%lu insertion_strings=0\n",
                 (unsigned long)eventId, (unsigned int)category, (unsigned long)packedSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Raw Event Log records are readable by anyone who can query that classic log\n");

cleanup:
    if (eventSource && !ADVAPI32$DeregisterEventSource(eventSource)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] DeregisterEventSource failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
    }
}

static void destroy_custom_log(EvtApis *apis, Params *params) {
    LSTATUS status;
    DWORD fileError;

    if (!verify_owned_registration(params)) {
        return;
    }

    if (!clear_channel(apis, params, 1)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Registration was preserved because clearing failed\n");
        return;
    }
    status = ADVAPI32$RegDeleteTreeW(HKEY_LOCAL_MACHINE, params->registryPath);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to remove owned registry tree: %ld\n", (long)status);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed owned log and source registration for %ls\n", params->name);
    build_default_file_path(params);
    if (!safe_owned_file_path(params->filePath)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Backing file path was unavailable or outside the expected Winevt directory; no file was deleted\n");
        return;
    }
    if (KERNEL32$DeleteFileW(params->filePath)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Deleted backing file %ls\n", params->filePath);
        return;
    }
    fileError = KERNEL32$GetLastError();
    if (fileError == ERROR_FILE_NOT_FOUND) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No backing file remained at %ls\n", params->filePath);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Registration was removed, but the Event Log service retained the backing file: %ls (error %lu)\n",
                     params->filePath, (unsigned long)fileError);
    }
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    HANDLE heap = NULL;
    Params *params = NULL;
    EvtApis apis;
    char *action = NULL;
    char *name = NULL;
    char *source = NULL;
    char *payload = NULL;
    char *backup = NULL;
    int payloadSize = 0;
    int requestedSize = 0;
    int categoryRaw = 0;
    DWORD eventId = 0;

    if (alen == 0) {
        print_usage();
        return;
    }
    BeaconDataParse(&parser, args, (int)alen);
    action = BeaconDataExtract(&parser, NULL);
    name = has_more(&parser) ? BeaconDataExtract(&parser, NULL) : NULL;
    if (!action || !action[0] || !name || !name[0]) {
        print_usage();
        return;
    }
    heap = KERNEL32$GetProcessHeap();
    if (!heap) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcessHeap failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    params = (Params *)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(Params));
    if (!params) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        return;
    }
    inline_memset(&apis, 0, sizeof(apis));
    if (!copy_ansi(params->action, sizeof(params->action), action) ||
        !ansi_to_wide(name, params->name, (int)(sizeof(params->name) / sizeof(params->name[0])))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid or oversized action/channel argument\n");
        goto cleanup;
    }

    if (ansi_eq_ci(params->action, "inspect") || ansi_eq_ci(params->action, "clear") ||
        ansi_eq_ci(params->action, "destroy")) {
        if (!resolve_evt_apis(&apis)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve Windows Event Log APIs\n");
            goto cleanup;
        }
    }

    if (ansi_eq_ci(params->action, "inspect")) {
        inspect_channel(&apis, params);
    } else if (ansi_eq_ci(params->action, "create")) {
        source = has_more(&parser) ? BeaconDataExtract(&parser, NULL) : NULL;
        if (!source || !source[0] || !ansi_to_wide(source, params->source, (int)(sizeof(params->source) / sizeof(params->source[0])))) {
            BeaconPrintf(CALLBACK_ERROR, "[-] create requires a valid source name\n");
            goto cleanup;
        }
        if (has_more(&parser)) {
            requestedSize = BeaconDataInt(&parser);
        }
        create_custom_log(params, normalize_log_size(requestedSize));
    } else if (ansi_eq_ci(params->action, "sources")) {
        list_classic_sources(params);
    } else if (ansi_eq_ci(params->action, "write")) {
        source = has_more(&parser) ? BeaconDataExtract(&parser, NULL) : NULL;
        payload = has_more(&parser) ? BeaconDataExtract(&parser, &payloadSize) : NULL;
        if (!source || !source[0] || !ansi_to_wide(source, params->source, (int)(sizeof(params->source) / sizeof(params->source[0])))) {
            BeaconPrintf(CALLBACK_ERROR, "[-] write requires a valid source name\n");
            goto cleanup;
        }
        if (!payload) {
            BeaconPrintf(CALLBACK_ERROR, "[-] write requires a non-empty text payload\n");
            goto cleanup;
        }
        write_custom_event(params, payload, payloadSize);
    } else if (ansi_eq_ci(params->action, "write_raw")) {
        source = has_more(&parser) ? BeaconDataExtract(&parser, NULL) : NULL;
        if (!source || !source[0] || !ansi_to_wide(source, params->source, (int)(sizeof(params->source) / sizeof(params->source[0])))) {
            BeaconPrintf(CALLBACK_ERROR, "[-] write_raw requires a valid source name\n");
            goto cleanup;
        }
        if (BeaconDataLength(&parser) < 8) {
            BeaconPrintf(CALLBACK_ERROR, "[-] write_raw requires event_id, category, and binary data\n");
            goto cleanup;
        }
        eventId = (DWORD)BeaconDataInt(&parser);
        categoryRaw = BeaconDataInt(&parser);
        if (categoryRaw < 0 || categoryRaw > 0xFFFF) {
            BeaconPrintf(CALLBACK_ERROR, "[-] write_raw category must be 0-65535\n");
            goto cleanup;
        }
        payload = has_more(&parser) ? BeaconDataExtract(&parser, &payloadSize) : NULL;
        write_raw_event(params, eventId, (WORD)categoryRaw, payload, payloadSize);
    } else if (ansi_eq_ci(params->action, "clear")) {
        if (has_more(&parser)) {
            backup = BeaconDataExtract(&parser, NULL);
            if (backup && backup[0] && !ansi_to_wide(backup, params->backup, (int)(sizeof(params->backup) / sizeof(params->backup[0])))) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Invalid or oversized backup path\n");
                goto cleanup;
            }
        }
        clear_channel(&apis, params, 0);
    } else if (ansi_eq_ci(params->action, "destroy")) {
        source = has_more(&parser) ? BeaconDataExtract(&parser, NULL) : NULL;
        if (!source || !source[0] || !ansi_to_wide(source, params->source, (int)(sizeof(params->source) / sizeof(params->source[0])))) {
            BeaconPrintf(CALLBACK_ERROR, "[-] destroy requires the original source name\n");
            goto cleanup;
        }
        destroy_custom_log(&apis, params);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unknown action: %s\n", params->action);
        print_usage();
    }

cleanup:
    release_evt_apis(&apis);
    KERNEL32$HeapFree(heap, 0, params);
}
