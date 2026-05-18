#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include "beacon.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

#define MAX_WIDE_STRING 256
#define MAX_FAILURE_ACTIONS 16
#define MAX_ENUM_SERVICES 200

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);
DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR *lpServiceArgVectors);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE hService);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$ChangeServiceConfig2W(SC_HANDLE hService, DWORD dwInfoLevel, LPVOID lpInfo);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$QueryServiceConfigW(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$EnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count-- != 0U) {
        *d++ = (unsigned char)value;
    }
}

static void copy_wide_string(LPWSTR dest, size_t destLen, LPCWSTR src) {
    size_t i = 0;

    if (destLen == 0) {
        return;
    }

    if (src == NULL) {
        dest[0] = L'\0';
        return;
    }

    while (i < (destLen - 1) && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
}

static int wide_to_utf8(LPCWSTR src, char *dst, int dstSize) {
    int converted;

    if (dst == NULL || dstSize <= 0) {
        return 0;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return 1;
    }

    converted = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstSize, NULL, NULL);
    if (converted == 0) {
        int i = 0;
        while (src[i] != L'\0' && i < (dstSize - 1)) {
            dst[i] = (char)(src[i] & 0xFF);
            i++;
        }
        dst[i] = '\0';
        converted = i + 1;
    }

    return converted;
}

static wchar_t wide_tolower(wchar_t c) {
    if (c >= L'A' && c <= L'Z') {
        return (wchar_t)(c + 32);
    }
    return c;
}

static BOOL wide_equals_ci(LPCWSTR a, LPCWSTR b) {
    if (a == NULL || b == NULL) {
        return FALSE;
    }

    while (*a != L'\0' && *b != L'\0') {
        if (wide_tolower(*a) != wide_tolower(*b)) {
            return FALSE;
        }
        a++;
        b++;
    }

    return (*a == L'\0' && *b == L'\0');
}

static BOOL has_more(datap *parser) {
    return (BeaconDataLength(parser) > 0);
}

static BOOL extract_wide_string(datap *parser, wchar_t *dest, size_t destLen) {
    char *raw = BeaconDataExtract(parser, NULL);
    if (destLen == 0) {
        return FALSE;
    }

    if (raw == NULL) {
        dest[0] = L'\0';
        return FALSE;
    }

    copy_wide_string(dest, destLen, (LPCWSTR)raw);
    return (dest[0] != L'\0');
}

static void print_windows_error(const char *context, DWORD error) {
    LPSTR message = NULL;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

    if (KERNEL32$FormatMessageA(flags, NULL, error, 0, (LPSTR)&message, 0, NULL) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s (0x%08lx): %s", (context != NULL) ? context : "Windows error", (unsigned long)error, message);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s (0x%08lx)", (context != NULL) ? context : "Windows error", (unsigned long)error);
    }

    if (message != NULL) {
        KERNEL32$LocalFree(message);
    }
}

static void report_last_error(const char *context) {
    DWORD err = KERNEL32$GetLastError();
    print_windows_error(context, err);
}

static void close_service_handle(SC_HANDLE handle, const char *context) {
    if (handle == NULL) {
        return;
    }

    if (!ADVAPI32$CloseServiceHandle(handle)) {
        report_last_error(context);
    }
}

static BOOL parse_dword(LPCWSTR *cursor, DWORD *value) {
    DWORD result = 0;
    BOOL seen = FALSE;
    LPCWSTR p = *cursor;

    while (*p == L' ' || *p == L'\t') {
        p++;
    }

    while (*p >= L'0' && *p <= L'9') {
        result = (result * 10) + (DWORD)(*p - L'0');
        p++;
        seen = TRUE;
    }

    *cursor = p;
    if (!seen) {
        return FALSE;
    }

    *value = result;
    return TRUE;
}

static BOOL read_token(LPCWSTR *cursor, wchar_t *dest, size_t destLen) {
    size_t i = 0;
    LPCWSTR p = *cursor;

    if (destLen == 0) {
        return FALSE;
    }

    while (*p == L' ' || *p == L'\t' || *p == L',' || *p == L';') {
        p++;
    }

    if (*p == L'\0') {
        dest[0] = L'\0';
        *cursor = p;
        return FALSE;
    }

    while (*p != L'\0' && *p != L':' && *p != L'=' && *p != L',' && *p != L';' && *p != L' ' && *p != L'\t') {
        if (i < (destLen - 1)) {
            dest[i++] = *p;
        }
        p++;
    }

    dest[i] = L'\0';
    *cursor = p;
    return (i > 0);
}

static BOOL parse_failure_actions(LPCWSTR input, SC_ACTION *actions, DWORD maxActions, DWORD *actionCount) {
    DWORD count = 0;
    LPCWSTR cursor = input;
    wchar_t token[32];

    if (actionCount == NULL || actions == NULL || maxActions == 0) {
        return FALSE;
    }

    *actionCount = 0;
    if (input == NULL || input[0] == L'\0') {
        return TRUE;
    }

    while (*cursor != L'\0') {
        SC_ACTION action;
        DWORD delay = 0;

        inline_memset(&action, 0, sizeof(action));

        if (!read_token(&cursor, token, ARRAYSIZE(token))) {
            break;
        }

        while (*cursor == L' ' || *cursor == L'\t') {
            cursor++;
        }

        if (*cursor == L':' || *cursor == L'=') {
            cursor++;
        }

        if (!parse_dword(&cursor, &delay)) {
            delay = 0;
        }

        if (wide_equals_ci(token, L"none")) {
            action.Type = SC_ACTION_NONE;
        } else if (wide_equals_ci(token, L"restart")) {
            action.Type = SC_ACTION_RESTART;
        } else if (wide_equals_ci(token, L"reboot")) {
            action.Type = SC_ACTION_REBOOT;
        } else if (wide_equals_ci(token, L"run")) {
            action.Type = SC_ACTION_RUN_COMMAND;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Unknown failure action type: %ls", token);
            return FALSE;
        }

        action.Delay = delay;
        actions[count] = action;
        count++;

        if (count >= maxActions) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Failure action list truncated at %lu entries", (unsigned long)maxActions);
            break;
        }

        while (*cursor == L' ' || *cursor == L'\t' || *cursor == L',' || *cursor == L';') {
            cursor++;
        }
    }

    *actionCount = count;
    return TRUE;
}

static const char* service_state_str(DWORD state) {
    switch (state) {
        case SERVICE_STOPPED:          return "STOPPED";
        case SERVICE_START_PENDING:    return "START_PENDING";
        case SERVICE_STOP_PENDING:     return "STOP_PENDING";
        case SERVICE_RUNNING:          return "RUNNING";
        case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
        case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
        case SERVICE_PAUSED:           return "PAUSED";
        default:                       return "UNKNOWN";
    }
}

static const char* start_type_str(DWORD startType) {
    switch (startType) {
        case SERVICE_BOOT_START:   return "BOOT";
        case SERVICE_SYSTEM_START: return "SYSTEM";
        case SERVICE_AUTO_START:   return "AUTO";
        case SERVICE_DEMAND_START: return "DEMAND";
        case SERVICE_DISABLED:     return "DISABLED";
        default:                   return "UNKNOWN";
    }
}

static const char* service_type_str(DWORD type) {
    if (type & SERVICE_KERNEL_DRIVER)        return "KERNEL_DRIVER";
    if (type & SERVICE_FILE_SYSTEM_DRIVER)   return "FS_DRIVER";
    if (type & SERVICE_WIN32_OWN_PROCESS)    return "WIN32_OWN_PROCESS";
    if (type & SERVICE_WIN32_SHARE_PROCESS)  return "WIN32_SHARE_PROCESS";
    return "OTHER";
}

static void copy_ascii_string(char *dest, size_t destLen, const char *src) {
    size_t i = 0;
    if (dest == NULL || destLen == 0) {
        return;
    }
    if (src == NULL) {
        dest[0] = '\0';
        return;
    }
    while (i < (destLen - 1) && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

static void truncate_ascii(char *text, size_t width) {
    size_t i = 0;
    if (text == NULL || width == 0) {
        return;
    }
    while (text[i] != '\0' && i < width) {
        i++;
    }
    if (text[i] == '\0') {
        return;
    }
    if (width == 1) {
        text[0] = '\0';
        return;
    }
    if (width == 2) {
        text[0] = '.';
        text[1] = '\0';
        return;
    }
    if (width == 3) {
        text[0] = '.';
        text[1] = '.';
        text[2] = '\0';
        return;
    }
    text[width - 3] = '.';
    text[width - 2] = '.';
    text[width - 1] = '.';
    text[width] = '\0';
}

static void query_single_service(SC_HANDLE scManager, LPCWSTR serviceName) {
    SC_HANDLE service = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    DWORD configError = 0;
    BOOL configReady = FALSE;
    LPQUERY_SERVICE_CONFIGW config = NULL;
    char nameA[MAX_WIDE_STRING];
    char displayA[MAX_WIDE_STRING];
    char binPathA[MAX_WIDE_STRING];
    char startNameA[MAX_WIDE_STRING];

    inline_memset(&ssp, 0, sizeof(ssp));
    inline_memset(nameA, 0, sizeof(nameA));

    service = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (service == NULL) {
        report_last_error("OpenServiceW");
        return;
    }

    wide_to_utf8(serviceName, nameA, sizeof(nameA));

    if (!ADVAPI32$QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        report_last_error("QueryServiceStatusEx");
        close_service_handle(service, "CloseServiceHandle");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Service: %s\n", nameA);
    BeaconPrintf(CALLBACK_OUTPUT, "    State:   %s\n", service_state_str(ssp.dwCurrentState));
    BeaconPrintf(CALLBACK_OUTPUT, "    Type:    %s\n", service_type_str(ssp.dwServiceType));
    BeaconPrintf(CALLBACK_OUTPUT, "    PID:     %lu\n", (unsigned long)ssp.dwProcessId);

    needed = 0;
    if (!ADVAPI32$QueryServiceConfigW(service, NULL, 0, &needed)) {
        configError = KERNEL32$GetLastError();
    }

    if (configError == ERROR_INSUFFICIENT_BUFFER && needed > 0) {
        config = (LPQUERY_SERVICE_CONFIGW)KERNEL32$VirtualAlloc(NULL, needed, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (config != NULL) {
            if (ADVAPI32$QueryServiceConfigW(service, config, needed, &needed)) {
                configReady = TRUE;
                inline_memset(displayA, 0, sizeof(displayA));
                inline_memset(binPathA, 0, sizeof(binPathA));
                inline_memset(startNameA, 0, sizeof(startNameA));
                wide_to_utf8(config->lpDisplayName, displayA, sizeof(displayA));
                wide_to_utf8(config->lpBinaryPathName, binPathA, sizeof(binPathA));
                wide_to_utf8(config->lpServiceStartName, startNameA, sizeof(startNameA));
                BeaconPrintf(CALLBACK_OUTPUT, "    Display: %s\n", displayA);
                BeaconPrintf(CALLBACK_OUTPUT, "    Binary:  %s\n", binPathA);
                BeaconPrintf(CALLBACK_OUTPUT, "    Start:   %s\n", start_type_str(config->dwStartType));
                BeaconPrintf(CALLBACK_OUTPUT, "    Account: %s\n", startNameA);
            } else {
                configError = KERNEL32$GetLastError();
            }
            KERNEL32$VirtualFree(config, 0, MEM_RELEASE);
        } else {
            configError = KERNEL32$GetLastError();
        }
    }

    if (!configReady) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Service config details unavailable (0x%08lx)\n", (unsigned long)configError);
    }

    close_service_handle(service, "CloseServiceHandle");
}

static void handle_query(datap *parser) {
    wchar_t serviceName[MAX_WIDE_STRING];
    SC_HANDLE scManager = NULL;
    DWORD needed = 0;
    DWORD returned = 0;
    DWORD resume = 0;
    DWORD enumError = 0;
    BOOL enumPartial = FALSE;
    LPBYTE buf = NULL;
    DWORD i;

    inline_memset(serviceName, 0, sizeof(serviceName));

    extract_wide_string(parser, serviceName, ARRAYSIZE(serviceName));

    if (serviceName[0] != L'\0') {
        scManager = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (scManager == NULL) {
            report_last_error("OpenSCManagerW");
            return;
        }
        query_single_service(scManager, serviceName);
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    scManager = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (scManager == NULL) {
        report_last_error("OpenSCManagerW");
        return;
    }

    if (!ADVAPI32$EnumServicesStatusExW(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                        NULL, 0, &needed, &returned, &resume, NULL)) {
        enumError = KERNEL32$GetLastError();
    }

    if (needed == 0 || (enumError != 0 && enumError != ERROR_MORE_DATA)) {
        report_last_error("EnumServicesStatusExW");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    buf = (LPBYTE)KERNEL32$VirtualAlloc(NULL, needed, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf == NULL) {
        report_last_error("VirtualAlloc");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    resume = 0;
    if (!ADVAPI32$EnumServicesStatusExW(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                        buf, needed, &needed, &returned, &resume, NULL)) {
        enumError = KERNEL32$GetLastError();
        if (enumError == ERROR_MORE_DATA && returned > 0) {
            enumPartial = TRUE;
        } else {
            report_last_error("EnumServicesStatusExW");
            KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
            close_service_handle(scManager, "CloseServiceHandle");
            return;
        }
    }

    {
        DWORD limit = (returned > MAX_ENUM_SERVICES) ? MAX_ENUM_SERVICES : returned;
        if (returned > MAX_ENUM_SERVICES) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerated %lu services (showing first %d)\n", (unsigned long)returned, MAX_ENUM_SERVICES);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerated %lu services\n", (unsigned long)returned);
        }
        if (enumPartial) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Service enumeration truncated; additional services are available\n");
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-16s %-7s %s\n", "SERVICE", "STATE", "PID", "DISPLAY");
        returned = limit;
    }

    for (i = 0; i < returned; i++) {
        ENUM_SERVICE_STATUS_PROCESSW *svc = &((ENUM_SERVICE_STATUS_PROCESSW *)buf)[i];
        char nameA[256];
        char displayA[256];
        char stateA[32];

        inline_memset(nameA, 0, sizeof(nameA));
        inline_memset(displayA, 0, sizeof(displayA));
        inline_memset(stateA, 0, sizeof(stateA));
        wide_to_utf8(svc->lpServiceName, nameA, sizeof(nameA));
        wide_to_utf8(svc->lpDisplayName, displayA, sizeof(displayA));
        copy_ascii_string(stateA, sizeof(stateA), service_state_str(svc->ServiceStatusProcess.dwCurrentState));
        truncate_ascii(nameA, 22);
        truncate_ascii(stateA, 16);
        truncate_ascii(displayA, 28);

        BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-16s %-7lu %s\n",
                     nameA,
                     stateA,
                     (unsigned long)svc->ServiceStatusProcess.dwProcessId,
                     displayA);
    }

    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    close_service_handle(scManager, "CloseServiceHandle");
}

static void print_usage(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] service_control <create|start|stop|delete|failure|query>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] create  <service_name> <bin_path> [display_name] [start_type] [service_type] [error_control]\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] start   <service_name>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] stop    <service_name>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] delete  <service_name>\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] failure <service_name> <reset_seconds> [reboot_msg] [command] [actions]\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] failure actions format: restart:5000,run:1000,none:0 (type:delay ms)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[i] query   [service_name]  (omit name to list all services)\n");
}

static void handle_create(datap *parser) {
    wchar_t serviceName[MAX_WIDE_STRING];
    wchar_t binPath[MAX_WIDE_STRING];
    wchar_t displayName[MAX_WIDE_STRING];
    DWORD startType = SERVICE_DEMAND_START;
    DWORD serviceType = SERVICE_WIN32_OWN_PROCESS;
    DWORD errorControl = SERVICE_ERROR_NORMAL;
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    char serviceNameA[MAX_WIDE_STRING];

    inline_memset(serviceName, 0, sizeof(serviceName));
    inline_memset(binPath, 0, sizeof(binPath));
    inline_memset(displayName, 0, sizeof(displayName));

    if (!extract_wide_string(parser, serviceName, ARRAYSIZE(serviceName)) ||
        !extract_wide_string(parser, binPath, ARRAYSIZE(binPath))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] create requires service name and binary path");
        return;
    }

    if (has_more(parser)) {
        extract_wide_string(parser, displayName, ARRAYSIZE(displayName));
    }

    if (displayName[0] == L'\0') {
        copy_wide_string(displayName, ARRAYSIZE(displayName), serviceName);
    }

    if (has_more(parser)) {
        startType = (DWORD)BeaconDataInt(parser);
    }

    if (has_more(parser)) {
        serviceType = (DWORD)BeaconDataInt(parser);
    }

    if (has_more(parser)) {
        errorControl = (DWORD)BeaconDataInt(parser);
    }

    scManager = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (scManager == NULL) {
        report_last_error("OpenSCManagerW");
        return;
    }

    service = ADVAPI32$CreateServiceW(scManager, serviceName, displayName, SERVICE_CHANGE_CONFIG, serviceType,
                                     startType, errorControl, binPath, NULL, NULL, NULL, NULL, NULL);
    if (service == NULL) {
        report_last_error("CreateServiceW");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    wide_to_utf8(serviceName, serviceNameA, sizeof(serviceNameA));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Created service %s", serviceNameA);

    close_service_handle(service, "CloseServiceHandle");
    close_service_handle(scManager, "CloseServiceHandle");
}

static void handle_start(datap *parser) {
    wchar_t serviceName[MAX_WIDE_STRING];
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    char serviceNameA[MAX_WIDE_STRING];

    inline_memset(serviceName, 0, sizeof(serviceName));

    if (!extract_wide_string(parser, serviceName, ARRAYSIZE(serviceName))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] start requires service name");
        return;
    }

    scManager = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager == NULL) {
        report_last_error("OpenSCManagerW");
        return;
    }

    service = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_START);
    if (service == NULL) {
        report_last_error("OpenServiceW");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    if (!ADVAPI32$StartServiceW(service, 0, NULL)) {
        report_last_error("StartServiceW");
        close_service_handle(service, "CloseServiceHandle");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    wide_to_utf8(serviceName, serviceNameA, sizeof(serviceNameA));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Started service %s", serviceNameA);

    close_service_handle(service, "CloseServiceHandle");
    close_service_handle(scManager, "CloseServiceHandle");
}

static void handle_stop(datap *parser) {
    wchar_t serviceName[MAX_WIDE_STRING];
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS status;
    char serviceNameA[MAX_WIDE_STRING];

    inline_memset(serviceName, 0, sizeof(serviceName));
    inline_memset(&status, 0, sizeof(status));

    if (!extract_wide_string(parser, serviceName, ARRAYSIZE(serviceName))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] stop requires service name");
        return;
    }

    scManager = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager == NULL) {
        report_last_error("OpenSCManagerW");
        return;
    }

    service = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_STOP);
    if (service == NULL) {
        report_last_error("OpenServiceW");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    if (!ADVAPI32$ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        report_last_error("ControlService");
        close_service_handle(service, "CloseServiceHandle");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    wide_to_utf8(serviceName, serviceNameA, sizeof(serviceNameA));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Stopped service %s", serviceNameA);

    close_service_handle(service, "CloseServiceHandle");
    close_service_handle(scManager, "CloseServiceHandle");
}

static void handle_delete(datap *parser) {
    wchar_t serviceName[MAX_WIDE_STRING];
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    char serviceNameA[MAX_WIDE_STRING];

    inline_memset(serviceName, 0, sizeof(serviceName));

    if (!extract_wide_string(parser, serviceName, ARRAYSIZE(serviceName))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] delete requires service name");
        return;
    }

    scManager = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager == NULL) {
        report_last_error("OpenSCManagerW");
        return;
    }

    service = ADVAPI32$OpenServiceW(scManager, serviceName, DELETE);
    if (service == NULL) {
        report_last_error("OpenServiceW");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    if (!ADVAPI32$DeleteService(service)) {
        report_last_error("DeleteService");
        close_service_handle(service, "CloseServiceHandle");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    wide_to_utf8(serviceName, serviceNameA, sizeof(serviceNameA));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Deleted service %s", serviceNameA);

    close_service_handle(service, "CloseServiceHandle");
    close_service_handle(scManager, "CloseServiceHandle");
}

static void handle_failure(datap *parser) {
    wchar_t serviceName[MAX_WIDE_STRING];
    wchar_t rebootMsg[MAX_WIDE_STRING];
    wchar_t command[MAX_WIDE_STRING];
    wchar_t actionsInput[MAX_WIDE_STRING];
    DWORD resetPeriod = 0;
    SC_ACTION actions[MAX_FAILURE_ACTIONS];
    DWORD actionCount = 0;
    SERVICE_FAILURE_ACTIONSW failureActions;
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    char serviceNameA[MAX_WIDE_STRING];

    inline_memset(serviceName, 0, sizeof(serviceName));
    inline_memset(rebootMsg, 0, sizeof(rebootMsg));
    inline_memset(command, 0, sizeof(command));
    inline_memset(actionsInput, 0, sizeof(actionsInput));
    inline_memset(actions, 0, sizeof(actions));
    inline_memset(&failureActions, 0, sizeof(failureActions));

    if (!extract_wide_string(parser, serviceName, ARRAYSIZE(serviceName))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] failure requires service name");
        return;
    }

    if (!has_more(parser)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] failure requires reset period in seconds");
        return;
    }

    resetPeriod = (DWORD)BeaconDataInt(parser);

    if (has_more(parser)) {
        extract_wide_string(parser, rebootMsg, ARRAYSIZE(rebootMsg));
    }

    if (has_more(parser)) {
        extract_wide_string(parser, command, ARRAYSIZE(command));
    }

    if (has_more(parser)) {
        extract_wide_string(parser, actionsInput, ARRAYSIZE(actionsInput));
    }

    if (!parse_failure_actions(actionsInput, actions, ARRAYSIZE(actions), &actionCount)) {
        return;
    }

    failureActions.dwResetPeriod = resetPeriod;
    failureActions.lpRebootMsg = (rebootMsg[0] != L'\0') ? rebootMsg : NULL;
    failureActions.lpCommand = (command[0] != L'\0') ? command : NULL;
    failureActions.cActions = actionCount;
    failureActions.lpsaActions = (actionCount > 0) ? actions : NULL;

    scManager = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager == NULL) {
        report_last_error("OpenSCManagerW");
        return;
    }

    service = ADVAPI32$OpenServiceW(scManager, serviceName, SERVICE_CHANGE_CONFIG);
    if (service == NULL) {
        report_last_error("OpenServiceW");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    if (!ADVAPI32$ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
        report_last_error("ChangeServiceConfig2W");
        close_service_handle(service, "CloseServiceHandle");
        close_service_handle(scManager, "CloseServiceHandle");
        return;
    }

    wide_to_utf8(serviceName, serviceNameA, sizeof(serviceNameA));
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Updated failure actions for %s", serviceNameA);

    close_service_handle(service, "CloseServiceHandle");
    close_service_handle(scManager, "CloseServiceHandle");
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    wchar_t subcommand[MAX_WIDE_STRING];

    inline_memset(&parser, 0, sizeof(parser));
    inline_memset(subcommand, 0, sizeof(subcommand));

    if (alen == 0) {
        print_usage();
        return;
    }

    BeaconDataParse(&parser, args, (int)alen);

    if (!extract_wide_string(&parser, subcommand, ARRAYSIZE(subcommand))) {
        print_usage();
        return;
    }

    if (wide_equals_ci(subcommand, L"create")) {
        handle_create(&parser);
        return;
    }

    if (wide_equals_ci(subcommand, L"start")) {
        handle_start(&parser);
        return;
    }

    if (wide_equals_ci(subcommand, L"stop")) {
        handle_stop(&parser);
        return;
    }

    if (wide_equals_ci(subcommand, L"delete")) {
        handle_delete(&parser);
        return;
    }

    if (wide_equals_ci(subcommand, L"failure")) {
        handle_failure(&parser);
        return;
    }

    if (wide_equals_ci(subcommand, L"query")) {
        handle_query(&parser);
        return;
    }

    BeaconPrintf(CALLBACK_ERROR, "[-] Unknown subcommand: %ls\n", subcommand);
    print_usage();
}
