#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

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

// Constants and section labels
#define MAX_PATH_LEN 480
#define SECTION_WINDOWS_COPILOT "[i] Windows Copilot"
#define SECTION_OFFICE_COPILOT  "[i] Office Copilot"
#define SECTION_EDGE_COPILOT    "[i] Edge Copilot"
#define SECTION_GH_COPILOT      "[i] GitHub Copilot"
#define SECTION_THIRD_PARTY_AI  "[i] Third-party AI"


#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#endif
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFF)
#endif
#define INVALID_ATTR INVALID_FILE_ATTRIBUTES
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

typedef struct {
    DWORD dwFileAttributes;
    unsigned long nFileSizeHigh;
    unsigned long nFileSizeLow;
    wchar_t cFileName[260];
} WIN32_FIND_DATAW;
typedef WIN32_FIND_DATAW *LPWIN32_FIND_DATAW;

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE);
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
    if (!s) return 0;
    while (s[i] != L'\0') {
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

static int ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

static int ascii_contains_ci(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    size_t nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0) return 0;
    for (size_t i = 0; hay[i]; i++) {
        size_t j = 0;
        while (hay[i + j] && needle[j] &&
               ascii_tolower((int)hay[i + j]) == ascii_tolower((int)needle[j])) {
            j++;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static void wchar_to_ascii(const wchar_t *src, char *dst, size_t max) {
    size_t i = 0;
    if (!src || !dst || max == 0) return;
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
    if (!path) return 0;
    DWORD attr = KERNEL32$GetFileAttributesW(path);
    return (attr != INVALID_ATTR);
}

static void report_path_if_exists(const wchar_t *label, const wchar_t *path) {
    if (!label || !path) return;
    if (path_exists(path)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", label, path);
    }
}

static int name_matches_copilot(const wchar_t *name) {
    if (!name) return 0;
    char ascii[256];
    inline_memset(ascii, 0, sizeof(ascii));
    wchar_to_ascii(name, ascii, sizeof(ascii));
    int result = ascii_contains_ci(ascii, "copilot") || ascii_contains_ci(ascii, "microsoft.windows.copilot");
    inline_memset(ascii, 0, sizeof(ascii));
    return result;
}

static void check_taskbar_ai_setting() {
    HKEY hKey = NULL;
    LONG res = ADVAPI32$RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        0,
        KEY_READ,
        &hKey
    );
    if (res != ERROR_SUCCESS) {
        return;
    }

    DWORD value = 0;
    DWORD type = 0;
    DWORD size = sizeof(DWORD);
    res = ADVAPI32$RegQueryValueExW(hKey, L"TaskbarAI", NULL, &type, (LPBYTE)&value, &size);
    if (res == ERROR_SUCCESS && type == REG_DWORD && value != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Copilot visible in taskbar\n");
    }
    ADVAPI32$RegCloseKey(hKey);
    value = 0;
    type = 0;
    size = 0;
}

static void check_windows_copilot(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_WINDOWS_COPILOT ":\n");

    wchar_t localApp[MAX_PATH_LEN];
    wchar_t packagesRoot[MAX_PATH_LEN];
    wchar_t search[MAX_PATH_LEN];
    wchar_t localState[MAX_PATH_LEN];
    wchar_t sub[MAX_PATH_LEN];
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    int found = 0;

    inline_memset(localApp, 0, sizeof(localApp));
    inline_memset(packagesRoot, 0, sizeof(packagesRoot));
    inline_memset(search, 0, sizeof(search));
    inline_memset(localState, 0, sizeof(localState));
    inline_memset(sub, 0, sizeof(sub));
    inline_memset(&fd, 0, sizeof(fd));

    DWORD len = KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH_LEN);
    if (len == 0 || len >= MAX_PATH_LEN) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
    }

    if (!build_path(localApp, L"\\Packages\\", packagesRoot, MAX_PATH_LEN)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
    }
    if (!build_path(packagesRoot, L"Microsoft*", search, MAX_PATH_LEN)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
    }

    hFind = KERNEL32$FindFirstFileW(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                continue;
            }
            if (fd.cFileName[0] == L'.') continue;

            if (!name_matches_copilot(fd.cFileName)) {
                continue;
            }
            found = 1;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Package: %S\n", fd.cFileName);

            inline_memset(localState, 0, sizeof(localState));
            if (!build_path(packagesRoot, fd.cFileName, localState, MAX_PATH_LEN)) {
                continue;
            }
            size_t len_ls = inline_wcslen(localState);
            if (len_ls + 12 < MAX_PATH_LEN) {
                localState[len_ls++] = L'\\';
                localState[len_ls] = L'\0';
                build_path(localState, L"LocalState", localState, MAX_PATH_LEN);
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
    inline_memset(localApp, 0, sizeof(localApp));
    inline_memset(packagesRoot, 0, sizeof(packagesRoot));
    inline_memset(search, 0, sizeof(search));
    inline_memset(localState, 0, sizeof(localState));
    inline_memset(sub, 0, sizeof(sub));
    inline_memset(&fd, 0, sizeof(fd));
}

static void check_office_copilot(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_OFFICE_COPILOT ":\n");

    HKEY hKey = NULL;
    LONG res = ADVAPI32$RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Office\\16.0\\Common\\Identity",
        0,
        KEY_READ,
        &hKey
    );
    int office_installed = 0;
    if (res == ERROR_SUCCESS) {
        office_installed = 1;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Office installed\n");
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }

    wchar_t appData[MAX_PATH_LEN];
    wchar_t localAppData[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    int any = 0;

    inline_memset(appData, 0, sizeof(appData));
    inline_memset(localAppData, 0, sizeof(localAppData));
    inline_memset(path, 0, sizeof(path));

    DWORD lenA = KERNEL32$GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH_LEN);
    DWORD lenL = KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH_LEN);

    if (lenL > 0 && lenL < MAX_PATH_LEN) {
        inline_memset(path, 0, sizeof(path));
        if (build_path(localAppData, L"\\Microsoft\\Office\\16.0\\OfficeFileCache", path, MAX_PATH_LEN)) {
            if (path_exists(path)) {
                any = 1;
                report_path_if_exists(L"OfficeFileCache", path);
            }
        }

        inline_memset(path, 0, sizeof(path));
        if (build_path(localAppData, L"\\Microsoft\\Office\\Copilot", path, MAX_PATH_LEN)) {
            if (path_exists(path)) {
                any = 1;
                report_path_if_exists(L"Copilot", path);
            }
        }
    }

    if (lenA > 0 && lenA < MAX_PATH_LEN) {
        inline_memset(path, 0, sizeof(path));
        if (build_path(appData, L"\\Microsoft\\Office\\OfficeFileCache", path, MAX_PATH_LEN)) {
            if (path_exists(path)) {
                any = 1;
                report_path_if_exists(L"OfficeFileCache", path);
            }
        }

        inline_memset(path, 0, sizeof(path));
        if (build_path(appData, L"\\Microsoft\\Office\\Copilot", path, MAX_PATH_LEN)) {
            if (path_exists(path)) {
                any = 1;
                report_path_if_exists(L"Copilot", path);
            }
        }
    }

    if (!office_installed && !any) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    }

    inline_memset(path, 0, sizeof(path));
    inline_memset(appData, 0, sizeof(appData));
    inline_memset(localAppData, 0, sizeof(localAppData));
}

static void check_edge_copilot(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_EDGE_COPILOT ":\n");

    wchar_t localApp[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    wchar_t profileSearch[MAX_PATH_LEN];
    wchar_t profileLeveldb[MAX_PATH_LEN];
    char ascii[256];
    WIN32_FIND_DATAW fd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    int any = 0;

    inline_memset(localApp, 0, sizeof(localApp));
    inline_memset(path, 0, sizeof(path));
    inline_memset(profileSearch, 0, sizeof(profileSearch));
    inline_memset(profileLeveldb, 0, sizeof(profileLeveldb));
    inline_memset(ascii, 0, sizeof(ascii));
    inline_memset(&fd, 0, sizeof(fd));

    DWORD len = KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH_LEN);
    if (len == 0 || len >= MAX_PATH_LEN) {
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
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
                if (fd.cFileName[0] == L'.') continue;
                
                inline_memset(ascii, 0, sizeof(ascii));
                wchar_to_ascii(fd.cFileName, ascii, sizeof(ascii));
                if (ascii_contains_ci(ascii, "Profile 1") || ascii_contains_ci(ascii, "Default")) {
                    inline_memset(ascii, 0, sizeof(ascii));
                    continue;
                }
                
                inline_memset(profileLeveldb, 0, sizeof(profileLeveldb));
                if (!build_path(localApp, L"\\Microsoft\\Edge\\User Data\\", profileLeveldb, MAX_PATH_LEN)) {
                    inline_memset(ascii, 0, sizeof(ascii));
                    continue;
                }
                size_t plen = inline_wcslen(profileLeveldb);
                size_t j = 0;
                while (fd.cFileName[j] && plen + 1 < MAX_PATH_LEN) {
                    profileLeveldb[plen++] = fd.cFileName[j++];
                }
                profileLeveldb[plen] = L'\0';
                if (!build_path(profileLeveldb, L"\\Local Storage\\leveldb", profileLeveldb, MAX_PATH_LEN)) {
                    inline_memset(ascii, 0, sizeof(ascii));
                    continue;
                }
                
                if (path_exists(profileLeveldb)) {
                    any = 1;
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %S: %S\n", fd.cFileName, profileLeveldb);
                }
                inline_memset(ascii, 0, sizeof(ascii));
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
    inline_memset(localApp, 0, sizeof(localApp));
    inline_memset(path, 0, sizeof(path));
    inline_memset(profileSearch, 0, sizeof(profileSearch));
    inline_memset(profileLeveldb, 0, sizeof(profileLeveldb));
    inline_memset(ascii, 0, sizeof(ascii));
    inline_memset(&fd, 0, sizeof(fd));
}

static void scan_vscode_workspace_storage(const wchar_t *base_path, const wchar_t *variant_name) {
    if (!base_path || !variant_name) {
        return;
    }

    wchar_t wsPath[MAX_PATH_LEN];
    inline_memset(wsPath, 0, sizeof(wsPath));

    if (!build_path(base_path, L"\\workspaceStorage", wsPath, MAX_PATH_LEN)) {
        return;
    }
    
    if (path_exists(wsPath)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %S workspaceStorage: %S\n", variant_name, wsPath);
    }
}

static void check_github_copilot(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_GH_COPILOT ":\n");

    wchar_t appData[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    wchar_t codePath[MAX_PATH_LEN];
    int any = 0;

    inline_memset(appData, 0, sizeof(appData));
    inline_memset(path, 0, sizeof(path));
    inline_memset(codePath, 0, sizeof(codePath));

    DWORD len = KERNEL32$GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH_LEN);
    if (len == 0 || len >= MAX_PATH_LEN) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
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

cleanup:
    inline_memset(path, 0, sizeof(path));
    inline_memset(codePath, 0, sizeof(codePath));
    inline_memset(appData, 0, sizeof(appData));
}

static void check_third_party_ai(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n" SECTION_THIRD_PARTY_AI ":\n");

    wchar_t appData[MAX_PATH_LEN];
    wchar_t path[MAX_PATH_LEN];
    int any = 0;

    inline_memset(appData, 0, sizeof(appData));
    inline_memset(path, 0, sizeof(path));

    DWORD len = KERNEL32$GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH_LEN);
    if (len == 0 || len >= MAX_PATH_LEN) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
        goto cleanup;
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

    if (!any) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Not detected\n");
    }

cleanup:
    inline_memset(path, 0, sizeof(path));
    inline_memset(appData, 0, sizeof(appData));
}

void go(char *args, unsigned long alen) {
    (void)args;
    (void)alen;

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Mapping AI/Copilot tool presence:\n");

    check_windows_copilot();
    check_office_copilot();
    check_edge_copilot();
    check_github_copilot();
    check_third_party_ai();
}
