#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <psapi.h>
#include "beacon.h"

#define MAX_PIDS 512
#define MAX_ACCOUNT_CHARS 128
#define HIGH_VALUE_THRESHOLD 50
#define MAX_HIGH_VALUE_ENTRIES 10

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif


DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI PSAPI$GetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI PSAPI$EnumProcesses(DWORD *lpidProcess, DWORD cb, DWORD *lpcbNeeded);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2);

DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

void inline_memset(void *mem, char val, unsigned int size) {
    unsigned char *p = (unsigned char *)mem;
    while (size--) {
        *p++ = val;
    }
}

typedef struct {
    DWORD pid;
    char procName[64];
    char domain[64];
    char user[64];
    BOOL isSystem;
    BOOL isDelegation;
    BOOL isElevated;
    BOOL isDomainUser;
} HighValueEntry;

DWORD SimpleAtoi(const char *str) {
    DWORD result = 0;
    if (!str) return 0;
    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

BOOL IsNumeric(const char *str) {
    if (!str || *str == '\0') return FALSE;
    while (*str) {
        if (*str < '0' || *str > '9') return FALSE;
        str++;
    }
    return TRUE;
}

BOOL MatchProcessNameW(WCHAR *procNameW, const char *filterA) {
    char procNameA[MAX_PATH];
    int i = 0;
    int filterLen = 0;
    int procLen = 0;
    if (!procNameW || !filterA) return FALSE;
    
    while (procNameW[i] != L'\0' && i < (MAX_PATH - 1)) {
        procNameA[i] = (char)procNameW[i];
        i++;
    }
    procNameA[i] = '\0';
    procLen = i;
    
    while (filterA[filterLen] != '\0') {
        filterLen++;
    }
    
    if (filterLen == 0) return FALSE;
    if (filterLen > procLen) return FALSE;
    
    if (KERNEL32$lstrcmpiA(procNameA, filterA) == 0) {
        return TRUE;
    }
    
    if (procLen >= filterLen) {
        char saved = procNameA[filterLen];
        procNameA[filterLen] = '\0';
        BOOL match = (KERNEL32$lstrcmpiA(procNameA, filterA) == 0);
        procNameA[filterLen] = saved;
        if (match) {
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOL IsSystemAccount(const char *domain, const char *user) {
    if (!domain || !user) return FALSE;
    if (KERNEL32$lstrcmpiA(domain, "NT AUTHORITY") == 0) {
        if (KERNEL32$lstrcmpiA(user, "SYSTEM") == 0) return TRUE;
    }
    return FALSE;
}

BOOL IsDomainAccount(const char *domain) {
    if (!domain || domain[0] == '\0') return FALSE;
    if (KERNEL32$lstrcmpiA(domain, "NT AUTHORITY") == 0) return FALSE;
    if (KERNEL32$lstrcmpiA(domain, "BUILTIN") == 0) return FALSE;
    if (KERNEL32$lstrcmpiA(domain, "NT SERVICE") == 0) return FALSE;
    if (KERNEL32$lstrcmpiA(domain, "Window Manager") == 0) return FALSE;
    return TRUE;
}

void WcharToChar(WCHAR *src, char *dest, int max_len) {
    int i = 0;
    while (src[i] != L'\0' && i < (max_len - 1)) {
        dest[i] = (char)src[i];
        i++;
    }
    dest[i] = '\0';
}

const char* GetTokenTypeStr(TOKEN_TYPE tt) {
    if (tt == TokenPrimary) return "Primary";
    if (tt == TokenImpersonation) return "Impersonation";
    return "Unknown";
}

const char* GetImpersonationLevelStr(SECURITY_IMPERSONATION_LEVEL il) {
    switch (il) {
        case SecurityAnonymous: return "Anonymous";
        case SecurityIdentification: return "Identification";
        case SecurityImpersonation: return "Impersonation";
        case SecurityDelegation: return "Delegation";
        default: return "N/A";
    }
}

BOOL EnableSeDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tkp;
    BOOL ok = FALSE;
    LPCWSTR seDebugPriv = L"SeDebugPrivilege";

    inline_memset(&tkp, 0, sizeof(tkp));

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (ADVAPI32$LookupPrivilegeValueW(NULL, seDebugPriv, &tkp.Privileges[0].Luid)) {
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
        if (ok && KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            ok = FALSE;
        }
    }

    KERNEL32$CloseHandle(hToken);
    inline_memset(&tkp, 0, sizeof(tkp));
    return ok;
}


BOOL PrintTokenInfo(HANDLE hToken, DWORD pid, WCHAR* procNameW, HighValueEntry *hvEntry, int hvCount) {
    BYTE tokenUserBuffer[sizeof(TOKEN_USER) + SID_MAX_SUB_AUTHORITIES * sizeof(DWORD)];
    TOKEN_TYPE tokenType = TokenPrimary;
    SECURITY_IMPERSONATION_LEVEL impLevel = SecurityAnonymous;
    TOKEN_ELEVATION tokenElevation;
    DWORD returnLength;
    char procNameA[MAX_PATH];
    WCHAR userName[MAX_ACCOUNT_CHARS];
    WCHAR domainName[MAX_ACCOUNT_CHARS];
    char userNameA[MAX_ACCOUNT_CHARS];
    char domainNameA[MAX_ACCOUNT_CHARS];
    DWORD cchUserName = MAX_ACCOUNT_CHARS;
    DWORD cchDomainName = MAX_ACCOUNT_CHARS;
    SID_NAME_USE sidUse;
    BOOL hasUser = FALSE;
    BOOL hasType = FALSE;
    BOOL hasLevel = FALSE;
    BOOL isElevated = FALSE;
    BOOL isDomainUser = FALSE;
    BOOL isHighValue = FALSE;

    if (procNameW == NULL || procNameW[0] == L'\0') {
        inline_memset(procNameA, 0, sizeof(procNameA));
        procNameA[0] = '<';
        procNameA[1] = 'u';
        procNameA[2] = 'n';
        procNameA[3] = 'k';
        procNameA[4] = 'n';
        procNameA[5] = 'o';
        procNameA[6] = 'w';
        procNameA[7] = 'n';
        procNameA[8] = '>';
        procNameA[9] = '\0';
    } else {
        WcharToChar(procNameW, procNameA, MAX_PATH);
    }
    inline_memset(userName, 0, sizeof(userName));
    inline_memset(domainName, 0, sizeof(domainName));
    inline_memset(userNameA, 0, sizeof(userNameA));
    inline_memset(domainNameA, 0, sizeof(domainNameA));
    inline_memset(tokenUserBuffer, 0, sizeof(tokenUserBuffer));

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenUserBuffer, sizeof(tokenUserBuffer), &returnLength)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PID: %-5lu | Process: %-25s | Couldn't get TokenUser. Error: %lu\n", pid, procNameA, KERNEL32$GetLastError());
        goto cleanup;
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)tokenUserBuffer;
    if (!ADVAPI32$LookupAccountSidW(NULL, pTokenUser->User.Sid, userName, &cchUserName, domainName, &cchDomainName, &sidUse)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PID: %-5lu | Process: %-25s | Couldn't lookup SID. Error: %lu\n", pid, procNameA, KERNEL32$GetLastError());
        goto cleanup;
    }

    WcharToChar(userName, userNameA, MAX_ACCOUNT_CHARS);
    WcharToChar(domainName, domainNameA, MAX_ACCOUNT_CHARS);
    hasUser = TRUE;
    isDomainUser = IsDomainAccount(domainNameA);

    if (!ADVAPI32$GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &returnLength)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PID: %-5lu | Process: %-25s | Couldn't get TokenType. Error: %lu\n", pid, procNameA, KERNEL32$GetLastError());
        goto cleanup;
    }
    hasType = TRUE;

    if (tokenType == TokenImpersonation) {
        if (ADVAPI32$GetTokenInformation(hToken, TokenImpersonationLevel, &impLevel, sizeof(impLevel), &returnLength)) {
            hasLevel = TRUE;
        }
    }

    inline_memset(&tokenElevation, 0, sizeof(tokenElevation));
    if (ADVAPI32$GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(tokenElevation), &returnLength)) {
        isElevated = tokenElevation.TokenIsElevated ? TRUE : FALSE;
    }

    if (IsSystemAccount(domainNameA, userNameA)) {
        isHighValue = TRUE;
    }
    if (hasLevel && impLevel == SecurityDelegation) {
        isHighValue = TRUE;
    }
    if (isElevated && isDomainUser && !IsSystemAccount(domainNameA, userNameA)) {
        if (hvCount < MAX_HIGH_VALUE_ENTRIES) {
            isHighValue = TRUE;
        }
    }

    if (hasUser && hasType) {
        if (hasLevel) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] PID: %-5lu | Process: %-25s | User: %s\\%s | Type: %s | Level: %s\n", 
                pid, procNameA, domainNameA, userNameA, GetTokenTypeStr(tokenType), GetImpersonationLevelStr(impLevel));
        } else if (tokenType == TokenImpersonation) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] PID: %-5lu | Process: %-25s | User: %s\\%s | Type: %s | Level: <Error>\n", 
                pid, procNameA, domainNameA, userNameA, GetTokenTypeStr(tokenType));
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] PID: %-5lu | Process: %-25s | User: %s\\%s | Type: %s\n", 
                pid, procNameA, domainNameA, userNameA, GetTokenTypeStr(tokenType));
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] PID: %-5lu | Process: %-25s | Incomplete token info (hasUser=%d, hasType=%d)\n", 
            pid, procNameA, hasUser, hasType);
    }

    
    if (isHighValue && hvEntry) {
        hvEntry->pid = pid;
        hvEntry->isSystem = IsSystemAccount(domainNameA, userNameA);
        hvEntry->isDelegation = (hasLevel && impLevel == SecurityDelegation);
        hvEntry->isElevated = isElevated;
        hvEntry->isDomainUser = isDomainUser;
        
        int j = 0;
        while (procNameA[j] && j < 63) { hvEntry->procName[j] = procNameA[j]; j++; }
        hvEntry->procName[j] = '\0';
        j = 0;
        while (domainNameA[j] && j < 63) { hvEntry->domain[j] = domainNameA[j]; j++; }
        hvEntry->domain[j] = '\0';
        j = 0;
        while (userNameA[j] && j < 63) { hvEntry->user[j] = userNameA[j]; j++; }
        hvEntry->user[j] = '\0';
    }

cleanup:
    inline_memset(userName, 0, sizeof(userName));
    inline_memset(domainName, 0, sizeof(domainName));
    inline_memset(userNameA, 0, sizeof(userNameA));
    inline_memset(domainNameA, 0, sizeof(domainNameA));
    inline_memset(tokenUserBuffer, 0, sizeof(tokenUserBuffer));
    inline_memset(&tokenElevation, 0, sizeof(tokenElevation));
    inline_memset(procNameA, 0, sizeof(procNameA));
    return isHighValue;
}

void go(char *args, unsigned long alen) {
    DWORD pids[MAX_PIDS], cbNeeded, cProcesses;
    unsigned int i;
    DWORD deniedCount = 0;
    DWORD openedCount = 0;
    DWORD successPercent = 0;
    BOOL truncated = FALSE;
    
    datap parser = {0};
    char *arg1 = NULL;
    char *arg2 = NULL;
    BOOL enableSeDebug = FALSE;
    DWORD filterPid = 0;
    char filterName[64];
    BOOL hasFilter = FALSE;
    
    HighValueEntry hvEntries[MAX_HIGH_VALUE_ENTRIES];
    int hvCount = 0;
    
    inline_memset(filterName, 0, sizeof(filterName));
    inline_memset(hvEntries, 0, sizeof(hvEntries));
    
    if (alen > 0) {
        BeaconDataParse(&parser, args, (int)alen);
        arg1 = BeaconDataExtract(&parser, NULL);
        
        if (arg1 && arg1[0] != '\0') {
            if (KERNEL32$lstrcmpiA(arg1, "/debug") == 0 || KERNEL32$lstrcmpiA(arg1, "/enablesebug") == 0) {
                enableSeDebug = TRUE;
                arg2 = BeaconDataExtract(&parser, NULL);
                if (arg2 && arg2[0] != '\0') {
                    if (IsNumeric(arg2)) {
                        filterPid = SimpleAtoi(arg2);
                        hasFilter = TRUE;
                        BeaconPrintf(CALLBACK_OUTPUT, "[i] filtering for pid: %lu\n", filterPid);
                    } else {
                        int j = 0;
                        while (arg2[j] && j < 63) { filterName[j] = arg2[j]; j++; }
                        filterName[j] = '\0';
                        hasFilter = TRUE;
                        BeaconPrintf(CALLBACK_OUTPUT, "[i] filtering for process: %s\n", filterName);
                    }
                }
            } else {
                if (IsNumeric(arg1)) {
                    filterPid = SimpleAtoi(arg1);
                    hasFilter = TRUE;
                    BeaconPrintf(CALLBACK_OUTPUT, "[i] filtering for pid: %lu\n", filterPid);
                } else {
                    int j = 0;
                    while (arg1[j] && j < 63) { filterName[j] = arg1[j]; j++; }
                    filterName[j] = '\0';
                    hasFilter = TRUE;
                    BeaconPrintf(CALLBACK_OUTPUT, "[i] filtering for process: %s\n", filterName);
                }
                arg2 = BeaconDataExtract(&parser, NULL);
                if (arg2 && (KERNEL32$lstrcmpiA(arg2, "/debug") == 0 || KERNEL32$lstrcmpiA(arg2, "/enablesebug") == 0)) {
                    enableSeDebug = TRUE;
                }
            }
        }
    }
    
    if (enableSeDebug) {
        if (EnableSeDebugPrivilege()) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] seDebugPrivilege enabled.\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] couldn't enable seDebugPrivilege. error: %lu\n", KERNEL32$GetLastError());
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] skipping seDebugPrivilege (OPSEC default).\n");
    }

    inline_memset(pids, 0, sizeof(pids));

    if (!PSAPI$EnumProcesses(pids, sizeof(pids), &cbNeeded)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] enumProcesses failed. error: %lu\n", KERNEL32$GetLastError());
        inline_memset(pids, 0, sizeof(pids));
        return;
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    if (cProcesses > MAX_PIDS) {
        cProcesses = MAX_PIDS;
        truncated = TRUE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[i] enumerating tokens for %lu processes\n", cProcesses);
    if (truncated) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] truncated plist to %lu entries (MAX_PIDS=512).\n", (unsigned long)cProcesses);
    }

    for (i = 0; i < cProcesses; i++) {
        if (pids[i] == 0) continue;
        
        if (hasFilter && filterPid > 0 && pids[i] != filterPid) {
            continue;
        }

        HANDLE hProcess = NULL;
        DWORD desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
        hProcess = KERNEL32$OpenProcess(desiredAccess, FALSE, pids[i]);
        if (hProcess == NULL) {
            desiredAccess = PROCESS_QUERY_INFORMATION;
            hProcess = KERNEL32$OpenProcess(desiredAccess, FALSE, pids[i]);
        }

        if (hProcess == NULL) {
            deniedCount++;
            continue;
        }

        WCHAR procNameW[MAX_PATH];
        WCHAR* last_slash = NULL;
        inline_memset(procNameW, 0, sizeof(procNameW));
        
        DWORD nameLen = PSAPI$GetProcessImageFileNameW(hProcess, procNameW, MAX_PATH - 1);
        if (nameLen > 0 && nameLen < MAX_PATH) {
            WCHAR* p = &procNameW[0];
            last_slash = p;
            while (*p != L'\0') {
                if (*p == L'\\') {
                    last_slash = p + 1;
                }
                p++;
            }
            
            if (hasFilter && filterName[0] != '\0') {
                if (!MatchProcessNameW(last_slash, filterName)) {
                    KERNEL32$CloseHandle(hProcess);
                    inline_memset(procNameW, 0, sizeof(procNameW));
                    continue;
                }
            }            
            openedCount++;

            HANDLE hToken = NULL;
            if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                HighValueEntry *hvSlot = NULL;
                if (hvCount < MAX_HIGH_VALUE_ENTRIES) {
                    hvSlot = &hvEntries[hvCount];
                }
                
                BOOL isHV = PrintTokenInfo(hToken, pids[i], last_slash, hvSlot, hvCount);
                if (isHV && hvSlot) {
                    hvCount++;
                }
                
                KERNEL32$CloseHandle(hToken);
            } else {
                char procNameA[MAX_PATH];
                if (last_slash && last_slash[0] != L'\0') {
                    WcharToChar(last_slash, procNameA, MAX_PATH);
                } else {
                    inline_memset(procNameA, 0, sizeof(procNameA));
                    procNameA[0] = '<';
                    procNameA[1] = 'u';
                    procNameA[2] = 'n';
                    procNameA[3] = 'k';
                    procNameA[4] = 'n';
                    procNameA[5] = 'o';
                    procNameA[6] = 'w';
                    procNameA[7] = 'n';
                    procNameA[8] = '>';
                    procNameA[9] = '\0';
                }
                BeaconPrintf(CALLBACK_ERROR, "[-] PID: %-5lu | Process: %-25s | Couldn't open token. Error: %lu\n", 
                    pids[i], procNameA, KERNEL32$GetLastError());
                inline_memset(procNameA, 0, sizeof(procNameA));
            }
        } else {
            openedCount++;
            DWORD error = KERNEL32$GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "[-] PID: %-5lu | Process: <could not retrieve> | Error: %lu\n", pids[i], error);
        }

        KERNEL32$CloseHandle(hProcess);
        inline_memset(procNameW, 0, sizeof(procNameW));
    }

    if (cProcesses > HIGH_VALUE_THRESHOLD && hvCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[i] high-value processes (top %d)\n", hvCount);
        for (i = 0; i < (unsigned int)hvCount && i < MAX_HIGH_VALUE_ENTRIES; i++) {
            const char *hvType = "";
            if (hvEntries[i].isSystem && hvEntries[i].isDelegation) {
                hvType = "SYSTEM+Delegation";
            } else if (hvEntries[i].isSystem) {
                hvType = "SYSTEM";
            } else if (hvEntries[i].isDelegation) {
                hvType = "Delegation";
            } else if (hvEntries[i].isElevated && hvEntries[i].isDomainUser) {
                hvType = "Elevated+Domain";
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[*] pid: %-5lu | process: %s | domain: %s\\user: %s | type: %s\n",
                hvEntries[i].pid, hvEntries[i].procName, 
                hvEntries[i].domain, hvEntries[i].user, hvType);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    if (cProcesses > 0 && openedCount > 0) {
        successPercent = (openedCount * 100) / cProcesses;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[i] opened: %lu, skipped: %lu, success: %lu\n", openedCount, deniedCount, successPercent);
    
    inline_memset(pids, 0, sizeof(pids));
    inline_memset(filterName, 0, sizeof(filterName));
    inline_memset(hvEntries, 0, sizeof(hvEntries));
}
