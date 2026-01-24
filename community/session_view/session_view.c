#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include "beacon.h"

#define WTS_CURRENT_SERVER_HANDLE ((HANDLE)NULL)

#define WTSSessionId        4
#define WTSUserName         5
#define WTSDomainName       7
#define WTSConnectState     8

#define WTSActive           0
#define WTSConnected        1
#define WTSConnectQuery     2
#define WTSShadow           3
#define WTSDisconnected     4
#define WTSIdle             5
#define WTSListen           6
#define WTSReset            7
#define WTSDown             8
#define WTSInit             9

#define MAX_SESSIONS        200
#define MAX_OUTPUT_SESSIONS 50


#ifndef TokenStatistics
#define TokenStatistics 10
#endif

typedef struct _WTS_SESSION_INFOA {
    DWORD SessionId;
    LPSTR pWinStationName;
    DWORD State;
} WTS_SESSION_INFOA, *PWTS_SESSION_INFOA;

DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSEnumerateSessionsA(
    HANDLE hServer,
    DWORD Reserved,
    DWORD Version,
    PWTS_SESSION_INFOA *ppSessionInfo,
    DWORD *pCount
);

DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSQuerySessionInformationA(
    HANDLE hServer,
    DWORD SessionId,
    DWORD WTSInfoClass,
    LPSTR *ppBuffer,
    DWORD *pBytesReturned
);

DECLSPEC_IMPORT void WINAPI WTSAPI32$WTSFreeMemory(PVOID pMemory);

DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSQueryUserToken(
    ULONG SessionId,
    PHANDLE phToken
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    LPVOID TokenInformation,
    DWORD TokenInformationLength,
    PDWORD ReturnLength
);

DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenA(LPCSTR lpString);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ProcessIdToSessionId(DWORD dwProcessId, PDWORD pSessionId);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

static void inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count-- != 0U) {
        *d++ = (unsigned char)value;
    }
}

static const char* GetStateString(DWORD state) {
    switch (state) {
        case WTSActive:       return "Active";
        case WTSConnected:    return "Connected";
        case WTSConnectQuery: return "ConnectQuery";
        case WTSShadow:       return "Shadow";
        case WTSDisconnected: return "Disconnected";
        case WTSIdle:         return "Idle";
        case WTSListen:       return "Listen";
        case WTSReset:        return "Reset";
        case WTSDown:         return "Down";
        case WTSInit:         return "Init";
        default:              return "Unknown";
    }
}

static BOOL GetSessionInfo(HANDLE hServer, DWORD sessionId, DWORD infoClass, char *outBuffer, size_t bufSize) {
    LPSTR buffer = NULL;
    DWORD bytesReturned = 0;
    int i;
    
    if (outBuffer == NULL || bufSize == 0) {
        return FALSE;
    }
    
    outBuffer[0] = '\0';
    
    if (!WTSAPI32$WTSQuerySessionInformationA(hServer, sessionId, infoClass, &buffer, &bytesReturned)) {
        return FALSE;
    }
    
    if (buffer != NULL && bytesReturned > 0) {
        for (i = 0; i < (int)(bufSize - 1) && i < (int)(bytesReturned - 1) && buffer[i] != '\0'; i++) {
            outBuffer[i] = buffer[i];
        }
        outBuffer[i] = '\0';
        
        WTSAPI32$WTSFreeMemory(buffer);
        return TRUE;
    }
    
    if (buffer != NULL) {
        WTSAPI32$WTSFreeMemory(buffer);
    }
    
    return FALSE;
}

static BOOL GetSessionLuid(DWORD sessionId, char *outBuffer, size_t bufSize) {
    HANDLE hToken = NULL;
    BOOL result = FALSE;
    DWORD returnLength = 0;
    TOKEN_STATISTICS tokenStats;
    DWORD currentSessionId = 0;
    
    if (outBuffer == NULL || bufSize < 32) {
        return FALSE;
    }
    
    outBuffer[0] = '\0';
    inline_memset(&tokenStats, 0, sizeof(tokenStats));
    
    if (KERNEL32$ProcessIdToSessionId(KERNEL32$GetCurrentProcessId(), &currentSessionId)) {
        if (currentSessionId == sessionId) {
            if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            } else {    
                hToken = NULL;
            }
        }
    }
    
    if (hToken == NULL) {
        if (!WTSAPI32$WTSQueryUserToken(sessionId, &hToken)) {
            return FALSE;
        }
    }
    
    returnLength = sizeof(tokenStats);
    if (!ADVAPI32$GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &returnLength)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }
    

    {
        unsigned long high = (unsigned long)tokenStats.AuthenticationId.HighPart;
        unsigned long low = (unsigned long)tokenStats.AuthenticationId.LowPart;
        int pos = 0;
        
        
        outBuffer[pos++] = '0';
        outBuffer[pos++] = 'x';
        
       
        {
            int i;
            char hex[] = "0123456789abcdef";
            for (i = 7; i >= 0; i--) {
                outBuffer[pos++] = hex[(high >> (i * 4)) & 0xF];
            }
        }
        
        outBuffer[pos++] = ':';
        
        {
            int i;
            char hex[] = "0123456789abcdef";
            for (i = 7; i >= 0; i--) {
                outBuffer[pos++] = hex[(low >> (i * 4)) & 0xF];
            }
        }
        
        outBuffer[pos] = '\0';
        result = TRUE;
    }
    
    KERNEL32$CloseHandle(hToken);
    return result;
}

void go(char *args, unsigned long alen) {
    PWTS_SESSION_INFOA pSessionInfo = NULL;
    DWORD sessionCount = 0;
    DWORD sessionsToShow = 0;
    DWORD i;
    BOOL result;
    char username[256];
    char domain[256];
    char luidStr[32];

    (void)args;
    (void)alen;

    result = WTSAPI32$WTSEnumerateSessionsA(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &pSessionInfo,
        &sessionCount
    );

    if (!result || pSessionInfo == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enumerate sessions (Error: %lu)\n",
                     (unsigned long)KERNEL32$GetLastError());
        goto cleanup;
    }

    if (sessionCount > MAX_SESSIONS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Session count (%lu) exceeds safety limit, truncating to %d\n",
                     (unsigned long)sessionCount, MAX_SESSIONS);
        sessionCount = MAX_SESSIONS;
    }

    sessionsToShow = (sessionCount > MAX_OUTPUT_SESSIONS) ? MAX_OUTPUT_SESSIONS : sessionCount;

    for (i = 0; i < sessionsToShow; i++) {
        WTS_SESSION_INFOA *session = &pSessionInfo[i];
        const char *stationName;

        inline_memset(username, 0, sizeof(username));
        inline_memset(domain, 0, sizeof(domain));
        inline_memset(luidStr, 0, sizeof(luidStr));

        if (session->pWinStationName != NULL && session->pWinStationName[0] != '\0') {
            stationName = session->pWinStationName;
        } else {
            stationName = "(none)";
        }

        if (GetSessionInfo(WTS_CURRENT_SERVER_HANDLE, session->SessionId, WTSUserName, username, sizeof(username))) {
            if (username[0] != '\0') {
                BOOL hasLuid = GetSessionLuid(session->SessionId, luidStr, sizeof(luidStr));
                
                if (GetSessionInfo(WTS_CURRENT_SERVER_HANDLE, session->SessionId, WTSDomainName, domain, sizeof(domain))) {
                    if (domain[0] != '\0') {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] %lu (%s): %s - %s\\%s - LUID:%s\n",
                                     (unsigned long)session->SessionId,
                                     stationName,
                                     GetStateString(session->State),
                                     domain,
                                     username,
                                     hasLuid ? luidStr : "(unavailable)");
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] %lu (%s): %s - %s - LUID:%s\n",
                                     (unsigned long)session->SessionId,
                                     stationName,
                                     GetStateString(session->State),
                                     username,
                                     hasLuid ? luidStr : "(unavailable)");
                    }
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] %lu (%s): %s - %s - LUID:%s\n",
                                 (unsigned long)session->SessionId,
                                 stationName,
                                 GetStateString(session->State),
                                 username,
                                 hasLuid ? luidStr : "(unavailable)");
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %lu (%s): %s - (No user logged in)\n",
                             (unsigned long)session->SessionId,
                             stationName,
                             GetStateString(session->State));
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %lu (%s): %s - (No user logged in)\n",
                         (unsigned long)session->SessionId,
                         stationName,
                         GetStateString(session->State));
        }
    }

    if (sessionCount > MAX_OUTPUT_SESSIONS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Truncated: showing first %d of %lu sessions\n",
                     MAX_OUTPUT_SESSIONS, (unsigned long)sessionCount);
    }

cleanup:
    inline_memset(username, 0, sizeof(username));
    inline_memset(domain, 0, sizeof(domain));
    inline_memset(luidStr, 0, sizeof(luidStr));

    if (pSessionInfo != NULL) {
        WTSAPI32$WTSFreeMemory(pSessionInfo);
    }
}

