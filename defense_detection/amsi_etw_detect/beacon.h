/*
 * Common BOF (Beacon Object File) Header
 * Provides standard Windows API declarations for BOF development
 * Compatible with Cobalt Strike BOF loader and COFFLoader
 */

#ifndef BOF_COMMON_H
#define BOF_COMMON_H

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

#ifndef WINAPI
#define WINAPI __stdcall
#endif

// Basic Windows types
typedef void*           PVOID;
typedef void*           HANDLE;
typedef void*           HMODULE;
typedef void*           HINSTANCE;
typedef void*           FARPROC;
typedef unsigned long   DWORD;
typedef unsigned short  WORD;
typedef unsigned char   BYTE;
typedef int             BOOL;
typedef char            CHAR;
typedef short           SHORT;
typedef long            LONG;
typedef unsigned short  wchar_t;
typedef wchar_t         WCHAR;

// String types
typedef const char*     LPCSTR;
typedef char*           LPSTR;
typedef const wchar_t*  LPCWSTR;
typedef wchar_t*        LPWSTR;

// Constants
#define TRUE  1
#define FALSE 0
#define NULL  ((void*)0)

// Process/Thread types
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION;

// Beacon API declarations
DECLSPEC_IMPORT void BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char *data, int len);

// Beacon callback types
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

// Essential Windows API functions - BOF format with LIBRARY$ prefix
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR lpModuleName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR lpLibFileName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE hLibModule);

#endif // BOF_COMMON_H