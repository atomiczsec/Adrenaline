#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "beacon.h"

DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$IsWindowVisible(HWND hWnd);
DECLSPEC_IMPORT WINUSERAPI int WINAPI USER32$GetWindowTextLengthW(HWND hWnd);
DECLSPEC_IMPORT WINUSERAPI int WINAPI USER32$GetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount);
DECLSPEC_IMPORT WINUSERAPI DWORD WINAPI USER32$GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI PSAPI$GetModuleBaseNameW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2);


void inline_memset(void *ptr, int value, size_t num) {
  unsigned char *p = (unsigned char *)ptr;
  while (num-- > 0) {
    *p++ = (unsigned char)value;
  }
}

typedef struct {
  BOOL includeProcessInfo;
  int windowCount;
} ENUM_DATA;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
  ENUM_DATA *data = (ENUM_DATA *)lParam;
  WCHAR windowTitle[256];

  inline_memset(windowTitle, 0, sizeof(windowTitle));

  if (USER32$IsWindowVisible(hwnd)) {
    int length = USER32$GetWindowTextLengthW(hwnd);
    if (length > 0) {
      int readLength = (length + 1 < 256) ? length + 1 : 255;
      USER32$GetWindowTextW(hwnd, windowTitle, readLength);

      if (windowTitle[0] != L'\0') {
        data->windowCount++;
        if (data->includeProcessInfo) {
          DWORD pid = 0;
          USER32$GetWindowThreadProcessId(hwnd, &pid);

          if (pid != 0) {
            HANDLE hProcess = KERNEL32$OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProcess != NULL) {
              WCHAR processName[256];
              inline_memset(processName, 0, sizeof(processName));
              if (PSAPI$GetModuleBaseNameW(hProcess, NULL, processName, 256)) {
                BeaconPrintf(CALLBACK_OUTPUT,
                             "[i] PID: %-6lu | Proc: %-20ls | Title: %ls\n",
                             pid, processName, windowTitle);
              } else {
                BeaconPrintf(
                    CALLBACK_OUTPUT,
                    "[i] PID: %-6lu | Proc: <could not resolve> | Title: %ls\n",
                    pid, windowTitle);
              }
              KERNEL32$CloseHandle(hProcess);
            } else {
              BeaconPrintf(
                  CALLBACK_OUTPUT,
                  "[i] PID: %-6lu | Proc: <access denied> | Title: %ls\n", pid,
                  windowTitle);
            }
          } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[i] PID: %-6lu | Proc: <invalid PID> | Title: %ls\n",
                         0UL, windowTitle);
          }
        } else {
          BeaconPrintf(CALLBACK_OUTPUT, "[i] Title: %ls\n", windowTitle);
        }
      }
    }
  }
  return TRUE;
}

void go(char *args, unsigned long alen) {
  ENUM_DATA data = {0};
  data.includeProcessInfo = FALSE;

  char *arg = NULL;
  if (alen > 0) {
    datap parser = {0};
    BeaconDataParse(&parser, args, (int)alen);
    arg = BeaconDataExtract(&parser, NULL);

    if (arg && KERNEL32$lstrcmpiA(arg, "/pid") == 0) {
      data.includeProcessInfo = TRUE;
    }
  }

  if (data.includeProcessInfo) {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerating windows w/ PIDs...\n");
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Enumerating windows w/ titles...\n");
  }

  USER32$EnumWindows(EnumWindowsProc, (LPARAM)&data);

  if (data.windowCount == 0) {
    BeaconPrintf(CALLBACK_OUTPUT, "[i] No windows found.\n");
  } else {
    const char *infoType = data.includeProcessInfo ? "PIDs" : "titles";
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Found %d visible windows w/ %s.\n",
                 data.windowCount, infoType);
  }
}
