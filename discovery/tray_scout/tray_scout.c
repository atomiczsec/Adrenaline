#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "beacon.h"

#define WM_USER_VAL 0x0400
#define TB_BUTTONCOUNT (WM_USER_VAL + 24)
#define TB_GETBUTTON (WM_USER_VAL + 23)
#define TB_GETBUTTONTEXTW (WM_USER_VAL + 75)

#define SMTO_ABORTIFHUNG 0x0002

#define MAX_TRAY_BUTTONS 128
#define TOOLBAR_TEXT_CCH 256
#define REMOTE_TB_OFF 0
#define REMOTE_TEXT_OFF 64
#define REMOTE_BLOCK_SIZE (REMOTE_TEXT_OFF + (TOOLBAR_TEXT_CCH * (int)sizeof(WCHAR)))

#define MAX_TRAY_REG_ITEMS 128
#define TRAY_REG_PATH_CCH 520
#define TRAY_REG_NAME_CCH 96
#define TRAY_REG_DEDUP 32
#define TRAY_REG_BASE_CCH 64

#define TRAYDATA_READ 64

DECLSPEC_IMPORT WINUSERAPI HWND WINAPI USER32$FindWindowW(LPCWSTR lpClassName,
                                                        LPCWSTR lpWindowName);
DECLSPEC_IMPORT WINUSERAPI HWND WINAPI USER32$FindWindowExW(HWND hwndParent,
                                                            HWND hwndChildAfter,
                                                            LPCWSTR lpszClass,
                                                            LPCWSTR lpszWindow);
DECLSPEC_IMPORT WINUSERAPI DWORD WINAPI USER32$GetWindowThreadProcessId(
    HWND hWnd, LPDWORD lpdwProcessId);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$IsWindow(HWND hWnd);
DECLSPEC_IMPORT WINUSERAPI LRESULT WINAPI USER32$SendMessageTimeoutW(
    HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, UINT fuFlags, UINT uTimeout,
    PDWORD_PTR lpdwResult);

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(
    DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType,
    DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$VirtualFreeEx(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory(
    HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize,
    SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrcmpiA(LPCSTR lpString1,
                                                       LPCSTR lpString2);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$QueryFullProcessImageNameW(
    HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI PSAPI$GetModuleBaseNameW(
    HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize);

DECLSPEC_IMPORT WINADVAPI LSTATUS WINAPI ADVAPI32$RegOpenKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT WINADVAPI LSTATUS WINAPI ADVAPI32$RegEnumKeyExW(
    HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
    LPWSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime);
DECLSPEC_IMPORT WINADVAPI LSTATUS WINAPI ADVAPI32$RegQueryValueExW(
    HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData,
    LPDWORD lpcbData);
DECLSPEC_IMPORT WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY hKey);

#pragma pack(push, 1)
typedef struct {
  int iBitmap;
  int idCommand;
  BYTE fsState;
  BYTE fsStyle;
  BYTE bReserved[6];
  DWORD_PTR dwData;
  INT_PTR iString;
} TBBUTTON_X64;
#pragma pack(pop)

static void inline_memset(void *ptr, int value, size_t num) {
  unsigned char *p = (unsigned char *)ptr;
  while (num-- > 0) {
    *p++ = (unsigned char)value;
  }
}

static int wchars_len(const WCHAR *s, int maxc) {
  int n = 0;
  while (n < maxc && s[n] != L'\0') {
    n++;
  }
  return n;
}

static void inline_memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  while (n-- > 0) {
    *d++ = *s++;
  }
}

static HWND find_toolbar_deep(HWND parent, int depth) {
  HWND h;
  HWND c;

  if (depth <= 0) {
    return NULL;
  }

  h = USER32$FindWindowExW(parent, NULL, L"ToolbarWindow32", NULL);
  if (h != NULL) {
    return h;
  }

  for (c = USER32$FindWindowExW(parent, NULL, NULL, NULL); c != NULL;
       c = USER32$FindWindowExW(parent, c, NULL, NULL)) {
    h = find_toolbar_deep(c, depth - 1);
    if (h != NULL) {
      return h;
    }
  }
  return NULL;
}

static HWND find_notify_toolbar(void) {
  HWND shellTray;
  HWND notify;
  HWND pager;

  shellTray = USER32$FindWindowW(L"Shell_TrayWnd", NULL);
  if (shellTray == NULL) {
    return NULL;
  }

  notify = USER32$FindWindowExW(shellTray, NULL, L"TrayNotifyWnd", NULL);
  if (notify == NULL) {
    return NULL;
  }

  pager = USER32$FindWindowExW(notify, NULL, L"SysPager", NULL);
  if (pager != NULL) {
    HWND tb = USER32$FindWindowExW(pager, NULL, L"ToolbarWindow32", NULL);
    if (tb != NULL) {
      return tb;
    }
  }

  return USER32$FindWindowExW(notify, NULL, L"ToolbarWindow32", NULL);
}

static HWND find_overflow_toolbar(void) {
  HWND ov;

  ov = USER32$FindWindowExW(NULL, NULL, L"NotifyIconOverflowWindow", NULL);
  if (ov == NULL) {
    return NULL;
  }
  return find_toolbar_deep(ov, 8);
}

static void print_process_names(DWORD pid, int verbose) {
  HANDLE hp;
  WCHAR base[96];
  WCHAR full[270];
  DWORD fullsz;

  inline_memset(base, 0, sizeof(base));
  inline_memset(full, 0, sizeof(full));

  hp = KERNEL32$OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (hp == NULL) {
    hp = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                              pid);
  }
  if (hp == NULL) {
    BeaconPrintf(CALLBACK_OUTPUT, "[-] OpenProcess failed for pid %lu\n",
                 (unsigned long)pid);
    return;
  }

  if (!PSAPI$GetModuleBaseNameW(hp, NULL, base, 95)) {
    KERNEL32$CloseHandle(hp);
    BeaconPrintf(CALLBACK_OUTPUT, "[-] GetModuleBaseNameW failed for pid %lu\n",
                 (unsigned long)pid);
    return;
  }

  if (verbose) {
    fullsz = 269;
    if (KERNEL32$QueryFullProcessImageNameW(hp, 0, full, &fullsz)) {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TaskbarHostExe: %ls\n", base);
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TaskbarHostPath: %ls\n", full);
    } else {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TaskbarHostExe: %ls\n", base);
      BeaconPrintf(CALLBACK_OUTPUT,
                   "[!] TaskbarHostPath: (QueryFullProcessImageNameW failed)\n");
    }
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TaskbarHostExe: %ls\n", base);
  }

  KERNEL32$CloseHandle(hp);
}

static void resolve_icon_process(DWORD_PTR trayDataPtr, HANDLE hExplorer,
                                 int verbose, WCHAR *tipLocal, int tipLen) {
  BYTE blob[TRAYDATA_READ];
  SIZE_T got;
  HWND iconHwnd;
  DWORD iconPid;
  HANDLE hp;
  WCHAR base[96];
  WCHAR full[270];
  DWORD fullsz;

  inline_memset(blob, 0, sizeof(blob));
  got = 0;

  if (trayDataPtr == 0) {
    goto print_tip_only;
  }

  if (!KERNEL32$ReadProcessMemory(hExplorer, (LPCVOID)trayDataPtr, blob,
                                  sizeof(blob), &got) ||
      got < sizeof(HWND)) {
    goto print_tip_only;
  }

  inline_memcpy(&iconHwnd, blob, sizeof(HWND));
  if (iconHwnd == NULL || !USER32$IsWindow(iconHwnd)) {
    goto print_tip_only;
  }

  iconPid = 0;
  USER32$GetWindowThreadProcessId(iconHwnd, &iconPid);
  if (iconPid == 0) {
    goto print_tip_only;
  }

  hp = KERNEL32$OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, iconPid);
  if (hp == NULL) {
    hp = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                              iconPid);
  }
  if (hp == NULL) {
    if (tipLen > 0) {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %.*ls (pid %lu, path n/a)\n",
                   tipLen, tipLocal, (unsigned long)iconPid);
    } else {
      BeaconPrintf(CALLBACK_OUTPUT,
                   "[+] TrayItem: (no tooltip) pid %lu path n/a\n",
                   (unsigned long)iconPid);
    }
    return;
  }

  inline_memset(base, 0, sizeof(base));
  inline_memset(full, 0, sizeof(full));
  if (!PSAPI$GetModuleBaseNameW(hp, NULL, base, 95)) {
    KERNEL32$CloseHandle(hp);
    goto print_tip_only;
  }

  if (verbose) {
    fullsz = 269;
    if (KERNEL32$QueryFullProcessImageNameW(hp, 0, full, &fullsz)) {
      if (tipLen > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %.*ls\n", tipLen, tipLocal);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItemExe: %ls\n", base);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItemPath: %ls\n", full);
      } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: (no tooltip)\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItemExe: %ls\n", base);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItemPath: %ls\n", full);
      }
    } else {
      if (tipLen > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %.*ls\n", tipLen, tipLocal);
      } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: (no tooltip)\n");
      }
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItemExe: %ls\n", base);
      BeaconPrintf(CALLBACK_OUTPUT,
                   "[!] TrayItemPath: (QueryFullProcessImageNameW failed)\n");
    }
  } else {
    if (tipLen > 0) {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %.*ls | %ls\n", tipLen,
                   tipLocal, base);
    } else {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: (no tooltip) | %ls\n", base);
    }
  }

  KERNEL32$CloseHandle(hp);
  return;

print_tip_only:
  if (tipLen > 0) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %.*ls\n", tipLen, tipLocal);
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: (no tooltip)\n");
  }
}

static void enum_tray_toolbar(HWND hToolbar, const char *area_label, int verbose) {
  DWORD explorerPid = 0;
  HANDLE hExplorer = NULL;
  LPVOID remote = NULL;
  DWORD_PTR smres;
  int count;
  int i;
  TBBUTTON_X64 btn;
  SIZE_T got;
  WCHAR tipLocal[TOOLBAR_TEXT_CCH];

  USER32$GetWindowThreadProcessId(hToolbar, &explorerPid);
  if (explorerPid == 0) {
    BeaconPrintf(CALLBACK_OUTPUT, "[-] %s: could not resolve toolbar pid\n",
                 area_label);
    return;
  }

  hExplorer = KERNEL32$OpenProcess(
      PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
          PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE, explorerPid);
  if (hExplorer == NULL) {
    hExplorer = KERNEL32$OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION,
        FALSE, explorerPid);
  }
  if (hExplorer == NULL) {
    BeaconPrintf(
        CALLBACK_OUTPUT,
        "[-] %s: OpenProcess(vm) failed for explorer pid %lu (tray enum skipped)\n",
        area_label, (unsigned long)explorerPid);
    return;
  }

  remote = KERNEL32$VirtualAllocEx(hExplorer, NULL, REMOTE_BLOCK_SIZE,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (remote == NULL) {
    BeaconPrintf(CALLBACK_OUTPUT, "[-] %s: VirtualAllocEx failed\n", area_label);
    KERNEL32$CloseHandle(hExplorer);
    return;
  }

  smres = 0;
  if (!USER32$SendMessageTimeoutW(hToolbar, TB_BUTTONCOUNT, 0, 0, SMTO_ABORTIFHUNG,
                                  200, &smres)) {
    BeaconPrintf(CALLBACK_OUTPUT, "[-] %s: TB_BUTTONCOUNT failed\n", area_label);
    KERNEL32$VirtualFreeEx(hExplorer, remote, 0, MEM_RELEASE);
    KERNEL32$CloseHandle(hExplorer);
    return;
  }

  count = (int)smres;
  if (count < 0) {
    count = 0;
  }
  if (count > MAX_TRAY_BUTTONS) {
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[!] %s: capping buttons %d -> %d\n", area_label, count,
                 MAX_TRAY_BUTTONS);
    count = MAX_TRAY_BUTTONS;
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[i] %s: %d tray button(s)\n", area_label, count);

  for (i = 0; i < count; i++) {
    BYTE *rbase = (BYTE *)remote;

    inline_memset(&btn, 0, sizeof(btn));
    inline_memset(tipLocal, 0, sizeof(tipLocal));

    smres = 0;
    if (!USER32$SendMessageTimeoutW(hToolbar, TB_GETBUTTON, (WPARAM)i,
                                    (LPARAM)(rbase + REMOTE_TB_OFF),
                                    SMTO_ABORTIFHUNG, 200, &smres)) {
      continue;
    }

    got = 0;
    if (!KERNEL32$ReadProcessMemory(hExplorer, rbase + REMOTE_TB_OFF, &btn,
                                    sizeof(btn), &got) ||
        got != sizeof(btn)) {
      continue;
    }

    smres = 0;
    (void)USER32$SendMessageTimeoutW(
        hToolbar, TB_GETBUTTONTEXTW, (WPARAM)btn.idCommand,
        (LPARAM)(rbase + REMOTE_TEXT_OFF), SMTO_ABORTIFHUNG, 200, &smres);

    got = 0;
    (void)KERNEL32$ReadProcessMemory(hExplorer, rbase + REMOTE_TEXT_OFF, tipLocal,
                                     sizeof(tipLocal) - sizeof(WCHAR), &got);
    tipLocal[TOOLBAR_TEXT_CCH - 1] = L'\0';

    {
      int tl = wchars_len(tipLocal, TOOLBAR_TEXT_CCH);
      resolve_icon_process(btn.dwData, hExplorer, verbose, tipLocal, tl);
    }
  }

  if (remote != NULL) {
    KERNEL32$VirtualFreeEx(hExplorer, remote, 0, MEM_RELEASE);
  }
  KERNEL32$CloseHandle(hExplorer);
}

static int wide_equals_ci(const WCHAR *a, const WCHAR *b, int maxc) {
  int i = 0;
  while (i < maxc && a[i] != L'\0' && b[i] != L'\0') {
    WCHAR ca = a[i];
    WCHAR cb = b[i];
    if (ca >= L'A' && ca <= L'Z') {
      ca = (WCHAR)(ca + 32);
    }
    if (cb >= L'A' && cb <= L'Z') {
      cb = (WCHAR)(cb + 32);
    }
    if (ca != cb) {
      return 0;
    }
    i++;
  }
  return (i < maxc && a[i] == L'\0' && b[i] == L'\0');
}

static void tray_path_basename(const WCHAR *path, WCHAR *base, int base_cch) {
  const WCHAR *last;
  const WCHAR *p;
  int i;

  if (base == NULL || base_cch <= 0) {
    return;
  }
  base[0] = L'\0';
  if (path == NULL || path[0] == L'\0') {
    return;
  }

  last = path;
  for (p = path; *p != L'\0'; p++) {
    if (*p == L'\\' || *p == L'/') {
      last = p + 1;
    }
  }
  for (i = 0; i < base_cch - 1 && last[i] != L'\0'; i++) {
    base[i] = last[i];
  }
  base[i] = L'\0';
}

static int tray_base_seen(WCHAR seen[][TRAY_REG_BASE_CCH], int seen_count,
                          const WCHAR *path) {
  WCHAR base[TRAY_REG_BASE_CCH];
  int i;

  tray_path_basename(path, base, TRAY_REG_BASE_CCH);
  if (base[0] == L'\0') {
    return 1;
  }

  for (i = 0; i < seen_count; i++) {
    if (wide_equals_ci(seen[i], base, TRAY_REG_BASE_CCH)) {
      return 1;
    }
  }
  return 0;
}

static void tray_base_store(WCHAR seen[][TRAY_REG_BASE_CCH], int *seen_count,
                            const WCHAR *path) {
  if (*seen_count >= TRAY_REG_DEDUP) {
    return;
  }
  tray_path_basename(path, seen[*seen_count], TRAY_REG_BASE_CCH);
  if (seen[*seen_count][0] != L'\0') {
    (*seen_count)++;
  }
}

static void print_tray_reg_item(const WCHAR *exe_path, const WCHAR *tooltip,
                                int verbose) {
  WCHAR base[TRAY_REG_BASE_CCH];
  int tip_len;

  if (exe_path == NULL || exe_path[0] == L'\0') {
    return;
  }

  tray_path_basename(exe_path, base, TRAY_REG_BASE_CCH);
  tip_len = wchars_len(tooltip, 128);
  if (verbose) {
    if (tip_len > 0) {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %.*ls\n", tip_len, tooltip);
    } else {
      BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %ls\n", base);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItemExe: %ls\n", base);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItemPath: %ls\n", exe_path);
    return;
  }

  if (tip_len > 0) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %.*ls | %ls\n", tip_len, tooltip,
                 base);
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] TrayItem: %ls\n", base);
  }
}

static int query_reg_sz(HKEY hKey, LPCWSTR value_name, WCHAR *out, DWORD out_cch) {
  DWORD type = 0;
  DWORD cb = out_cch * (DWORD)sizeof(WCHAR);
  LSTATUS st;

  if (out == NULL || out_cch == 0) {
    return 0;
  }
  out[0] = L'\0';
  st = ADVAPI32$RegQueryValueExW(hKey, value_name, NULL, &type, (LPBYTE)out, &cb);
  if (st != ERROR_SUCCESS || type != REG_SZ) {
    out[0] = L'\0';
    return 0;
  }
  out[out_cch - 1] = L'\0';
  return out[0] != L'\0';
}

static int enum_tray_registry(int verbose, int *items_out) {
  HKEY hRoot = NULL;
  DWORD index = 0;
  WCHAR subname[64];
  WCHAR exe_path[TRAY_REG_PATH_CCH];
  WCHAR tooltip[128];
  WCHAR seen[TRAY_REG_DEDUP][TRAY_REG_BASE_CCH];
  int seen_count = 0;
  int items = 0;

  if (items_out != NULL) {
    *items_out = 0;
  }

  if (ADVAPI32$RegOpenKeyExW(HKEY_CURRENT_USER,
                             L"Control Panel\\NotifyIconSettings", 0, KEY_READ,
                             &hRoot) != ERROR_SUCCESS) {
    return 0;
  }

  BeaconPrintf(CALLBACK_OUTPUT,
               "[i] NotifyIconSettings: registry tray metadata (Win11 fallback)\n");

  for (;;) {
    DWORD subname_cch = (DWORD)(sizeof(subname) / sizeof(subname[0]));
    HKEY hItem = NULL;
    LSTATUS st;

    inline_memset(subname, 0, sizeof(subname));
    st = ADVAPI32$RegEnumKeyExW(hRoot, index, subname, &subname_cch, NULL, NULL,
                                NULL, NULL);
    if (st != ERROR_SUCCESS) {
      break;
    }
    index++;

    if (ADVAPI32$RegOpenKeyExW(hRoot, subname, 0, KEY_READ, &hItem) != ERROR_SUCCESS) {
      continue;
    }

    inline_memset(exe_path, 0, sizeof(exe_path));
    inline_memset(tooltip, 0, sizeof(tooltip));
    if (!query_reg_sz(hItem, L"ExecutablePath", exe_path,
                      (DWORD)(sizeof(exe_path) / sizeof(exe_path[0])))) {
      ADVAPI32$RegCloseKey(hItem);
      continue;
    }
    (void)query_reg_sz(hItem, L"InitialTooltip", tooltip,
                       (DWORD)(sizeof(tooltip) / sizeof(tooltip[0])));
    ADVAPI32$RegCloseKey(hItem);

    if (tray_base_seen(seen, seen_count, exe_path)) {
      continue;
    }
    tray_base_store(seen, &seen_count, exe_path);
    print_tray_reg_item(exe_path, tooltip, verbose);
    items++;
    if (items >= MAX_TRAY_REG_ITEMS) {
      BeaconPrintf(CALLBACK_OUTPUT,
                   "[!] NotifyIconSettings: capped at %d item(s)\n",
                   MAX_TRAY_REG_ITEMS);
      break;
    }
  }

  ADVAPI32$RegCloseKey(hRoot);
  if (items_out != NULL) {
    *items_out = items;
  }
  return items > 0;
}

void go(char *args, unsigned long alen) {
  datap parser = {0};
  HWND shellTray;
  DWORD trayPid = 0;
  HWND tbMain;
  HWND tbOver;
  int verbose = 0;
  char *arg = NULL;

  if (alen > 0) {
    BeaconDataParse(&parser, args, (int)alen);
    arg = BeaconDataExtract(&parser, NULL);
    if (arg != NULL &&
        (KERNEL32$lstrcmpiA(arg, "verbose") == 0 ||
         KERNEL32$lstrcmpiA(arg, "/verbose") == 0)) {
      verbose = 1;
    }
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[i] tray_scout: notification area recon\n");

  shellTray = USER32$FindWindowW(L"Shell_TrayWnd", NULL);
  if (shellTray == NULL) {
    BeaconPrintf(CALLBACK_OUTPUT, "[-] Shell_TrayWnd not found\n");
    return;
  }

  USER32$GetWindowThreadProcessId(shellTray, &trayPid);
  if (trayPid == 0) {
    BeaconPrintf(CALLBACK_OUTPUT, "[-] Could not resolve taskbar host pid\n");
    return;
  }

  print_process_names(trayPid, verbose);

  tbMain = find_notify_toolbar();
  if (tbMain == NULL) {
    {
      int reg_items = 0;
      if (enum_tray_registry(verbose, &reg_items)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] NotifyIconSettings: %d unique tray item(s)\n",
                     reg_items);
      } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[-] Main tray ToolbarWindow32 not found (layout unsupported?)\n");
        BeaconPrintf(CALLBACK_OUTPUT,
                     "[-] NotifyIconSettings registry fallback found no tray items\n");
      }
    }
  } else {
    enum_tray_toolbar(tbMain, "MainTray", verbose);
  }

  tbOver = find_overflow_toolbar();
  if (tbOver == NULL) {
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[i] Overflow tray not present or not yet created\n");
  } else {
    enum_tray_toolbar(tbOver, "OverflowTray", verbose);
  }

  BeaconPrintf(CALLBACK_OUTPUT, "[i] tray_scout finished\n");
}
