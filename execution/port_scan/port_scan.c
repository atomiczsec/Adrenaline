#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "beacon.h"

#ifndef WSAAPI
#define WSAAPI __stdcall
#endif

#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define INVALID_SOCKET ((SOCKET)(~0ULL))
#define SOCKET_ERROR (-1)
#define FIONBIO 0x8004667E
#ifndef WSAEWOULDBLOCK
#define WSAEWOULDBLOCK 10035
#endif
#define INADDR_NONE 0xFFFFFFFF
#define SOL_SOCKET 0xFFFF
#define SO_ERROR 0x1007
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04
#ifndef MAKEWORD
#define MAKEWORD(a, b) ((WORD)(((BYTE)(a)) | ((WORD)((BYTE)(b))) << 8))
#endif

#define MAX_PORTS 1024
#define MAX_OPEN_OUTPUT 200
#define DEFAULT_TIMEOUT_MS 1000
#define MAX_TIMEOUT_MS 30000

typedef unsigned long long SOCKET;

typedef struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char *lpVendorInfo;
} WSADATA, *LPWSADATA;

typedef struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
} SOCKADDR;

typedef struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    struct in_addr {
        union {
            struct {
                unsigned char s_b1;
                unsigned char s_b2;
                unsigned char s_b3;
                unsigned char s_b4;
            } S_un_b;
            unsigned long S_addr;
        } S_un;
    } sin_addr;
    char sin_zero[8];
} SOCKADDR_IN;

typedef struct timeval {
    long tv_sec;
    long tv_usec;
} TIMEVAL;

typedef struct fd_set_local {
    unsigned int fd_count;
    SOCKET fd_array[1];
} FD_SET_LOCAL;

typedef struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
} HOSTENT;

#define FD_ZERO_ONE(set) do { (set)->fd_count = 0; (set)->fd_array[0] = 0; } while (0)
#define FD_SET_ONE(sock, set) do { (set)->fd_array[0] = (sock); (set)->fd_count = 1; } while (0)

DECLSPEC_IMPORT void WINAPI BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *WINAPI BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT short WINAPI BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int WINAPI BeaconDataInt(datap *parser);
DECLSPEC_IMPORT int WINAPI BeaconDataLength(datap *parser);
DECLSPEC_IMPORT void WINAPI BeaconPrintf(int type, char *fmt, ...);

DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET s, const struct sockaddr *name, int namelen);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET s);
DECLSPEC_IMPORT int WSAAPI WS2_32$select(int nfds, FD_SET_LOCAL *readfds, FD_SET_LOCAL *writefds, FD_SET_LOCAL *exceptfds, const struct timeval *timeout);
DECLSPEC_IMPORT int WSAAPI WS2_32$ioctlsocket(SOCKET s, long cmd, unsigned long *argp);
DECLSPEC_IMPORT int WSAAPI WS2_32$sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *cp);
DECLSPEC_IMPORT unsigned short WSAAPI WS2_32$htons(unsigned short hostshort);
DECLSPEC_IMPORT struct hostent *WSAAPI WS2_32$gethostbyname(const char *name);
DECLSPEC_IMPORT int WSAAPI WS2_32$getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

static const int TOP20_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
};

static const int TOP100_PORTS[] = {
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157
};

static void zero_bytes(void *dest, SIZE_T count) {
    unsigned char *d = (unsigned char *)dest;
    while (count-- != 0) {
        *d++ = 0;
    }
}

static void copy_bytes(void *dest, const void *src, SIZE_T count) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (count-- != 0) {
        *d++ = *s++;
    }
}

static int str_equals(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0' && *a == *b) {
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

static int parse_uint_max(const char *text, int max_value, int *value) {
    int result = 0;
    int seen = 0;
    int digit = 0;

    if (text == NULL || max_value <= 0 || value == NULL) {
        return 0;
    }

    while (*text >= '0' && *text <= '9') {
        digit = *text - '0';
        if (result > (max_value - digit) / 10) {
            return 0;
        }
        result = (result * 10) + digit;
        seen = 1;
        text++;
    }

    if (!seen || *text != '\0') {
        return 0;
    }

    *value = result;
    return 1;
}

static int parse_slice_uint(const char *start, const char *end, int max_value, int *value) {
    int result = 0;
    int digit = 0;

    if (start == NULL || end == NULL || start >= end || max_value <= 0 || value == NULL) {
        return 0;
    }

    while (start < end) {
        if (*start < '0' || *start > '9') {
            return 0;
        }
        digit = *start - '0';
        if (result > (max_value - digit) / 10) {
            return 0;
        }
        result = (result * 10) + digit;
        start++;
    }

    *value = result;
    return 1;
}

static int append_port(int *ports, int max_ports, int count, int port) {
    if (ports == NULL || count >= max_ports || port < 1 || port > 65535) {
        return count;
    }
    ports[count] = port;
    return count + 1;
}

static int parse_port_range(const char *spec, int *ports, int max_ports) {
    const char *dash = spec;
    int start = 0;
    int end = 0;
    int count = 0;
    int port = 0;

    while (*dash != '\0' && *dash != '-') {
        dash++;
    }

    if (*dash != '-') {
        return 0;
    }

    if (!parse_slice_uint(spec, dash, 65535, &start) || !parse_uint_max(dash + 1, 65535, &end)) {
        return 0;
    }

    if (start < 1 || end > 65535 || start > end) {
        return 0;
    }

    if ((end - start + 1) > max_ports) {
        return -1;
    }

    for (port = start; port <= end; port++) {
        count = append_port(ports, max_ports, count, port);
    }

    return count;
}

static int parse_port_list(const char *spec, int *ports, int max_ports) {
    const char *cursor = spec;
    const char *token = spec;
    int count = 0;
    int port = 0;

    while (*cursor != '\0') {
        while (*cursor == ',' || *cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        token = cursor;
        while (*cursor != '\0' && *cursor != ',' && *cursor != ' ') {
            cursor++;
        }

        if (!parse_slice_uint(token, cursor, 65535, &port) || port < 1) {
            return 0;
        }
        if (count >= max_ports) {
            return -1;
        }
        count = append_port(ports, max_ports, count, port);
    }

    return count;
}

static int parse_ports(const char *spec, int *ports, int max_ports) {
    int i = 0;
    int count = 0;
    int port = 0;

    if (spec == NULL || spec[0] == '\0' || ports == NULL || max_ports <= 0) {
        return 0;
    }

    if (str_equals(spec, "top20")) {
        count = (int)(sizeof(TOP20_PORTS) / sizeof(TOP20_PORTS[0]));
        if (count > max_ports) {
            return -1;
        }
        copy_bytes(ports, TOP20_PORTS, sizeof(TOP20_PORTS));
        return count;
    }

    if (str_equals(spec, "top100")) {
        count = (int)(sizeof(TOP100_PORTS) / sizeof(TOP100_PORTS[0]));
        if (count > max_ports) {
            return -1;
        }
        copy_bytes(ports, TOP100_PORTS, sizeof(TOP100_PORTS));
        return count;
    }

    while (spec[i] != '\0') {
        if (spec[i] == '-') {
            return parse_port_range(spec, ports, max_ports);
        }
        if (spec[i] == ',' || spec[i] == ' ') {
            return parse_port_list(spec, ports, max_ports);
        }
        i++;
    }

    if (parse_uint_max(spec, 65535, &port) && port >= 1) {
        return append_port(ports, max_ports, 0, port);
    }

    return 0;
}

static int resolve_target_ipv4(const char *host, unsigned long *addr_out) {
    unsigned long numeric_addr;
    HOSTENT *resolved = NULL;

    if (host == NULL || host[0] == '\0' || addr_out == NULL) {
        return 0;
    }

    numeric_addr = WS2_32$inet_addr(host);
    if (numeric_addr != INADDR_NONE) {
        *addr_out = numeric_addr;
        return 1;
    }

    resolved = WS2_32$gethostbyname(host);
    if (resolved == NULL || resolved->h_addrtype != AF_INET || resolved->h_length != 4 || resolved->h_addr_list == NULL || resolved->h_addr_list[0] == NULL) {
        return 0;
    }

    copy_bytes(addr_out, resolved->h_addr_list[0], 4);
    return 1;
}

static int socket_is_set(SOCKET sock, FD_SET_LOCAL *set) {
    if (set == NULL || set->fd_count == 0) {
        return 0;
    }
    return (set->fd_array[0] == sock);
}

static int tcp_connect_scan(unsigned long target_addr, int port, int timeout_ms) {
    SOCKET sock = INVALID_SOCKET;
    SOCKADDR_IN addr;
    FD_SET_LOCAL writefds;
    TIMEVAL timeout;
    unsigned long mode = 1;
    int connect_result = 0;
    int error = 0;
    int select_result = 0;
    int socket_error = 0;
    int socket_error_len = sizeof(socket_error);
    int result = 0;

    zero_bytes(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons((unsigned short)port);
    addr.sin_addr.S_un.S_addr = target_addr;

    sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    if (WS2_32$ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR) {
        WS2_32$closesocket(sock);
        return -1;
    }

    connect_result = WS2_32$connect(sock, (const struct sockaddr *)&addr, sizeof(addr));
    error = WS2_32$WSAGetLastError();
    if (connect_result == 0) {
        result = 1;
    } else if (error == WSAEWOULDBLOCK) {
        FD_ZERO_ONE(&writefds);
        FD_SET_ONE(sock, &writefds);
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        select_result = WS2_32$select(0, NULL, &writefds, NULL, &timeout);
        if (select_result > 0 && socket_is_set(sock, &writefds)) {
            if (WS2_32$getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&socket_error, &socket_error_len) == 0 && socket_error == 0) {
                result = 1;
            }
        }
    }

    WS2_32$closesocket(sock);
    return result;
}

static int udp_probe(unsigned long target_addr, int port, int timeout_ms) {
    SOCKET sock = INVALID_SOCKET;
    SOCKADDR_IN addr;
    FD_SET_LOCAL readfds;
    TIMEVAL timeout;
    char buffer[1];
    int send_result = 0;
    int select_result = 0;
    int result = 0;

    zero_bytes(&addr, sizeof(addr));
    zero_bytes(buffer, sizeof(buffer));
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons((unsigned short)port);
    addr.sin_addr.S_un.S_addr = target_addr;

    sock = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    send_result = WS2_32$sendto(sock, buffer, 0, 0, (const struct sockaddr *)&addr, sizeof(addr));
    if (send_result == SOCKET_ERROR) {
        WS2_32$closesocket(sock);
        return -1;
    }

    FD_ZERO_ONE(&readfds);
    FD_SET_ONE(sock, &readfds);
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    select_result = WS2_32$select(0, &readfds, NULL, NULL, &timeout);
    if (select_result > 0 && socket_is_set(sock, &readfds)) {
        result = 1;
    }

    WS2_32$closesocket(sock);
    return result;
}

static void print_usage(void) {
    BeaconPrintf(CALLBACK_ERROR, "[-] Usage: port_scan <target> [top20|top100|port|port-list|start-end] [protocol: 0=tcp 1=udp 2=both] [timeout_ms]");
}

void go(char *args, unsigned long alen) {
    datap parser = {0};
    WSADATA wsa;
    char *target = NULL;
    char *port_spec = NULL;
    short protocol = 0;
    int timeout_ms = DEFAULT_TIMEOUT_MS;
    int *ports = NULL;
    int port_count = 0;
    int i = 0;
    int tcp_open = 0;
    int tcp_closed = 0;
    int tcp_errors = 0;
    int udp_responsive = 0;
    int udp_no_response = 0;
    int udp_errors = 0;
    int printed_open = 0;
    int total_checks = 0;
    unsigned long target_addr = 0;
    const char *proto_label = "tcp";

    if (alen == 0) {
        print_usage();
        return;
    }

    BeaconDataParse(&parser, args, (int)alen);
    target = BeaconDataExtract(&parser, NULL);
    if (BeaconDataLength(&parser) > 0) {
        port_spec = BeaconDataExtract(&parser, NULL);
    }
    if (BeaconDataLength(&parser) >= (int)sizeof(short)) {
        protocol = BeaconDataShort(&parser);
    }
    if (BeaconDataLength(&parser) >= (int)sizeof(int)) {
        timeout_ms = BeaconDataInt(&parser);
    }

    if (target == NULL || target[0] == '\0') {
        print_usage();
        return;
    }
    if (port_spec == NULL || port_spec[0] == '\0') {
        port_spec = "top20";
    }
    if (protocol < 0 || protocol > 2) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid protocol: use 0=tcp, 1=udp, or 2=both");
        return;
    }
    if (timeout_ms <= 0 || timeout_ms > MAX_TIMEOUT_MS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid timeout requested; using %d ms", DEFAULT_TIMEOUT_MS);
        timeout_ms = DEFAULT_TIMEOUT_MS;
    }

    ports = (int *)KERNEL32$VirtualAlloc(NULL, MAX_PORTS * sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ports == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate port list");
        return;
    }

    port_count = parse_ports(port_spec, ports, MAX_PORTS);
    if (port_count < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Port specification exceeds cap of %d ports", MAX_PORTS);
        KERNEL32$VirtualFree(ports, 0, MEM_RELEASE);
        return;
    }
    if (port_count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid port specification: %s", port_spec);
        KERNEL32$VirtualFree(ports, 0, MEM_RELEASE);
        return;
    }

    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize Winsock");
        KERNEL32$VirtualFree(ports, 0, MEM_RELEASE);
        return;
    }

    if (!resolve_target_ipv4(target, &target_addr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target resolution failed: %s", target);
        WS2_32$WSACleanup();
        KERNEL32$VirtualFree(ports, 0, MEM_RELEASE);
        return;
    }

    if (protocol == 1) {
        proto_label = "udp";
    } else if (protocol == 2) {
        proto_label = "tcp+udp";
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Port scan target=%s protocol=%s timeout_ms=%d ports=%d", target, proto_label, timeout_ms, port_count);
    if (port_count > 200 || protocol == 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Large scans can trigger firewall, EDR, or IDS alerts; prefer targeted port lists when possible");
    }
    if (protocol == 1 || protocol == 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] UDP results only confirm responsive services; no-response can mean open, filtered, or closed");
    }

    for (i = 0; i < port_count; i++) {
        int port = ports[i];
        int result = 0;

        if (protocol == 0 || protocol == 2) {
            result = tcp_connect_scan(target_addr, port, timeout_ms);
            total_checks++;
            if (result == 1) {
                tcp_open++;
                if (printed_open < MAX_OPEN_OUTPUT) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] tcp/%d open", port);
                    printed_open++;
                }
            } else if (result == 0) {
                tcp_closed++;
            } else {
                tcp_errors++;
            }
        }

        if (protocol == 1 || protocol == 2) {
            result = udp_probe(target_addr, port, timeout_ms);
            total_checks++;
            if (result == 1) {
                udp_responsive++;
                if (printed_open < MAX_OPEN_OUTPUT) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] udp/%d responsive", port);
                    printed_open++;
                }
            } else if (result == 0) {
                udp_no_response++;
            } else {
                udp_errors++;
            }
        }
    }

    if ((tcp_open + udp_responsive) > printed_open) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Output truncated: displayed %d of %d open/responsive results", printed_open, tcp_open + udp_responsive);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[i] Summary target=%s checks=%d tcp_open=%d tcp_closed=%d tcp_errors=%d udp_responsive=%d udp_no_response=%d udp_errors=%d",
                 target, total_checks, tcp_open, tcp_closed, tcp_errors, udp_responsive, udp_no_response, udp_errors);

    WS2_32$WSACleanup();
    KERNEL32$VirtualFree(ports, 0, MEM_RELEASE);
}
