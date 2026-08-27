/*
 * 网络栈探测原语实现 —— UDP 探测(+DNS 回退) + 本机 IP 收集
 */
#include "pdns_netstack.h"
#include "pdns_log.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#define pdns_close_socket(fd) closesocket(fd)
typedef SOCKET pdns_socket_t;
#define PDNS_INVALID_SOCK INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#define pdns_close_socket(fd) close(fd)
typedef int pdns_socket_t;
#define PDNS_INVALID_SOCK (-1)
#endif

/* 探测参数：IPv4 8.8.8.8 / IPv6 2000::，端口 0xFFFF，DNS 回退域名 */
#define PDNS_TEST_PORT      0xFFFF
#define PDNS_IPV4_PROBE     "8.8.8.8"
#define PDNS_IPV6_PROBE     "2000::"
#define PDNS_PROBE_DOMAIN   "dns.alidns.com"

/* ---------------- UDP 探测 ---------------- */

/* 创建 UDP socket 并 connect（UDP connect 仅设置目的地址，不产生实际报文），成功返回 true */
static bool can_connect(int family, const struct sockaddr *addr, socklen_t addr_len) {
    pdns_socket_t fd = socket(family, SOCK_DGRAM, 0);
    if (fd == PDNS_INVALID_SOCK) {
        return false;
    }
    int rc;
    do {
        rc = connect(fd, addr, addr_len);
#if defined(_WIN32)
    } while (rc < 0 && WSAGetLastError() == WSAEINTR);
#else
    } while (rc < 0 && errno == EINTR);
#endif
    pdns_close_socket(fd);
    return rc == 0;
}

/* 单一 UDP 探测原语：按地址族构造目的地址（探测端口统一 PDNS_TEST_PORT），
 * 地址转换失败或 connect 失败返回 false。v4/v6 共用此入口，避免重复样板。 */
static bool udp_probe(int family, const char *addr_text) {
    struct sockaddr_storage ss;
    socklen_t               addr_len;
    memset(&ss, 0, sizeof(ss));

    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *) &ss;
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(PDNS_TEST_PORT);
        if (inet_pton(AF_INET, addr_text, &v4->sin_addr) <= 0) {
            return false;
        }
        addr_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) &ss;
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(PDNS_TEST_PORT);
        if (inet_pton(AF_INET6, addr_text, &v6->sin6_addr) <= 0) {
            return false;
        }
        addr_len = sizeof(struct sockaddr_in6);
    }
    return can_connect(family, (struct sockaddr *) &ss, addr_len);
}

static pdns_netstack_type_t detect_by_udp(void) {
    int stack = PDNS_STACK_NONE;
    if (udp_probe(AF_INET, PDNS_IPV4_PROBE)) {
        PDNS_LOGD("[网络栈] UDP 探测到 IPv4");
        stack |= PDNS_STACK_IPV4_ONLY;
    }
    if (udp_probe(AF_INET6, PDNS_IPV6_PROBE)) {
        PDNS_LOGD("[网络栈] UDP 探测到 IPv6");
        stack |= PDNS_STACK_IPV6_ONLY;
    }
    return (pdns_netstack_type_t) stack;
}

/* 网络栈类型语义名（日志可读） */
const char *pdns_netstack_name(pdns_netstack_type_t stack) {
    switch (stack) {
        case PDNS_STACK_IPV4_ONLY: return "IPv4_ONLY";
        case PDNS_STACK_IPV6_ONLY: return "IPv6_ONLY";
        case PDNS_STACK_DUAL:      return "DUAL";
        case PDNS_STACK_NONE:
        default:                   return "NONE";
    }
}

/* ---------------- DNS 回退探测 ---------------- */

static pdns_netstack_type_t detect_by_dns(const char *domain) {
    struct addrinfo hint;
    struct addrinfo *answer = NULL, *cur = NULL;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family   = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(domain, NULL, &hint, &answer) != 0 || answer == NULL) {
        return PDNS_STACK_NONE;
    }
    int stack = PDNS_STACK_NONE;
    for (cur = answer; cur != NULL; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET) {
            PDNS_LOGD("[网络栈] DNS 探测到 IPv4");
            stack |= PDNS_STACK_IPV4_ONLY;
        } else if (cur->ai_family == AF_INET6) {
            PDNS_LOGD("[网络栈] DNS 探测到 IPv6");
            stack |= PDNS_STACK_IPV6_ONLY;
        }
    }
    freeaddrinfo(answer);
    return (pdns_netstack_type_t) stack;
}

pdns_netstack_type_t pdns_netstack_detect(void) {
    pdns_netstack_type_t stack = detect_by_udp();
    if (stack != PDNS_STACK_NONE) {
        PDNS_LOGI("[网络栈] UDP 探测结果: type=%d (%s)", stack, pdns_netstack_name(stack));
        return stack;
    }
    /* UDP 探测无结果，回退 DNS 探测 */
    stack = detect_by_dns(PDNS_PROBE_DOMAIN);
    if (stack != PDNS_STACK_NONE) {
        PDNS_LOGI("[网络栈] DNS 探测结果: type=%d (%s)", stack, pdns_netstack_name(stack));
        return stack;
    }
    PDNS_LOGW("[网络栈] 无可用网络栈 (NONE)");
    return stack;
}

/* ---------------- 本机 IP 收集 ---------------- */

#if defined(_WIN32)

int pdns_netstack_collect_local_ips(pdns_list_impl_t *out) {
    if (out == NULL) {
        return 1;
    }
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size  = 15000;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *) malloc(size);
    if (addrs == NULL) {
        return 1;
    }
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addrs, &size) != ERROR_SUCCESS) {
        free(addrs);
        return 1;
    }
    for (IP_ADAPTER_ADDRESSES *a = addrs; a != NULL; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }
        for (IP_ADAPTER_UNICAST_ADDRESS *ua = a->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
            char ip[INET6_ADDRSTRLEN] = {0};
            if (getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength,
                            ip, sizeof(ip), NULL, 0, NI_NUMERICHOST) == 0) {
                pdns_list_impl_add(out, ip);
            }
        }
    }
    free(addrs);
    return 0;
}

#else

int pdns_netstack_collect_local_ips(pdns_list_impl_t *out) {
    if (out == NULL) {
        return 1;
    }
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        return 1;
    }
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        /* 跳过回环与未启用的接口 */
        if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }
        int  family = ifa->ifa_addr->sa_family;
        char ip[INET6_ADDRSTRLEN] = {0};
        if (family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
        } else if (family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *) ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip));
        } else {
            continue;
        }
        pdns_list_impl_add(out, ip);
    }
    freeifaddrs(ifaddr);
    return 0;
}

#endif
