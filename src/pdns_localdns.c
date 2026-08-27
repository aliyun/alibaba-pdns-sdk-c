/*
 * LocalDNS 降级模块实现 —— getaddrinfo 跨平台封装
 */
#include "pdns_localdns.h"
#include "pdns_log.h"
#include "pdns_idn.h"

#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

/* query_type 映射到 getaddrinfo 的 ai_family */
static int query_type_family(pdns_query_type_t t) {
    switch (t) {
        case PDNS_QUERY_IPV4:
            return AF_INET;
        case PDNS_QUERY_IPV6:
            return AF_INET6;
        default:      /* AUTO / BOTH：不限族，返回系统给出的全部 */
            return AF_UNSPEC;
    }
}

int pdns_localdns_resolve(const char *host,
                          pdns_query_type_t query_type,
                          pdns_result_list_t *out_ips) {
    if (host == NULL || out_ips == NULL) {
        return 1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = query_type_family(query_type);
    hints.ai_socktype = SOCK_STREAM;

    /* 中文域名转 punycode（用时转）：getaddrinfo 需 ASCII 域名；
     * 转换失败尽力而为，回退原始 host 继续。 */
    char ascii_host[256];
    if (!pdns_idn_to_ascii(host, ascii_host, sizeof(ascii_host))) {
        PDNS_LOGW("localdns idn convert failed, use original host: %s", host);
    }

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(ascii_host, NULL, &hints, &res);
    if (rc != 0 || res == NULL) {
        PDNS_LOGW("localdns resolve failed: host=%s rc=%d", host, rc);
        return 1;
    }

    int found = 0;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        char ip[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *) ai->ai_addr;
            if (inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)) == NULL) {
                continue;
            }
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *) ai->ai_addr;
            if (inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip)) == NULL) {
                continue;
            }
        } else {
            continue;
        }
        pdns_result_list_add(out_ips, ip);
        found++;
    }

    freeaddrinfo(res);

    if (found > 0) {
        PDNS_LOGI("localdns resolve ok: host=%s count=%d", host, found);
        return PDNS_OK;
    }
    return 1;
}
