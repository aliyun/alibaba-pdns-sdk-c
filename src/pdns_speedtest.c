/*
 * IP 测速模块实现 —— TCP 非阻塞 connect + select 计时（跨平台）
 */
#include "pdns_speedtest.h"
#include "pdns_cache.h"   /* PDNS_RTT_TIMEOUT */
#include "pdns_log.h"

#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET pdns_st_sock_t;
#define PDNS_ST_INVALID INVALID_SOCKET
#define pdns_st_close(fd) closesocket(fd)
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
typedef int pdns_st_sock_t;
#define PDNS_ST_INVALID (-1)
#define pdns_st_close(fd) close(fd)
#endif

#include <apr_time.h>

/* connect 超时（秒） */
#define PDNS_ST_CONNECT_TIMEOUT_SEC 3

/* 设置非阻塞 */
static bool set_nonblock(pdns_st_sock_t fd) {
#if defined(_WIN32)
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

/* connect 是否处于“进行中”（非阻塞下的正常返回） */
static bool connect_in_progress(void) {
#if defined(_WIN32)
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
#else
    return errno == EINPROGRESS;
#endif
}

float pdns_speedtest_tcp(const char *ip, int port) {
    if (ip == NULL || ip[0] == '\0' || port <= 0) {
        return PDNS_RTT_TIMEOUT;
    }

    /* 解析地址（纯数字 IP，按族构造，不做 DNS 查询） */
    struct sockaddr_storage ss;
    socklen_t               ss_len;
    int                     family;
    memset(&ss, 0, sizeof(ss));

    struct in6_addr a6;
    struct in_addr  a4;
    if (inet_pton(AF_INET, ip, &a4) == 1) {
        family = AF_INET;
        struct sockaddr_in *sa = (struct sockaddr_in *) &ss;
        sa->sin_family = AF_INET;
        sa->sin_port   = htons((unsigned short) port);
        sa->sin_addr   = a4;
        ss_len = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, ip, &a6) == 1) {
        family = AF_INET6;
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) &ss;
        sa->sin6_family = AF_INET6;
        sa->sin6_port   = htons((unsigned short) port);
        sa->sin6_addr   = a6;
        ss_len = sizeof(struct sockaddr_in6);
    } else {
        return PDNS_RTT_TIMEOUT;   /* 非法 IP 字面量 */
    }

    pdns_st_sock_t fd = socket(family, SOCK_STREAM, 0);
    if (fd == PDNS_ST_INVALID) {
        return PDNS_RTT_TIMEOUT;
    }
    if (!set_nonblock(fd)) {
        pdns_st_close(fd);
        return PDNS_RTT_TIMEOUT;
    }

    apr_time_t start      = apr_time_now();
    float      rtt        = PDNS_RTT_TIMEOUT;

    int rc = connect(fd, (struct sockaddr *) &ss, ss_len);
    if (rc == 0) {
        /* 极少见：本机/极近端立即完成 */
        rtt = (float) ((apr_time_now() - start) / 1000);
    } else if (connect_in_progress()) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        struct timeval tv;
        tv.tv_sec  = PDNS_ST_CONNECT_TIMEOUT_SEC;
        tv.tv_usec = 0;
        int n = select((int) (fd + 1), NULL, &wset, NULL, &tv);
        if (n > 0 && FD_ISSET(fd, &wset)) {
            /* 可写不代表成功，需查 SO_ERROR 判定 */
            int       soerr = 0;
            socklen_t len   = sizeof(soerr);
#if defined(_WIN32)
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &soerr, &len) == 0 && soerr == 0) {
#else
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0 && soerr == 0) {
#endif
                rtt = (float) ((apr_time_now() - start) / 1000);
            }
        }
        /* n==0 超时 / n<0 出错 / SO_ERROR!=0 → 保持 PDNS_RTT_TIMEOUT */
    }

    /* 握手成功后立即 close：无数据读写且未设 SO_LINGER，走正常挥手发 FIN */
    pdns_st_close(fd);

    return rtt;
}
