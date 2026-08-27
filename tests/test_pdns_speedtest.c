/*
 * IP 测速测试 —— TCP connect RTT 测量
 *
 * 成功路径用本机临时监听端口验证（不依赖外网）；
 * 失败路径用「本机未监听端口」触发立即 refused，避免等满 3 秒超时。
 */
#include "test_suite_list.h"
#include "pdns_speedtest.h"
#include "pdns_cache.h"   /* PDNS_RTT_TIMEOUT */

#include <apr_network_io.h>
#include <apr_pools.h>

/* 在 127.0.0.1 上建立一个监听 socket，返回实际端口；失败返回 0 */
static apr_port_t start_listener(apr_pool_t *pool, apr_socket_t **out_sock) {
    apr_socket_t   *sock = NULL;
    apr_sockaddr_t *sa   = NULL;

    if (apr_sockaddr_info_get(&sa, "127.0.0.1", APR_INET, 0, 0, pool) != APR_SUCCESS) {
        return 0;
    }
    if (apr_socket_create(&sock, sa->family, SOCK_STREAM, APR_PROTO_TCP, pool) != APR_SUCCESS) {
        return 0;
    }
    apr_socket_opt_set(sock, APR_SO_REUSEADDR, 1);
    if (apr_socket_bind(sock, sa) != APR_SUCCESS || apr_socket_listen(sock, 8) != APR_SUCCESS) {
        apr_socket_close(sock);
        return 0;
    }
    /* 取内核分配的实际端口 */
    apr_sockaddr_t *bound = NULL;
    if (apr_socket_addr_get(&bound, APR_LOCAL, sock) != APR_SUCCESS) {
        apr_socket_close(sock);
        return 0;
    }
    *out_sock = sock;
    return bound->port;
}

/* 可连通端口：应返回真实 RTT，且必然小于 3000ms 超时线 */
void test_speedtest_reachable_port(CuTest *tc) {
    apr_pool_t   *pool = NULL;
    apr_socket_t *sock = NULL;

    CuAssertIntEquals(tc, APR_SUCCESS, apr_pool_create(&pool, NULL));
    apr_port_t port = start_listener(pool, &sock);
    if (port == 0) {
        apr_pool_destroy(pool);
        CuFail(tc, "failed to start local listener");
        return;
    }

    float rtt = pdns_speedtest_tcp("127.0.0.1", (int) port);
    CuAssert(tc, "reachable port should not time out", rtt < 3000.0f);
    CuAssert(tc, "rtt should be non-negative", rtt >= 0.0f);
    CuAssert(tc, "reachable rtt must differ from timeout sentinel", rtt != PDNS_RTT_TIMEOUT);

    apr_socket_close(sock);
    apr_pool_destroy(pool);
}

/* 未监听端口：连接被拒绝，应快速返回超时哨兵 9999 */
void test_speedtest_refused_port(CuTest *tc) {
    apr_pool_t   *pool = NULL;
    apr_socket_t *sock = NULL;

    CuAssertIntEquals(tc, APR_SUCCESS, apr_pool_create(&pool, NULL));
    apr_port_t port = start_listener(pool, &sock);
    if (port == 0) {
        apr_pool_destroy(pool);
        CuFail(tc, "failed to start local listener");
        return;
    }
    /* 关掉监听，使该端口变为「无人监听」，connect 会立即 refused */
    apr_socket_close(sock);

    float rtt = pdns_speedtest_tcp("127.0.0.1", (int) port);
    CuAssertDblEquals_Msg(tc, "refused connection should return timeout sentinel",
                          PDNS_RTT_TIMEOUT, rtt, 0.01);
    apr_pool_destroy(pool);
}

/* 非法 IP 字符串：不得崩溃，返回超时哨兵 */
void test_speedtest_invalid_ip(CuTest *tc) {
    CuAssertDblEquals_Msg(tc, "invalid ip should return sentinel", PDNS_RTT_TIMEOUT,
                          pdns_speedtest_tcp("not-an-ip", 80), 0.01);
    CuAssertDblEquals_Msg(tc, "empty ip should return sentinel", PDNS_RTT_TIMEOUT,
                          pdns_speedtest_tcp("", 80), 0.01);
    CuAssertDblEquals_Msg(tc, "NULL ip should return sentinel", PDNS_RTT_TIMEOUT,
                          pdns_speedtest_tcp(NULL, 80), 0.01);
}

/* 非法端口：不得崩溃，返回超时哨兵 */
void test_speedtest_invalid_port(CuTest *tc) {
    CuAssertDblEquals_Msg(tc, "port 0 should return sentinel", PDNS_RTT_TIMEOUT,
                          pdns_speedtest_tcp("127.0.0.1", 0), 0.01);
    CuAssertDblEquals_Msg(tc, "negative port should return sentinel", PDNS_RTT_TIMEOUT,
                          pdns_speedtest_tcp("127.0.0.1", -1), 0.01);
    /* 超范围端口会被 htons 截断到合法区间，结果取决于本机是否恰好监听该端口，
     * 故只要求返回值合法、不崩溃，不断言具体值。 */
    float rtt = pdns_speedtest_tcp("127.0.0.1", 70000);
    CuAssert(tc, "out-of-range port must still return a sane value",
             rtt >= 0.0f && rtt <= PDNS_RTT_TIMEOUT);
}

/* RTT 哨兵值区间约定：成功 < 3000 < 未测速 5000 < 超时 9999，三区间互斥 */
void test_speedtest_sentinel_ranges(CuTest *tc) {
    CuAssertDblEquals(tc, 5000.0, PDNS_RTT_DEFAULT, 0.01);
    CuAssertDblEquals(tc, 9999.0, PDNS_RTT_TIMEOUT, 0.01);
    CuAssert(tc, "untested sentinel must exceed connect timeout", PDNS_RTT_DEFAULT > 3000.0f);
    CuAssert(tc, "timeout sentinel must exceed untested sentinel",
             PDNS_RTT_TIMEOUT > PDNS_RTT_DEFAULT);
}

void add_pdns_speedtest_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_speedtest_reachable_port);
    SUITE_ADD_TEST(suite, test_speedtest_refused_port);
    SUITE_ADD_TEST(suite, test_speedtest_invalid_ip);
    SUITE_ADD_TEST(suite, test_speedtest_invalid_port);
    SUITE_ADD_TEST(suite, test_speedtest_sentinel_ranges);
}
