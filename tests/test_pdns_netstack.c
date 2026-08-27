/*
 * 网络栈探测测试 —— 栈类型判定 + 本机 IP 收集
 *
 * 探测结果依赖运行环境（是否有 IPv4/IPv6 出口），故不断言具体栈类型，
 * 只校验取值合法、语义名正确、多次探测稳定、本机 IP 可收集。
 */
#include "test_suite_list.h"
#include "pdns_netstack.h"
#include "pdns_list.h"

static bool is_valid_stack(pdns_netstack_type_t s) {
    return s == PDNS_STACK_NONE || s == PDNS_STACK_IPV4_ONLY ||
           s == PDNS_STACK_IPV6_ONLY || s == PDNS_STACK_DUAL;
}

/* 探测结果必须落在枚举取值范围内 */
void test_netstack_detect_returns_valid_type(CuTest *tc) {
    pdns_netstack_type_t s = pdns_netstack_detect();
    CuAssert(tc, "detect result must be a valid stack type", is_valid_stack(s));
}

/* 枚举值必须满足位掩码约定（DUAL = V4|V6） */
void test_netstack_enum_values(CuTest *tc) {
    CuAssertIntEquals(tc, 0, PDNS_STACK_NONE);
    CuAssertIntEquals(tc, 1, PDNS_STACK_IPV4_ONLY);
    CuAssertIntEquals(tc, 2, PDNS_STACK_IPV6_ONLY);
    CuAssertIntEquals_Msg(tc, "DUAL must be bitwise OR of v4|v6", 3, PDNS_STACK_DUAL);
    CuAssertIntEquals(tc, PDNS_STACK_DUAL, PDNS_STACK_IPV4_ONLY | PDNS_STACK_IPV6_ONLY);
}

/* 语义名用于日志可读性，必须与枚举一一对应且非空 */
void test_netstack_name(CuTest *tc) {
    CuAssertStrEquals(tc, "IPv4_ONLY", pdns_netstack_name(PDNS_STACK_IPV4_ONLY));
    CuAssertStrEquals(tc, "IPv6_ONLY", pdns_netstack_name(PDNS_STACK_IPV6_ONLY));
    CuAssertStrEquals(tc, "DUAL", pdns_netstack_name(PDNS_STACK_DUAL));
    CuAssertStrEquals(tc, "NONE", pdns_netstack_name(PDNS_STACK_NONE));
    /* 越界值也必须返回可打印字符串而非 NULL */
    CuAssertPtrNotNull(tc, pdns_netstack_name((pdns_netstack_type_t) 99));
}

/* 短时间内连续探测结果应一致（网络未变化） */
void test_netstack_detect_is_stable(CuTest *tc) {
    pdns_netstack_type_t a = pdns_netstack_detect();
    pdns_netstack_type_t b = pdns_netstack_detect();
    CuAssertIntEquals_Msg(tc, "consecutive detections should agree", (int) a, (int) b);
}

/* 本机 IP 收集：应成功返回，且在有网卡的机器上至少收集到 1 个非回环地址 */
void test_netstack_collect_local_ips(CuTest *tc) {
    pdns_list_impl_t *ips = pdns_list_impl_create();

    int rc = pdns_netstack_collect_local_ips(ips);
    CuAssertIntEquals_Msg(tc, "collect local ips should succeed", 0, rc);

    size_t n = pdns_list_impl_size(ips);
    CuAssert(tc, "should collect at least one local ip", n > 0);

    /* 收集结果不应包含回环地址 */
    for (size_t i = 0; i < n; i++) {
        const char *ip = pdns_list_impl_get(ips, i);
        CuAssertPtrNotNull(tc, ip);
        CuAssert(tc, "loopback v4 must be excluded", strcmp(ip, "127.0.0.1") != 0);
        CuAssert(tc, "loopback v6 must be excluded", strcmp(ip, "::1") != 0);
    }
    pdns_list_impl_destroy(ips);
}

/* 同一时刻两次收集应得到相同的地址集合（用于「集合对比」式切换检测） */
void test_netstack_collect_is_repeatable(CuTest *tc) {
    pdns_list_impl_t *a = pdns_list_impl_create();
    pdns_list_impl_t *b = pdns_list_impl_create();

    pdns_netstack_collect_local_ips(a);
    pdns_netstack_collect_local_ips(b);

    CuAssertIntEquals_Msg(tc, "local ip count should be stable",
                          (int) pdns_list_impl_size(a), (int) pdns_list_impl_size(b));

    pdns_list_impl_destroy(a);
    pdns_list_impl_destroy(b);
}

/* NULL 入参不得崩溃 */
void test_netstack_collect_null_safety(CuTest *tc) {
    int rc = pdns_netstack_collect_local_ips(NULL);
    CuAssert(tc, "NULL out list should fail gracefully", rc != 0);
}

void add_pdns_netstack_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_netstack_detect_returns_valid_type);
    SUITE_ADD_TEST(suite, test_netstack_enum_values);
    SUITE_ADD_TEST(suite, test_netstack_name);
    SUITE_ADD_TEST(suite, test_netstack_detect_is_stable);
    SUITE_ADD_TEST(suite, test_netstack_collect_local_ips);
    SUITE_ADD_TEST(suite, test_netstack_collect_is_repeatable);
    SUITE_ADD_TEST(suite, test_netstack_collect_null_safety);
}
