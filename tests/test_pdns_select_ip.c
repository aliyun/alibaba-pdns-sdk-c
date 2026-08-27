/*
 * IP 选择接口测试 —— 随机选择 / 取首个，按 query_type 过滤地址族
 *
 * 关键约束：IPV4 只选 IPv4，IPV6 只选 IPv6，BOTH/AUTO 不过滤；
 * 无同族 IP 时必须失败并把输出置为空串，避免调用方拿到脏数据去连接。
 */
#include "test_suite_list.h"
#include "pdns_list.h"

static pdns_result_list_t *make_list(const char *const *items, int n) {
    pdns_result_list_t *list = pdns_result_list_create();
    for (int i = 0; i < n; i++) {
        pdns_result_list_add(list, items[i]);
    }
    return list;
}

static bool is_v6(const char *ip) {
    return ip != NULL && strchr(ip, ':') != NULL;
}

static bool is_v4(const char *ip) {
    return ip != NULL && strchr(ip, '.') != NULL && strchr(ip, ':') == NULL;
}

/* 取首个：纯 v4 列表应返回第一个元素（测速排序后即最优 IP） */
void test_select_first_returns_head(CuTest *tc) {
    const char *const items[] = {"1.1.1.1", "2.2.2.2", "3.3.3.3"};
    pdns_result_list_t *list    = make_list(items, 3);
    char              ip[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};

    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_first(list, PDNS_QUERY_IPV4, ip));
    CuAssertStrEquals_Msg(tc, "should return the first ip", "1.1.1.1", ip);

    pdns_result_list_cleanup(list);
}

/* 取首个 + 族过滤：v4v6 混排列表中请求 IPv6 应跳过前面的 v4 */
void test_select_first_filters_family(CuTest *tc) {
    const char *const items[] = {"1.1.1.1", "2.2.2.2", "2400:3200::1"};
    pdns_result_list_t *list    = make_list(items, 3);
    char              ip[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};

    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_first(list, PDNS_QUERY_IPV6, ip));
    CuAssertStrEquals_Msg(tc, "should skip v4 and pick the first v6", "2400:3200::1", ip);

    memset(ip, 0, sizeof(ip));
    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_first(list, PDNS_QUERY_IPV4, ip));
    CuAssertStrEquals_Msg(tc, "should pick the first v4", "1.1.1.1", ip);

    pdns_result_list_cleanup(list);
}

/* BOTH / AUTO 不过滤：保持混排顺序，返回列表首个 */
void test_select_first_both_keeps_order(CuTest *tc) {
    const char *const items[] = {"2400:3200::1", "1.1.1.1"};
    pdns_result_list_t *list    = make_list(items, 2);
    char              ip[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};

    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_first(list, PDNS_QUERY_BOTH, ip));
    CuAssertStrEquals_Msg(tc, "BOTH should not filter", "2400:3200::1", ip);

    memset(ip, 0, sizeof(ip));
    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_first(list, PDNS_QUERY_AUTO, ip));
    CuAssertStrEquals_Msg(tc, "AUTO should not filter", "2400:3200::1", ip);

    pdns_result_list_cleanup(list);
}

/* 无同族 IP：必须失败且输出置空串 */
void test_select_no_matching_family(CuTest *tc) {
    const char *const items[] = {"1.1.1.1", "2.2.2.2"};
    pdns_result_list_t *list    = make_list(items, 2);
    char              ip[PDNS_IP_ADDRESS_STRING_LENGTH];

    memset(ip, 'X', sizeof(ip));
    CuAssert(tc, "no v6 available should fail",
             pdns_select_ip_first(list, PDNS_QUERY_IPV6, ip) != PDNS_OK);
    CuAssertStrEquals_Msg(tc, "output must be cleared on failure", "", ip);

    memset(ip, 'X', sizeof(ip));
    CuAssert(tc, "no v6 available should fail (random)",
             pdns_select_ip_randomly(list, PDNS_QUERY_IPV6, ip) != PDNS_OK);
    CuAssertStrEquals_Msg(tc, "output must be cleared on failure", "", ip);

    pdns_result_list_cleanup(list);
}

/* 空列表：失败且输出置空串 */
void test_select_empty_list(CuTest *tc) {
    pdns_result_list_t *list = pdns_result_list_create();
    char              ip[PDNS_IP_ADDRESS_STRING_LENGTH];

    memset(ip, 'X', sizeof(ip));
    CuAssert(tc, "empty list should fail", pdns_select_ip_first(list, PDNS_QUERY_IPV4, ip) != PDNS_OK);
    CuAssertStrEquals(tc, "", ip);

    memset(ip, 'X', sizeof(ip));
    CuAssert(tc, "empty list should fail (random)",
             pdns_select_ip_randomly(list, PDNS_QUERY_IPV4, ip) != PDNS_OK);
    CuAssertStrEquals(tc, "", ip);

    pdns_result_list_cleanup(list);
}

/* 随机选择：结果必须来自列表且符合族过滤 */
void test_select_random_within_list(CuTest *tc) {
    const char *const items[] = {"1.1.1.1", "2.2.2.2", "3.3.3.3", "2400:3200::1"};
    pdns_result_list_t *list    = make_list(items, 4);
    char              ip[PDNS_IP_ADDRESS_STRING_LENGTH];

    for (int i = 0; i < 50; i++) {
        memset(ip, 0, sizeof(ip));
        CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_randomly(list, PDNS_QUERY_IPV4, ip));
        CuAssert(tc, "random pick must be ipv4", is_v4(ip));

        bool found = false;
        for (int j = 0; j < 3; j++) {   /* 前 3 个是 v4 */
            if (strcmp(ip, items[j]) == 0) {
                found = true;
                break;
            }
        }
        CuAssert(tc, "random pick must come from the list", found);
    }

    for (int i = 0; i < 20; i++) {
        memset(ip, 0, sizeof(ip));
        CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_randomly(list, PDNS_QUERY_IPV6, ip));
        CuAssert(tc, "random pick must be ipv6", is_v6(ip));
        CuAssertStrEquals(tc, "2400:3200::1", ip);
    }

    pdns_result_list_cleanup(list);
}

/* 随机选择应具备真随机性：多个候选时不应恒定返回同一个 */
void test_select_random_distribution(CuTest *tc) {
    const char *const items[] = {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"};
    pdns_result_list_t *list    = make_list(items, 4);
    char              ip[PDNS_IP_ADDRESS_STRING_LENGTH];
    int               seen[4] = {0, 0, 0, 0};

    for (int i = 0; i < 200; i++) {
        memset(ip, 0, sizeof(ip));
        pdns_select_ip_randomly(list, PDNS_QUERY_IPV4, ip);
        for (int j = 0; j < 4; j++) {
            if (strcmp(ip, items[j]) == 0) {
                seen[j]++;
            }
        }
    }
    int distinct = 0;
    for (int j = 0; j < 4; j++) {
        if (seen[j] > 0) {
            distinct++;
        }
    }
    /* 200 次抽样、4 个候选，理应覆盖到全部；放宽到至少 2 个以避免极端偶发 */
    CuAssert(tc, "random selection should not always return the same ip", distinct >= 2);

    pdns_result_list_cleanup(list);
}

/* 单元素列表：随机与取首个结果一致 */
void test_select_single_element(CuTest *tc) {
    const char *const items[] = {"9.9.9.9"};
    pdns_result_list_t *list    = make_list(items, 1);
    char              a[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};
    char              b[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};

    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_first(list, PDNS_QUERY_IPV4, a));
    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_randomly(list, PDNS_QUERY_IPV4, b));
    CuAssertStrEquals(tc, "9.9.9.9", a);
    CuAssertStrEquals(tc, "9.9.9.9", b);

    pdns_result_list_cleanup(list);
}

/* NULL 防护 */
void test_select_null_safety(CuTest *tc) {
    char ip[PDNS_IP_ADDRESS_STRING_LENGTH];

    CuAssert(tc, "NULL list should fail", pdns_select_ip_first(NULL, PDNS_QUERY_IPV4, ip) != PDNS_OK);
    CuAssert(tc, "NULL list should fail (random)",
             pdns_select_ip_randomly(NULL, PDNS_QUERY_IPV4, ip) != PDNS_OK);

    const char *const items[] = {"1.1.1.1"};
    pdns_result_list_t *list    = make_list(items, 1);
    CuAssert(tc, "NULL out buffer should fail",
             pdns_select_ip_first(list, PDNS_QUERY_IPV4, NULL) != PDNS_OK);
    CuAssert(tc, "NULL out buffer should fail (random)",
             pdns_select_ip_randomly(list, PDNS_QUERY_IPV4, NULL) != PDNS_OK);
    pdns_result_list_cleanup(list);
}

void add_pdns_select_ip_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_select_first_returns_head);
    SUITE_ADD_TEST(suite, test_select_first_filters_family);
    SUITE_ADD_TEST(suite, test_select_first_both_keeps_order);
    SUITE_ADD_TEST(suite, test_select_no_matching_family);
    SUITE_ADD_TEST(suite, test_select_empty_list);
    SUITE_ADD_TEST(suite, test_select_random_within_list);
    SUITE_ADD_TEST(suite, test_select_random_distribution);
    SUITE_ADD_TEST(suite, test_select_single_element);
    SUITE_ADD_TEST(suite, test_select_null_safety);
}
