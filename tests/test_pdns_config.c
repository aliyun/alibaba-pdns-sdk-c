/*
 * 客户端配置测试 —— 创建校验 / 配置边界 / 生命周期 / NULL 防护
 *
 * 这些用例不调用（或不期望成功地调用）pdns_client_start：start 会拉取服务列表与
 * 黑白名单，需联网。例外：test_client_start_requires_public_dns 会调 start，但因未配鉴权
 * 会在入参校验处立即返回，不会发起任何网络请求，故仍属离线用例。
 */
#include "test_suite_list.h"

/* create 为无参创建：创建必须成功，鉴权参数通过 init 系列接口配置 */
void test_client_create_requires_account(CuTest *tc) {
    pdns_client_t *client = pdns_client_create();
    CuAssertPtrNotNullMsg(tc, "parameterless create must succeed", client);
    pdns_client_cleanup(client);
}

/*
 * 鉴权三参数均为必填，缺任意一个都必须失败。
 * （鉴权不全时 Provider 直接不启用，根本不发请求），此用例守护该行为。
 */
void test_client_init_public_dns_requires_all_auth(CuTest *tc) {
    pdns_client_t *client = pdns_client_create();
    CuAssertPtrNotNull(tc, client);

    pdns_status_t st;

    st = pdns_client_init_public_dns(client, NULL, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET);
    CuAssert(tc, "NULL account_id must fail", !pdns_status_is_ok(&st));

    st = pdns_client_init_public_dns(client, "", PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET);
    CuAssert(tc, "empty account_id must fail", !pdns_status_is_ok(&st));

    st = pdns_client_init_public_dns(client, PDNS_TEST_ACCOUNT, NULL, PDNS_TEST_AK_SECRET);
    CuAssert(tc, "NULL access_key_id must fail", !pdns_status_is_ok(&st));

    st = pdns_client_init_public_dns(client, PDNS_TEST_ACCOUNT, "", PDNS_TEST_AK_SECRET);
    CuAssert(tc, "empty access_key_id must fail", !pdns_status_is_ok(&st));

    st = pdns_client_init_public_dns(client, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, NULL);
    CuAssert(tc, "NULL access_key_secret must fail", !pdns_status_is_ok(&st));

    st = pdns_client_init_public_dns(client, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, "");
    CuAssert(tc, "empty access_key_secret must fail", !pdns_status_is_ok(&st));

    /* NULL client 也不得崩溃 */
    st = pdns_client_init_public_dns(NULL, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET);
    CuAssert(tc, "NULL client must fail", !pdns_status_is_ok(&st));

    /* 三参数完整时必须成功，且可重复调用（更新鉴权） */
    st = pdns_client_init_public_dns(client, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET);
    CuAssert(tc, "complete auth must succeed", pdns_status_is_ok(&st));
    st = pdns_client_init_public_dns(client, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET);
    CuAssert(tc, "repeated init should be allowed", pdns_status_is_ok(&st));

    pdns_client_cleanup(client);
}

/* 未配置公共 DNS 鉴权时，start 必须拒绝启动（把配置错误提前暴露） */
void test_client_start_requires_public_dns(CuTest *tc) {
    pdns_client_t *client = pdns_client_create();
    CuAssertPtrNotNull(tc, client);

    pdns_status_t st = pdns_client_start(client);
    CuAssert(tc, "start without public dns must fail", !pdns_status_is_ok(&st));

    pdns_client_cleanup(client);
}

/* 完整鉴权参数创建并释放 */
void test_client_create_and_cleanup(CuTest *tc) {
    pdns_client_t *client = pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_cleanup(client);
}

/* 多个 client 实例可并存且各自独立释放 */
void test_client_multiple_instances(CuTest *tc) {
    pdns_client_t *c1 = pdns_test_client_create();
    pdns_client_t *c2 = pdns_test_client_create();

    CuAssertPtrNotNull(tc, c1);
    CuAssertPtrNotNull(tc, c2);
    CuAssert(tc, "instances must be distinct", c1 != c2);

    /* sessionId 每个实例独立生成 */
    const char *s1 = pdns_client_get_session_id(c1);
    const char *s2 = pdns_client_get_session_id(c2);
    CuAssertPtrNotNull(tc, s1);
    CuAssertPtrNotNull(tc, s2);
    CuAssert(tc, "session ids should differ between clients", strcmp(s1, s2) != 0);

    pdns_client_cleanup(c1);
    pdns_client_cleanup(c2);
}

/* sessionId：12 位字母数字，且在实例生命周期内保持不变 */
void test_client_session_id_stable(CuTest *tc) {
    pdns_client_t *client =
        pdns_test_client_create();

    const char *first = pdns_client_get_session_id(client);
    CuAssertPtrNotNull(tc, first);
    CuAssertIntEquals_Msg(tc, "session id should be 12 chars", 12, (int) strlen(first));

    /* 多次获取应为同一内容 */
    const char *again = pdns_client_get_session_id(client);
    CuAssertStrEquals_Msg(tc, "session id must not change during lifetime", first, again);

    CuAssertPtrEquals_Msg(tc, "NULL client should return NULL session id", NULL,
                          (void *) pdns_client_get_session_id(NULL));

    pdns_client_cleanup(client);
}

/* 所有配置项在 start 之前批量设置都不应崩溃（含越界值，内部会夹紧） */
void test_client_setters_accept_boundary_values(CuTest *tc) {
    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);

    /* 超时：负数 / 0 / 正常 / 极大 */
    pdns_client_set_timeout(client, -1);
    pdns_client_set_timeout(client, 0);
    pdns_client_set_timeout(client, 3000);
    pdns_client_set_timeout(client, 1000000);

    /* TTL 相关：min_ttl 上限 300，越界应被夹紧而非崩溃 */
    pdns_client_set_min_ttl_cache(client, -10);
    pdns_client_set_min_ttl_cache(client, 0);
    pdns_client_set_min_ttl_cache(client, 300);
    pdns_client_set_min_ttl_cache(client, 99999);
    pdns_client_set_max_ttl_cache(client, -1);
    pdns_client_set_max_ttl_cache(client, 3600);
    pdns_client_set_max_negative_cache(client, -1);
    pdns_client_set_max_negative_cache(client, 30);

    /* 缓存容量：负数按 0 处理，0 表示清空且禁写 */
    pdns_client_set_max_cache_size(client, -5);
    pdns_client_set_max_cache_size(client, 0);
    pdns_client_set_max_cache_size(client, 100);

    /* 并发数：范围 [1,50]，越界夹紧 */
    pdns_client_set_max_concurrent_resolve_count(client, 0);
    pdns_client_set_max_concurrent_resolve_count(client, -1);
    pdns_client_set_max_concurrent_resolve_count(client, 1);
    pdns_client_set_max_concurrent_resolve_count(client, 50);
    pdns_client_set_max_concurrent_resolve_count(client, 999);

    /* IPv6 测速让分：范围 [0,1000] */
    pdns_client_set_speed_test_ipv6_prefer_ms(client, -100);
    pdns_client_set_speed_test_ipv6_prefer_ms(client, 0);
    pdns_client_set_speed_test_ipv6_prefer_ms(client, 1000);
    pdns_client_set_speed_test_ipv6_prefer_ms(client, 5000);

    /* 测速端口 */
    pdns_client_set_speed_port(client, 80);
    pdns_client_set_speed_port(client, 443);
    pdns_client_set_speed_port(client, 0);

    /* bool 开关 */
    pdns_client_set_enable_cache(client, true);
    pdns_client_set_enable_cache(client, false);
    pdns_client_set_enable_speed_test(client, true);
    pdns_client_set_enable_localdns(client, false);
    pdns_client_set_enable_ipv6(client, true);
    pdns_client_set_enable_immutable_cache(client, true);
    pdns_client_set_enable_immutable_cache(client, false);
    pdns_client_set_enable_short(client, true);
    pdns_client_set_enable_short(client, false);

    /* 协议枚举 */
    pdns_client_set_schema_type(client, PDNS_SCHEMA_HTTP);
    pdns_client_set_schema_type(client, PDNS_SCHEMA_HTTPS);

    /* ECS：设置与清除 */
    pdns_client_set_edns_client_subnet(client, "1.2.3.0/24");
    pdns_client_set_edns_client_subnet(client, "");
    pdns_client_set_edns_client_subnet(client, NULL);

    pdns_client_cleanup(client);
    CuAssert(tc, "boundary configuration should not crash", true);
}

/* 所有 setter 对 NULL client 都必须安全返回 */
void test_client_setters_null_safety(CuTest *tc) {
    pdns_client_set_timeout(NULL, 1000);
    pdns_client_set_enable_cache(NULL, true);
    pdns_client_set_schema_type(NULL, PDNS_SCHEMA_HTTPS);
    pdns_client_set_enable_speed_test(NULL, true);
    pdns_client_set_speed_port(NULL, 80);
    pdns_client_set_speed_test_ipv6_prefer_ms(NULL, 10);
    pdns_client_set_enable_localdns(NULL, true);
    pdns_client_set_enable_ipv6(NULL, true);
    pdns_client_set_enable_immutable_cache(NULL, true);
    pdns_client_set_edns_client_subnet(NULL, "1.2.3.0/24");
    pdns_client_set_max_ttl_cache(NULL, 100);
    pdns_client_set_min_ttl_cache(NULL, 10);
    pdns_client_set_max_negative_cache(NULL, 10);
    pdns_client_set_max_cache_size(NULL, 10);
    pdns_client_set_max_concurrent_resolve_count(NULL, 10);
    pdns_client_set_enable_short(NULL, true);
    pdns_client_cleanup(NULL);

    /* 全局开关（进程级，不依赖 client） */
    pdns_set_enable_network_change(false);
    pdns_set_enable_network_change(true);

    CuAssert(tc, "NULL client setters should not crash", true);
}

/* 解析接口对非法入参应返回错误而非崩溃（不触网） */
void test_resolve_invalid_args(CuTest *tc) {
    pdns_result_list_t *results = NULL;
    pdns_status_t     st;

    st = pdns_resolve_sync(NULL, PDNS_TEST_HOST, PDNS_QUERY_IPV4, &results);
    CuAssert(tc, "NULL client should fail", st.code != PDNS_OK);

    pdns_client_t *client =
        pdns_test_client_create();

    st = pdns_resolve_sync(client, NULL, PDNS_QUERY_IPV4, &results);
    CuAssert(tc, "NULL host should fail", st.code != PDNS_OK);

    st = pdns_resolve_sync(client, "", PDNS_QUERY_IPV4, &results);
    CuAssert(tc, "empty host should fail", st.code != PDNS_OK);

    st = pdns_resolve_sync(client, PDNS_TEST_HOST, PDNS_QUERY_IPV4, NULL);
    CuAssert(tc, "NULL out param should fail", st.code != PDNS_OK);

    /* 缓存查询接口同样应校验入参（未命中时返回空，不触网） */
    results = NULL;
    st      = pdns_resolve_sync_from_cache(client, NULL, PDNS_QUERY_IPV4, false, &results);
    CuAssert(tc, "cache query with NULL host should fail", st.code != PDNS_OK);

    pdns_client_cleanup(client);
}

/* status 辅助函数语义 */
void test_status_is_ok(CuTest *tc) {
    pdns_status_t ok = {0};
    ok.code         = PDNS_OK;
    CuAssert(tc, "code 0 means ok", pdns_status_is_ok(&ok));

    pdns_status_t err = {0};
    err.code         = -1;
    CuAssert(tc, "non-zero code means failure", !pdns_status_is_ok(&err));

    CuAssert(tc, "NULL status is not ok", !pdns_status_is_ok(NULL));
}

void add_pdns_config_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_client_create_requires_account);
    SUITE_ADD_TEST(suite, test_client_init_public_dns_requires_all_auth);
    SUITE_ADD_TEST(suite, test_client_start_requires_public_dns);
    SUITE_ADD_TEST(suite, test_client_create_and_cleanup);
    SUITE_ADD_TEST(suite, test_client_multiple_instances);
    SUITE_ADD_TEST(suite, test_client_session_id_stable);
    SUITE_ADD_TEST(suite, test_client_setters_accept_boundary_values);
    SUITE_ADD_TEST(suite, test_client_setters_null_safety);
    SUITE_ADD_TEST(suite, test_resolve_invalid_args);
    SUITE_ADD_TEST(suite, test_status_is_ok);
}
