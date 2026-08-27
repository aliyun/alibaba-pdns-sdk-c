/*
 * provider 主备调度测试 —— 4 种配置组合 / 主备顺序 / 降级阈值 / 总重试上限 / 降级切换
 *
 * 调度规则：先配者为主用，threshold 随主用类型取默认值，
 * 单次解析内主用累计失败达阈值后切备用，且备用的 request_count 扣掉已消耗的阈值。
 */
#include "test_suite_list.h"
#include "pdns_server_manager.h"

#define MG_HC_DOMAIN "hc.example.com"
#define MG_DOMAIN    "www.taobao.com"
#define MG_TYPE      "1"
#define MG_RID       "rid-mgr-1"

static const char *mg_v4[] = {"10.0.0.1", "10.0.0.2"};

static int init_public(pdns_server_manager_t *m) {
    return pdns_server_manager_init_public_dns(m, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID,
                                                   PDNS_TEST_AK_SECRET);
}

static int init_fusion(pdns_server_manager_t *m) {
    return pdns_server_manager_init_fusion_dns(m, mg_v4, 2, NULL, 0, NULL, 0, 8443,
                                                   MG_HC_DOMAIN, PDNS_TEST_ACCOUNT,
                                                   PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET);
}

/* 取一次选点结果的 source（provider 名），失败返回 NULL */
static const char *pick_source(pdns_server_manager_t *m, int request_count) {
    static pdns_server_url_result_t res;
    pdns_server_provider_t *prov = NULL;
    memset(&res, 0, sizeof(res));
    if (pdns_server_manager_get_server_url_with_request_count(
            m, request_count, MG_DOMAIN, MG_TYPE, MG_RID, PDNS_STACK_IPV4_ONLY,
            false, true, &res, &prov) != 0) {
        return NULL;
    }
    return pdns_source_name(res.source);
}

/* 未配置任何 provider：组为空、重试上限 0、选点失败 */
void test_manager_empty_group(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertPtrNotNull(tc, m);

    CuAssertIntEquals(tc, 0, pdns_server_manager_provider_count(m));
    CuAssertIntEquals(tc, PDNS_FIRST_CONFIGURED_NONE,
                      pdns_server_manager_first_configured_type(m));
    CuAssertIntEquals_Msg(tc, "no provider -> zero retry budget", 0,
                          pdns_server_manager_max_total_retry_count(m, PDNS_STACK_IPV4_ONLY,
                                                                        false));
    CuAssertPtrEquals(tc, NULL, (void *) pick_source(m, 0));

    pdns_server_manager_destroy(m);
}

/* 组合 1：仅公共 */
void test_manager_public_only(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_public(m));

    CuAssertIntEquals(tc, 1, pdns_server_manager_provider_count(m));
    CuAssertIntEquals(tc, PDNS_FIRST_CONFIGURED_PUBLIC,
                      pdns_server_manager_first_configured_type(m));
    CuAssertPtrEquals(tc, NULL, (void *) pdns_server_manager_backup(m));
    CuAssertIntEquals_Msg(tc, "single public -> PUBLICRETRYCOUNT", PDNS_PUBLIC_RETRY_COUNT,
                          pdns_server_manager_max_total_retry_count(m, PDNS_STACK_IPV4_ONLY,
                                                                        false));
    CuAssertStrEquals(tc, "PublicDNS", pick_source(m, 0));

    pdns_server_manager_destroy(m);
}

/* 组合 2：仅自建 */
void test_manager_fusion_only(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_fusion(m));

    CuAssertIntEquals(tc, 1, pdns_server_manager_provider_count(m));
    CuAssertIntEquals(tc, PDNS_FIRST_CONFIGURED_FUSION,
                      pdns_server_manager_first_configured_type(m));
    CuAssertIntEquals_Msg(tc, "single fusion -> FUSIONRETRYCOUNT", PDNS_FUSION_RETRY_COUNT,
                          pdns_server_manager_max_total_retry_count(m, PDNS_STACK_IPV4_ONLY,
                                                                        false));
    CuAssertStrEquals(tc, "FusionDNS", pick_source(m, 0));

    pdns_server_manager_destroy(m);
}

/* 组合 3：先 public 再 fusion → 公共主用，阈值 4 */
void test_manager_public_primary(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_public(m));
    CuAssertIntEquals(tc, 0, init_fusion(m));

    CuAssertIntEquals(tc, 2, pdns_server_manager_provider_count(m));
    CuAssertStrEquals_Msg(tc, "first configured provider is primary", "PublicDNS",
                          pdns_provider_name(pdns_server_manager_primary(m)));
    CuAssertStrEquals(tc, "FusionDNS",
                      pdns_provider_name(pdns_server_manager_backup(m)));
    CuAssertIntEquals(tc, PDNS_FALLBACK_THRESHOLD_PUBLIC_PRIMARY,
                      pdns_server_manager_get_fallback_threshold(m));
    CuAssertIntEquals_Msg(tc, "threshold + backup retry",
                          PDNS_FALLBACK_THRESHOLD_PUBLIC_PRIMARY + PDNS_FUSION_RETRY_COUNT,
                          pdns_server_manager_max_total_retry_count(m, PDNS_STACK_IPV4_ONLY,
                                                                        false));

    pdns_server_manager_destroy(m);
}

/* 组合 4：先 fusion 再 public → 自建主用，阈值 2 */
void test_manager_fusion_primary(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_fusion(m));
    CuAssertIntEquals(tc, 0, init_public(m));

    CuAssertIntEquals(tc, 2, pdns_server_manager_provider_count(m));
    CuAssertStrEquals_Msg(tc, "first configured provider is primary", "FusionDNS",
                          pdns_provider_name(pdns_server_manager_primary(m)));
    CuAssertStrEquals(tc, "PublicDNS",
                      pdns_provider_name(pdns_server_manager_backup(m)));
    CuAssertIntEquals(tc, PDNS_FALLBACK_THRESHOLD_FUSION_PRIMARY,
                      pdns_server_manager_get_fallback_threshold(m));
    CuAssertIntEquals(tc,
                      PDNS_FALLBACK_THRESHOLD_FUSION_PRIMARY + PDNS_PUBLIC_RETRY_COUNT,
                      pdns_server_manager_max_total_retry_count(m, PDNS_STACK_IPV4_ONLY,
                                                                    false));

    pdns_server_manager_destroy(m);
}

/* 重复 init 不改变首配类型（主备顺序一旦确定就不翻转） */
void test_manager_first_configured_type_sticky(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_public(m));
    CuAssertIntEquals(tc, 0, init_fusion(m));
    /* 再配一次 public：仍应是 public 主用 */
    CuAssertIntEquals(tc, 0, init_public(m));

    CuAssertIntEquals(tc, PDNS_FIRST_CONFIGURED_PUBLIC,
                      pdns_server_manager_first_configured_type(m));
    CuAssertStrEquals(tc, "PublicDNS",
                      pdns_provider_name(pdns_server_manager_primary(m)));

    pdns_server_manager_destroy(m);
}

/* 阈值 setter 钳制到 [0,4] */
void test_manager_threshold_clamp(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();

    pdns_server_manager_set_fallback_threshold(m, -5);
    CuAssertIntEquals(tc, 0, pdns_server_manager_get_fallback_threshold(m));

    pdns_server_manager_set_fallback_threshold(m, 99);
    CuAssertIntEquals(tc, PDNS_FALLBACK_THRESHOLD_MAX,
                      pdns_server_manager_get_fallback_threshold(m));

    pdns_server_manager_set_fallback_threshold(m, 2);
    CuAssertIntEquals(tc, 2, pdns_server_manager_get_fallback_threshold(m));

    pdns_server_manager_destroy(m);
}

/* 降级：主用累计失败达阈值后切备用；成功后计数清零即回到主用 */
void test_manager_fallback_after_threshold_failures(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_public(m));
    CuAssertIntEquals(tc, 0, init_fusion(m));
    /* 阈值收到 2，缩短用例：失败 2 次即应降级 */
    pdns_server_manager_set_fallback_threshold(m, 2);

    CuAssertStrEquals_Msg(tc, "no failure -> primary", "PublicDNS", pick_source(m, 0));

    pdns_server_manager_on_request_failure(m, MG_DOMAIN, MG_TYPE, MG_RID);
    CuAssertStrEquals_Msg(tc, "1 failure < 2 -> still primary", "PublicDNS", pick_source(m, 1));

    pdns_server_manager_on_request_failure(m, MG_DOMAIN, MG_TYPE, MG_RID);
    CuAssertStrEquals_Msg(tc, "2 failures >= 2 -> backup", "FusionDNS", pick_source(m, 2));

    /* 成功清零后回到主用 */
    pdns_server_manager_on_request_success(m, MG_DOMAIN, MG_TYPE, MG_RID);
    CuAssertStrEquals_Msg(tc, "success resets counter -> primary again", "PublicDNS",
                          pick_source(m, 3));

    pdns_server_manager_destroy(m);
}

/* 降级时 request_count 扣掉阈值：备用从自己的第 0 次开始，不会跳过优选节点 */
void test_manager_fallback_request_count_offset(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_public(m));
    CuAssertIntEquals(tc, 0, init_fusion(m));
    pdns_server_manager_set_fallback_threshold(m, 2);

    pdns_server_manager_on_request_failure(m, MG_DOMAIN, MG_TYPE, MG_RID);
    pdns_server_manager_on_request_failure(m, MG_DOMAIN, MG_TYPE, MG_RID);

    /* request_count=2 → 备用换算为 0：应拿到自建首个节点，而非 HOST 兜底
     * （自建未配域名节点，若未扣减则 rc=2 仍是 IP、rc>=3 会失败） */
    pdns_server_url_result_t res;
    pdns_server_provider_t *prov = NULL;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_server_manager_get_server_url_with_request_count(
                                 m, 2, MG_DOMAIN, MG_TYPE, MG_RID, PDNS_STACK_IPV4_ONLY,
                                 false, true, &res, &prov));
    CuAssertStrEquals(tc, "FusionDNS", pdns_source_name(res.source));
    CuAssertStrEquals_Msg(tc, "backup should start from its own first node",
                          "https://10.0.0.1:8443", res.base_url);

    /* request_count=4 → 备用换算为 2，仍是 IP 节点（自建 2 个节点，走第二个） */
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_server_manager_get_server_url_with_request_count(
                                 m, 4, MG_DOMAIN, MG_TYPE, MG_RID, PDNS_STACK_IPV4_ONLY,
                                 false, true, &res, &prov));
    CuAssertStrEquals(tc, "FusionDNS", pdns_source_name(res.source));

    /* request_count = 阈值 + PDNS_RETRY_COUNT → 备用换算到 HOST 兜底；
     * 本自建无域名节点，基类会回退到 IP 节点，因此仍能选到自建。 */
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_server_manager_get_server_url_with_request_count(
                                 m, 2 + PDNS_RETRY_COUNT, MG_DOMAIN, MG_TYPE, MG_RID,
                                 PDNS_STACK_IPV4_ONLY, false, true, &res, &prov));
    CuAssertStrEquals_Msg(tc, "host fallback without domain node falls back to ip",
                          "FusionDNS", pdns_source_name(res.source));

    pdns_server_manager_destroy(m);
}

/* threshold=0：不给主用机会，首次即用备用 */
void test_manager_zero_threshold_uses_backup(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_public(m));
    CuAssertIntEquals(tc, 0, init_fusion(m));
    pdns_server_manager_set_fallback_threshold(m, 0);

    CuAssertStrEquals_Msg(tc, "threshold 0 -> backup from the very first try", "FusionDNS",
                          pick_source(m, 0));
    CuAssertIntEquals_Msg(tc, "threshold 0 -> total budget is backup only",
                          PDNS_FUSION_RETRY_COUNT,
                          pdns_server_manager_max_total_retry_count(m, PDNS_STACK_IPV4_ONLY,
                                                                        false));

    pdns_server_manager_destroy(m);
}

/* 主用在当前网络栈下无可调度节点：直接用备用且不扣 request_count */
void test_manager_primary_without_active_servers(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    /* 自建只配 IPv4 节点 → 在 IPV6_ONLY 栈下无可用节点 */
    CuAssertIntEquals(tc, 0, init_fusion(m));
    CuAssertIntEquals(tc, 0, init_public(m));

    CuAssert(tc, "fusion has no ipv6 node",
             !pdns_provider_has_active_servers(pdns_server_manager_primary(m),
                                               PDNS_STACK_IPV6_ONLY, true));
    CuAssertIntEquals_Msg(tc, "primary inactive -> budget is backup only",
                          PDNS_PUBLIC_RETRY_COUNT,
                          pdns_server_manager_max_total_retry_count(m, PDNS_STACK_IPV6_ONLY,
                                                                        true));

    pdns_server_url_result_t res;
    pdns_server_provider_t *prov = NULL;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_server_manager_get_server_url_with_request_count(
                                 m, 0, MG_DOMAIN, MG_TYPE, MG_RID, PDNS_STACK_IPV6_ONLY,
                                 true, true, &res, &prov));
    CuAssertStrEquals_Msg(tc, "should go straight to the backup", "PublicDNS", pdns_source_name(res.source));

    pdns_server_manager_destroy(m);
}

/* 网络切换重置 SRTT：两个 provider 都要清 */
void test_manager_reset_srtt_covers_both(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertIntEquals(tc, 0, init_public(m));
    CuAssertIntEquals(tc, 0, init_fusion(m));

    pdns_base_provider_t *pub_base =
        pdns_public_provider_as_base(pdns_server_manager_public(m));
    pdns_base_provider_t *fus_base =
        pdns_fusion_provider_as_base(pdns_server_manager_fusion(m));

    bool is_host = false;
    pdns_base_provider_update_srtt(pub_base, "223.5.5.5", 500);
    pdns_base_provider_update_srtt(fus_base, "10.0.0.1", 500);
    /* 已测量的首节点让位给未测量的次节点 */
    CuAssertStrEquals(tc, "223.6.6.6",
                      pdns_base_provider_get_server_ip_with_request_count(
                          pub_base, PDNS_STACK_IPV4_ONLY, false, 0, &is_host));
    CuAssertStrEquals(tc, "10.0.0.2",
                      pdns_base_provider_get_server_ip_with_request_count(
                          fus_base, PDNS_STACK_IPV4_ONLY, false, 0, &is_host));

    pdns_server_manager_reset_srtt(m);
    CuAssertStrEquals_Msg(tc, "public srtt should be reset", "223.5.5.5",
                          pdns_base_provider_get_server_ip_with_request_count(
                              pub_base, PDNS_STACK_IPV4_ONLY, false, 0, &is_host));
    CuAssertStrEquals_Msg(tc, "fusion srtt should be reset", "10.0.0.1",
                          pdns_base_provider_get_server_ip_with_request_count(
                              fus_base, PDNS_STACK_IPV4_ONLY, false, 0, &is_host));

    pdns_server_manager_destroy(m);
}

/* init 参数非法：不进入 provider group */
void test_manager_invalid_init_not_grouped(CuTest *tc) {
    pdns_server_manager_t *m = pdns_server_manager_create();

    CuAssert(tc, "public init with empty secret should fail",
             pdns_server_manager_init_public_dns(m, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID,
                                                     "") != 0);
    CuAssert(tc, "fusion init without address should fail",
             pdns_server_manager_init_fusion_dns(m, NULL, 0, NULL, 0, NULL, 0, 443,
                                                     MG_HC_DOMAIN, PDNS_TEST_ACCOUNT,
                                                     PDNS_TEST_AK_ID,
                                                     PDNS_TEST_AK_SECRET) != 0);
    CuAssertIntEquals_Msg(tc, "failed init must not join the group", 0,
                          pdns_server_manager_provider_count(m));
    CuAssertIntEquals(tc, PDNS_FIRST_CONFIGURED_NONE,
                      pdns_server_manager_first_configured_type(m));

    pdns_server_manager_destroy(m);
}

/* NULL 防护 */
void test_manager_null_safety(CuTest *tc) {
    CuAssertIntEquals(tc, 0, pdns_server_manager_provider_count(NULL));
    CuAssertIntEquals(tc, 0, pdns_server_manager_get_fallback_threshold(NULL));
    CuAssertIntEquals(tc, 0,
                      pdns_server_manager_max_total_retry_count(NULL, PDNS_STACK_DUAL,
                                                                    false));
    CuAssertPtrEquals(tc, NULL, (void *) pdns_server_manager_primary(NULL));
    CuAssertPtrEquals(tc, NULL, (void *) pdns_server_manager_backup(NULL));
    CuAssertPtrEquals(tc, NULL, (void *) pdns_server_manager_public(NULL));
    CuAssertPtrEquals(tc, NULL, (void *) pdns_server_manager_fusion(NULL));
    CuAssert(tc, "NULL manager init public fails",
             pdns_server_manager_init_public_dns(NULL, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID,
                                                     PDNS_TEST_AK_SECRET) != 0);
    pdns_server_manager_set_fallback_threshold(NULL, 3);
    pdns_server_manager_on_request_failure(NULL, MG_DOMAIN, MG_TYPE, MG_RID);
    pdns_server_manager_on_request_success(NULL, MG_DOMAIN, MG_TYPE, MG_RID);
    pdns_server_manager_on_request_finish(NULL, MG_DOMAIN, MG_TYPE, MG_RID);
    pdns_server_manager_cleanup_expired(NULL);
    pdns_server_manager_reset_srtt(NULL);
    pdns_server_manager_destroy(NULL);
}

void add_pdns_server_manager_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_manager_empty_group);
    SUITE_ADD_TEST(suite, test_manager_public_only);
    SUITE_ADD_TEST(suite, test_manager_fusion_only);
    SUITE_ADD_TEST(suite, test_manager_public_primary);
    SUITE_ADD_TEST(suite, test_manager_fusion_primary);
    SUITE_ADD_TEST(suite, test_manager_first_configured_type_sticky);
    SUITE_ADD_TEST(suite, test_manager_threshold_clamp);
    SUITE_ADD_TEST(suite, test_manager_fallback_after_threshold_failures);
    SUITE_ADD_TEST(suite, test_manager_fallback_request_count_offset);
    SUITE_ADD_TEST(suite, test_manager_zero_threshold_uses_backup);
    SUITE_ADD_TEST(suite, test_manager_primary_without_active_servers);
    SUITE_ADD_TEST(suite, test_manager_reset_srtt_covers_both);
    SUITE_ADD_TEST(suite, test_manager_invalid_init_not_grouped);
    SUITE_ADD_TEST(suite, test_manager_null_safety);
}
