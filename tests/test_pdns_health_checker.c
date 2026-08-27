/*
 * 熔断与健康检查测试 —— 覆盖连续失败计数与健康探测恢复状态机
 *
 * 覆盖状态机的四个关键面：
 *   1. 触发：连续失败达 PDNS_MIN_CONSECUTIVE_FAILURES 才熔断，中途成功即重新计数
 *   2. 影响：熔断节点从选点与 hasActiveServers 中消失（这是熔断的全部意义）
 *   3. 恢复：探测成功达 PDNS_MIN_CONSECUTIVE_SUCCESS 即回到调度池，且 srtt 归零
 *   4. 前置条件：仅自建参与、health_check_domain 为空即整体关闭
 *
 * 探测请求本身需要联网，本文件只测状态机与前置条件短路（不发网络请求）。
 */
#include "test_suite_list.h"
#include "pdns_server_manager.h"
#include "pdns_health_checker.h"
#include "pdns_base_provider.h"
#include "pdns_public_provider.h"

#define CB_HC_DOMAIN "hc.example.com"
#define CB_DOMAIN    "www.example.com"
#define CB_TYPE      "1"
#define CB_RID       "rid-cb-1"

static const char *g_cb_v4[] = {"10.0.0.1", "10.0.0.2"};

/* 建一个「仅自建」的 manager：熔断只对自建生效，单 provider 便于隔离验证 */
static pdns_server_manager_t *make_fusion_manager(const char *hc_domain) {
    pdns_server_manager_t *m = pdns_server_manager_create();
    if (m == NULL) {
        return NULL;
    }
    if (pdns_server_manager_init_fusion_dns(m, g_cb_v4, 2, NULL, 0, NULL, 0, 8443,
                                                hc_domain, PDNS_TEST_ACCOUNT,
                                                PDNS_TEST_AK_ID,
                                                PDNS_TEST_AK_SECRET) != 0) {
        pdns_server_manager_destroy(m);
        return NULL;
    }
    return m;
}

/* 连打 n 次失败 */
static void fail_times(pdns_server_manager_t *m, const char *node, int n) {
    pdns_server_provider_t *prov =
        pdns_fusion_provider_as_provider(pdns_server_manager_fusion(m));
    for (int i = 0; i < n; i++) {
        pdns_server_manager_update_consecutive_failure(m, prov, node);
    }
}

/* 取自建基类 */
static pdns_base_provider_t *fusion_base(pdns_server_manager_t *m) {
    return pdns_fusion_provider_as_base(pdns_server_manager_fusion(m));
}

/* 阈值前不熔断，达到阈值才熔断（即 MIN_CONSECUTIVE_FAILURES=3） */
void test_cb_trigger_at_threshold(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t *base = fusion_base(m);

    CuAssert(tc, "no broken node initially",
             !pdns_base_provider_has_broken_nodes(base));

    /* 阈值 -1 次：仍未熔断 */
    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES - 1);
    CuAssert(tc, "below threshold should not break",
             !pdns_base_provider_has_broken_nodes(base));

    /* 再补 1 次达到阈值：熔断 */
    fail_times(m, "10.0.0.1", 1);
    CuAssert(tc, "reaching threshold should break",
             pdns_base_provider_has_broken_nodes(base));

    pdns_server_manager_destroy(m);
}

/* 中途成功会打断失败链，重新累计 */
void test_cb_success_resets_failure_chain(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t   *base = fusion_base(m);
    pdns_server_provider_t *prov =
        pdns_fusion_provider_as_provider(pdns_server_manager_fusion(m));

    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES - 1);
    /* 一次成功清零失败计数 */
    pdns_server_manager_update_consecutive_success(m, prov, "10.0.0.1");
    /* 再失败「阈值-1」次也不该熔断（若成功没清零，这里就会熔断） */
    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES - 1);
    CuAssert(tc, "success must reset the failure chain",
             !pdns_base_provider_has_broken_nodes(base));

    pdns_server_manager_destroy(m);
}

/* 熔断节点必须从选点结果中消失——这是熔断的全部意义 */
void test_cb_broken_node_not_selected(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_server_provider_t *prov =
        pdns_fusion_provider_as_provider(pdns_server_manager_fusion(m));

    /* 未熔断时 rc=0 能选到某个节点 */
    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertPtrNotNull(tc, res.node_ip);

    /* 熔断两个 v4 节点后，IPv4 栈下再也选不出节点（本 provider 未配 host 节点） */
    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES);
    fail_times(m, "10.0.0.2", PDNS_MIN_CONSECUTIVE_FAILURES);

    CuAssert(tc, "all nodes broken -> no active servers",
             !pdns_provider_has_active_servers(prov, PDNS_STACK_IPV4_ONLY, false));
    memset(&res, 0, sizeof(res));
    CuAssert(tc, "all nodes broken -> select must fail",
             pdns_provider_get_server_url_with_request_count(
                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res) != 0);

    pdns_server_manager_destroy(m);
}

/* 只熔断其中一个节点时，选点应自动落到另一个存活节点 */
void test_cb_select_falls_to_alive_node(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_server_provider_t *prov =
        pdns_fusion_provider_as_provider(pdns_server_manager_fusion(m));

    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES);

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals_Msg(tc, "must skip the broken node", "10.0.0.2", res.node_ip);
    CuAssert(tc, "one node alive -> still has active servers",
             pdns_provider_has_active_servers(prov, PDNS_STACK_IPV4_ONLY, false));

    pdns_server_manager_destroy(m);
}

/* 已熔断节点应被 collect_broken_nodes 收集，供健康检查探测 */
void test_cb_collect_broken_nodes(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t *base = fusion_base(m);

    char broken[PDNS_HEALTH_CHECK_MAX_NODES][PDNS_IP_ADDRESS_STRING_LENGTH];
    CuAssertIntEquals_Msg(tc, "nothing to probe when all alive", 0,
                          pdns_base_provider_collect_broken_nodes(
                              base, PDNS_STACK_IPV4_ONLY, broken,
                              PDNS_HEALTH_CHECK_MAX_NODES));

    fail_times(m, "10.0.0.2", PDNS_MIN_CONSECUTIVE_FAILURES);
    int n = pdns_base_provider_collect_broken_nodes(
        base, PDNS_STACK_IPV4_ONLY, broken, PDNS_HEALTH_CHECK_MAX_NODES);
    CuAssertIntEquals(tc, 1, n);
    CuAssertStrEquals(tc, "10.0.0.2", broken[0]);

    pdns_server_manager_destroy(m);
}

/* IPv6_ONLY 栈下不探 v4 节点 */
void test_cb_collect_respects_stack(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t *base = fusion_base(m);

    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES);

    char broken[PDNS_HEALTH_CHECK_MAX_NODES][PDNS_IP_ADDRESS_STRING_LENGTH];
    CuAssertIntEquals_Msg(tc, "v4 node must not be probed on ipv6-only stack", 0,
                          pdns_base_provider_collect_broken_nodes(
                              base, PDNS_STACK_IPV6_ONLY, broken,
                              PDNS_HEALTH_CHECK_MAX_NODES));
    CuAssertIntEquals_Msg(tc, "but it is probed on ipv4-only stack", 1,
                          pdns_base_provider_collect_broken_nodes(
                              base, PDNS_STACK_IPV4_ONLY, broken,
                              PDNS_HEALTH_CHECK_MAX_NODES));

    pdns_server_manager_destroy(m);
}

/* 探测成功达阈值即恢复，并重新参与选点 */
void test_cb_recover_on_probe_success(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t   *base = fusion_base(m);
    pdns_server_provider_t *prov =
        pdns_fusion_provider_as_provider(pdns_server_manager_fusion(m));

    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES);
    fail_times(m, "10.0.0.2", PDNS_MIN_CONSECUTIVE_FAILURES);
    CuAssert(tc, "both broken", !pdns_provider_has_active_servers(
                                    prov, PDNS_STACK_IPV4_ONLY, false));

    /* 探测失败不恢复 */
    CuAssert(tc, "failed probe must not recover",
             !pdns_base_provider_record_probe_result(base, "10.0.0.1", false));
    CuAssert(tc, "still broken after failed probe",
             !pdns_provider_has_active_servers(prov, PDNS_STACK_IPV4_ONLY, false));

    /* 探测成功即恢复（阈值为 1） */
    CuAssert(tc, "successful probe should recover",
             pdns_base_provider_record_probe_result(base, "10.0.0.1", true));
    CuAssert(tc, "recovered node makes provider active again",
             pdns_provider_has_active_servers(prov, PDNS_STACK_IPV4_ONLY, false));

    /* 恢复后应能被选中（srtt 归零 → 优先选中以验证） */
    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals_Msg(tc, "recovered node should be picked first",
                          "10.0.0.1", res.node_ip);

    pdns_server_manager_destroy(m);
}

/* 恢复后失败计数须清零：否则一次失败就会立刻再次熔断 */
void test_cb_recover_resets_counters(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t *base = fusion_base(m);

    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES);
    CuAssert(tc, "recovered", pdns_base_provider_record_probe_result(
                                  base, "10.0.0.1", true));

    /* 恢复后再失败「阈值-1」次不应熔断（计数已清零） */
    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES - 1);
    CuAssert(tc, "counters must be cleared on recover",
             !pdns_base_provider_has_broken_nodes(base));

    pdns_server_manager_destroy(m);
}

/* 前置条件：health_check_domain 为空即整体关闭熔断（否则摘除后无法探测恢复） */
void test_cb_disabled_without_health_check_domain(CuTest *tc) {
    /* 自建 init 强制要求 health_check_domain 非空，故此处退化为「未配自建」，
     * 用公共 DNS 验证同一条前置：非自建节点永不熔断。 */
    pdns_server_manager_t *m = pdns_server_manager_create();
    CuAssertPtrNotNull(tc, m);
    CuAssertIntEquals(tc, 0, pdns_server_manager_init_public_dns(
                                 m, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID,
                                 PDNS_TEST_AK_SECRET));

    pdns_server_provider_t *pub =
        pdns_public_provider_as_provider(pdns_server_manager_public(m));
    pdns_base_provider_t *pub_base =
        pdns_public_provider_as_base(pdns_server_manager_public(m));

    /* 对公共 DNS 节点连续失败远超阈值也不该熔断 */
    for (int i = 0; i < PDNS_MIN_CONSECUTIVE_FAILURES * 3; i++) {
        pdns_server_manager_update_consecutive_failure(m, pub, "223.5.5.5");
    }
    CuAssert(tc, "public dns node must never be circuit-broken",
             !pdns_base_provider_has_broken_nodes(pub_base));
    CuAssert(tc, "public dns still active",
             pdns_provider_has_active_servers(pub, PDNS_STACK_IPV4_ONLY, false));

    pdns_server_manager_destroy(m);
}

/* 无熔断节点 / 未配自建时，健康检查不发请求且返回 0（前置条件短路） */
void test_cb_health_check_short_circuits(CuTest *tc) {
    /* 未配置任何 provider */
    pdns_server_manager_t *empty = pdns_server_manager_create();
    CuAssertPtrNotNull(tc, empty);
    CuAssertIntEquals_Msg(tc, "no fusion provider -> no probe", 0,
                          pdns_server_manager_run_health_check(
                              empty, PDNS_STACK_IPV4_ONLY, NULL, 1000, true));
    pdns_server_manager_destroy(empty);

    /* 配了自建但无熔断节点 */
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    CuAssertIntEquals_Msg(tc, "no broken node -> no probe", 0,
                          pdns_server_manager_run_health_check(
                              m, PDNS_STACK_IPV4_ONLY, NULL, 1000, true));
    pdns_server_manager_destroy(m);

    /* NULL 防护 */
    CuAssertIntEquals(tc, 0, pdns_server_manager_run_health_check(
                                 NULL, PDNS_STACK_IPV4_ONLY, NULL, 1000, true));
    CuAssert(tc, "probe with NULL provider is safe",
             !pdns_health_check_probe_node(NULL, "1.2.3.4", PDNS_QUERY_IPV4,
                                          NULL, 1000, true));
}

/* 网络切换重置 SRTT 时一并解除熔断（主动增强行为，见实现注释） */
void test_cb_reset_srtt_clears_break(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t *base = fusion_base(m);

    fail_times(m, "10.0.0.1", PDNS_MIN_CONSECUTIVE_FAILURES);
    CuAssert(tc, "broken before switch",
             pdns_base_provider_has_broken_nodes(base));

    pdns_server_manager_reset_srtt(m);
    CuAssert(tc, "network switch should clear circuit break",
             !pdns_base_provider_has_broken_nodes(base));

    pdns_server_manager_destroy(m);
}

/* NULL 与未知节点的防护：不得崩溃，也不得误伤其他节点 */
void test_cb_null_and_unknown_node_safety(CuTest *tc) {
    pdns_server_manager_t *m = make_fusion_manager(CB_HC_DOMAIN);
    CuAssertPtrNotNull(tc, m);
    pdns_base_provider_t   *base = fusion_base(m);
    pdns_server_provider_t *prov =
        pdns_fusion_provider_as_provider(pdns_server_manager_fusion(m));

    /* node_ip 为 NULL（HOST 兜底场景）：直接返回，不影响任何节点 */
    pdns_server_manager_update_consecutive_failure(m, prov, NULL);
    pdns_server_manager_update_consecutive_success(m, prov, NULL);
    /* 不在节点池中的地址：找不到即忽略 */
    fail_times(m, "192.0.2.99", PDNS_MIN_CONSECUTIVE_FAILURES);
    CuAssert(tc, "unknown node must not break anything",
             !pdns_base_provider_has_broken_nodes(base));

    CuAssert(tc, "record failure on NULL base is safe",
             !pdns_base_provider_record_node_failure(NULL, "10.0.0.1"));
    CuAssert(tc, "probe result on NULL base is safe",
             !pdns_base_provider_record_probe_result(NULL, "10.0.0.1", true));
    CuAssert(tc, "has_broken_nodes on NULL base is safe",
             !pdns_base_provider_has_broken_nodes(NULL));

    pdns_server_manager_destroy(m);
}

void add_pdns_health_checker_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_cb_trigger_at_threshold);
    SUITE_ADD_TEST(suite, test_cb_success_resets_failure_chain);
    SUITE_ADD_TEST(suite, test_cb_broken_node_not_selected);
    SUITE_ADD_TEST(suite, test_cb_select_falls_to_alive_node);
    SUITE_ADD_TEST(suite, test_cb_collect_broken_nodes);
    SUITE_ADD_TEST(suite, test_cb_collect_respects_stack);
    SUITE_ADD_TEST(suite, test_cb_recover_on_probe_success);
    SUITE_ADD_TEST(suite, test_cb_recover_resets_counters);
    SUITE_ADD_TEST(suite, test_cb_disabled_without_health_check_domain);
    SUITE_ADD_TEST(suite, test_cb_health_check_short_circuits);
    SUITE_ADD_TEST(suite, test_cb_reset_srtt_clears_break);
    SUITE_ADD_TEST(suite, test_cb_null_and_unknown_node_safety);
}
