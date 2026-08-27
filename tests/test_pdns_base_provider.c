/*
 * 服务节点选型测试
 *
 * 被测对象为 pdns_base_provider 的节点池与选点/SRTT 逻辑。用例通过
 * pdns_public_provider 实例化（基类是抽象的，且这些行为运行在公共 DNS
 * 的默认 bootstrap 节点 223.5.5.5 / 223.6.6.6 上）。
 *
 * 关键行为：
 *   - srtt==0（未测量）的节点优先返回，保证每个节点都有探测机会；
 *   - 全部已测量时取 srtt 最小者；
 *   - request_count >= PDNS_RETRY_COUNT 时切 HOST 域名兜底，返回 NULL 且 is_host=true；
 *   - update_srtt 首次直接取 rtt，之后按 srtt*0.7 + rtt*0.3 平滑；
 *   - punish：目标节点 +200ms，其余节点 *0.98。
 */
#include "test_suite_list.h"
#include "pdns_public_provider.h"

#include <apr_time.h>

static bool is_ipv6_literal(const char *ip) {
    return ip != NULL && strchr(ip, ':') != NULL;
}

static bool is_ipv4_literal(const char *ip) {
    return ip != NULL && strchr(ip, '.') != NULL && strchr(ip, ':') == NULL;
}

/* 选点简写：pdns_base_provider_get_server_ip_with_request_count 的封装（丢弃 is_host 出参） */
static const char *best(pdns_public_provider_t *p, pdns_netstack_type_t stack,
                        bool enable_ipv6, int request_count) {
    bool is_host = false;
    return pdns_base_provider_get_server_ip_with_request_count(
        pdns_public_provider_as_base(p), stack, enable_ipv6, request_count, &is_host);
}

static void set_srtt(pdns_public_provider_t *p, const char *ip, long rtt) {
    pdns_base_provider_update_srtt(pdns_public_provider_as_base(p), ip, rtt);
}

/* 初始状态：DUAL 且不启用 IPv6 时选默认 v4 首节点 */
void test_provider_default_v4_node(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();
    CuAssertPtrNotNull(tc, p);

    const char *ip = best(p, PDNS_STACK_DUAL, false, 0);
    CuAssertPtrNotNull(tc, ip);
    CuAssert(tc, "should pick an ipv4 bootstrap node", is_ipv4_literal(ip));
    CuAssertStrEquals_Msg(tc, "untested first v4 node should win", "223.5.5.5", ip);

    pdns_public_provider_destroy(p);
}

/* IPV4_ONLY 只选 v4 节点 */
void test_provider_ipv4_only_stack(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();
    const char *ip = best(p, PDNS_STACK_IPV4_ONLY, true, 0);
    CuAssertPtrNotNull(tc, ip);
    CuAssert(tc, "ipv4-only stack must pick ipv4", is_ipv4_literal(ip));
    pdns_public_provider_destroy(p);
}

/* IPV6_ONLY 只选 v6 节点 */
void test_provider_ipv6_only_stack(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();
    const char *ip = best(p, PDNS_STACK_IPV6_ONLY, false, 0);
    CuAssertPtrNotNull(tc, ip);
    CuAssert(tc, "ipv6-only stack must pick ipv6", is_ipv6_literal(ip));
    pdns_public_provider_destroy(p);
}

/* 双栈 + enable_ipv6：仅首次请求优先 v6，重试回落 v4 */
void test_provider_dual_prefers_v6_on_first_try(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    const char *first = best(p, PDNS_STACK_DUAL, true, 0);
    CuAssertPtrNotNull(tc, first);
    CuAssert(tc, "first attempt should prefer ipv6 when enabled", is_ipv6_literal(first));

    const char *retry = best(p, PDNS_STACK_DUAL, true, 1);
    CuAssertPtrNotNull(tc, retry);
    CuAssert(tc, "retry should fall back to ipv4", is_ipv4_literal(retry));

    pdns_public_provider_destroy(p);
}

/* 重试次数达到阈值：切 HOST 域名兜底，返回 NULL 且 is_host=true */
void test_provider_host_fallback_on_retry_limit(CuTest *tc) {
    pdns_public_provider_t *p    = pdns_public_provider_create();
    pdns_base_provider_t   *base = pdns_public_provider_as_base(p);
    bool is_host = false;

    CuAssertPtrNotNull(tc, pdns_base_provider_get_server_ip_with_request_count(
                               base, PDNS_STACK_DUAL, false, PDNS_RETRY_COUNT - 1, &is_host));
    CuAssert(tc, "below retry count should not be host", !is_host);

    CuAssertPtrEquals_Msg(tc, "reaching retry count should switch to HOST (NULL ip)", NULL,
                          (void *) pdns_base_provider_get_server_ip_with_request_count(
                              base, PDNS_STACK_DUAL, false, PDNS_RETRY_COUNT, &is_host));
    CuAssert(tc, "is_host should be set when switching to HOST", is_host);

    CuAssertPtrEquals_Msg(tc, "beyond retry count should stay HOST", NULL,
                          (void *) pdns_base_provider_get_server_ip_with_request_count(
                              base, PDNS_STACK_DUAL, false, PDNS_RETRY_COUNT + 5, &is_host));
    CuAssert(tc, "is_host should stay set beyond retry count", is_host);

    pdns_public_provider_destroy(p);
}

/* 网络栈未知（NONE）：优先 HOST 域名兜底 */
void test_provider_none_stack_uses_host(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();
    CuAssertPtrEquals_Msg(tc, "NONE stack should use HOST fallback", NULL,
                          (void *) best(p, PDNS_STACK_NONE, false, 0));
    pdns_public_provider_destroy(p);
}

/* 未测量节点优先：已测量节点会让位给 srtt==0 的节点，保证探测覆盖 */
void test_provider_untested_node_first(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    /* 给首节点一个 RTT，使其不再是「未测量」 */
    set_srtt(p, "223.5.5.5", 100);

    CuAssertStrEquals_Msg(tc, "untested node should be probed first", "223.6.6.6",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* 全部已测量后按 SRTT 最小者选择 */
void test_provider_picks_lowest_srtt(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    set_srtt(p, "223.5.5.5", 200);
    set_srtt(p, "223.6.6.6", 40);

    CuAssertStrEquals_Msg(tc, "lowest srtt node should win", "223.6.6.6",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    /* 反转优劣后选择应随之切换：把 223.6.6.6 拉高到远超 223.5.5.5
     * （srtt=40 → 40*0.7+3000*0.3=928 > 200） */
    set_srtt(p, "223.6.6.6", 3000);
    CuAssertStrEquals_Msg(tc, "selection should follow srtt change", "223.5.5.5",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* SRTT 平滑公式：首次直接取 rtt，第二次为 srtt*0.7 + rtt*0.3 */
void test_provider_srtt_smoothing(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    /* 首次：srtt = 100 */
    set_srtt(p, "223.5.5.5", 100);
    /* 第二次：srtt = 100*0.7 + 200*0.3 = 130 */
    set_srtt(p, "223.5.5.5", 200);

    /* 通过与另一节点比较间接验证：把 223.6.6.6 设为 129（< 130）应胜出 */
    set_srtt(p, "223.6.6.6", 129);
    CuAssertStrEquals_Msg(tc, "smoothed srtt should be ~130 (129 wins)", "223.6.6.6",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    /* 再把 223.6.6.6 抬到 131（> 130）：223.5.5.5 应重新胜出
     * （srtt=129 → 129*0.7+135*0.3=131.1） */
    set_srtt(p, "223.6.6.6", 135);
    CuAssertStrEquals_Msg(tc, "smoothed srtt should be ~130 (131.1 loses)", "223.5.5.5",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* 失败惩罚：目标节点 +200ms，其余节点 *0.98（相对优劣被拉开） */
void test_provider_punish_moves_selection(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    set_srtt(p, "223.5.5.5", 100);
    set_srtt(p, "223.6.6.6", 50);
    CuAssertStrEquals(tc, "223.6.6.6", best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    /* 惩罚当前最优节点：50+200=250，另一节点 100*0.98=98 → 选择切换 */
    pdns_base_provider_punish(pdns_public_provider_as_base(p), "223.6.6.6");
    CuAssertStrEquals_Msg(tc, "punished node should lose", "223.5.5.5",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* 重置 SRTT（网络切换）后回到「全部未测量」状态 */
void test_provider_reset_srtt(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    set_srtt(p, "223.5.5.5", 300);
    CuAssertStrEquals(tc, "223.6.6.6", best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_base_provider_reset_srtt(pdns_public_provider_as_base(p));
    CuAssertStrEquals_Msg(tc, "after reset first node should be picked again", "223.5.5.5",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* 对不存在的节点更新/惩罚应被忽略，不影响既有节点 */
void test_provider_unknown_ip_ignored(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    set_srtt(p, "8.8.8.8", 1);       /* 非本 provider 的节点 */
    CuAssertStrEquals_Msg(tc, "unknown ip update should not affect selection", "223.5.5.5",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* 合并服务端优选列表：下发节点排在默认节点之前 */
void test_provider_merge_server_list(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    const char *v4[] = {"1.2.3.4", "5.6.7.8"};
    pdns_public_provider_merge_server_list(p, v4, 2, NULL, 0, NULL, 0, 300, false);

    CuAssertStrEquals_Msg(tc, "server-pushed node should rank first", "1.2.3.4",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    /* 默认 bootstrap 节点仍应保留（可被继续选中） */
    set_srtt(p, "1.2.3.4", 500);
    CuAssertStrEquals_Msg(tc, "second pushed node should be probed next", "5.6.7.8",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));
    set_srtt(p, "5.6.7.8", 500);
    CuAssertStrEquals_Msg(tc, "default nodes must be kept after merge", "223.5.5.5",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* 合并时 inherit_srtt=true：同 IP 保留历史 SRTT（复用测速结果） */
void test_provider_merge_inherits_srtt(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    set_srtt(p, "223.5.5.5", 100);

    const char *v4[] = {"223.5.5.5"};
    pdns_public_provider_merge_server_list(p, v4, 1, NULL, 0, NULL, 0, 300, true);

    /* 223.5.5.5 保留 srtt=100，223.6.6.6 仍未测量 → 后者优先 */
    CuAssertStrEquals_Msg(tc, "inherited srtt should keep node non-zero", "223.6.6.6",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* 合并时 inherit_srtt=false：所有节点 SRTT 归零（网络切换场景） */
void test_provider_merge_resets_srtt(CuTest *tc) {
    pdns_public_provider_t *p = pdns_public_provider_create();

    set_srtt(p, "223.5.5.5", 100);

    const char *v4[] = {"223.5.5.5"};
    pdns_public_provider_merge_server_list(p, v4, 1, NULL, 0, NULL, 0, 300, false);

    CuAssertStrEquals_Msg(tc, "srtt should be reset when inherit=false", "223.5.5.5",
                          best(p, PDNS_STACK_IPV4_ONLY, false, 0));

    pdns_public_provider_destroy(p);
}

/* serverTtl 过期判定：未下发过不算过期；下发后按 TTL 计时 */
void test_provider_server_ip_expire(CuTest *tc) {
    pdns_public_provider_t *p    = pdns_public_provider_create();
    pdns_base_provider_t   *base = pdns_public_provider_as_base(p);

    CuAssert(tc, "never-pushed server list should not be expired",
             !pdns_base_provider_is_server_ip_expired(base));

    pdns_base_provider_touch_server_expire(base, 1);
    CuAssert(tc, "fresh ttl should not be expired",
             !pdns_base_provider_is_server_ip_expired(base));

    apr_sleep(1100 * 1000);   /* 1.1 秒 */
    CuAssert(tc, "should expire after ttl",
             pdns_base_provider_is_server_ip_expired(base));

    /* 重新计时 */
    pdns_base_provider_touch_server_expire(base, 300);
    CuAssert(tc, "touch should extend expire",
             !pdns_base_provider_is_server_ip_expired(base));

    pdns_public_provider_destroy(p);
}

/* 未配置鉴权时 provider 不启用，
 * 配好鉴权后启用；节点始终可用（公共 DNS 有内置 bootstrap 节点）。 */
void test_provider_enabled_requires_auth(CuTest *tc) {
    pdns_public_provider_t  *p    = pdns_public_provider_create();
    pdns_server_provider_t  *prov = pdns_public_provider_as_provider(p);

    CuAssert(tc, "public dns always has bootstrap servers",
             pdns_provider_is_server_available(prov));
    CuAssert(tc, "no auth -> not available", !pdns_provider_is_account_auth_available(prov));
    CuAssert(tc, "no auth -> provider disabled", !pdns_provider_is_dns_provider_enabled(prov));

    /* 缺一项即不算配置成功，状态不变 */
    CuAssert(tc, "partial auth should be rejected",
             pdns_public_provider_set_auth(p, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, "") != 0);
    CuAssert(tc, "partial auth -> still disabled",
             !pdns_provider_is_dns_provider_enabled(prov));

    CuAssertIntEquals(tc, 0, pdns_public_provider_set_auth(p, PDNS_TEST_ACCOUNT,
                                                               PDNS_TEST_AK_ID,
                                                               PDNS_TEST_AK_SECRET));
    CuAssert(tc, "full auth -> provider enabled",
             pdns_provider_is_dns_provider_enabled(prov));
    CuAssertStrEquals(tc, "PublicDNS", pdns_provider_name(prov));

    pdns_public_provider_destroy(p);
}

/* 选点结果：公共 DNS 的 base_url 固定为服务域名，选中 IP 交由 resolve_host+server_ip 注入 */
void test_provider_public_server_url(CuTest *tc) {
    pdns_public_provider_t *p    = pdns_public_provider_create();
    pdns_server_provider_t *prov = pdns_public_provider_as_provider(p);

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals_Msg(tc, "base url should be the service domain, not the ip",
                          "https://" PDNS_PUBLIC_RESOLVER_HOST, res.base_url);
    CuAssertStrEquals(tc, PDNS_PUBLIC_RESOLVER_HOST, res.resolve_host);
    CuAssertStrEquals_Msg(tc, "selected node should be injected as server_ip",
                          "223.5.5.5", res.server_ip);
    CuAssert(tc, "public dns always verifies certificate", res.verify_cert);
    CuAssertStrEquals(tc, "PublicDNS", pdns_source_name(res.source));

    /* HOST 兜底：不注入 IP，交由系统 DNS 解析服务域名 */
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, PDNS_RETRY_COUNT, PDNS_STACK_IPV4_ONLY, false,
                                 true, &res));
    CuAssertStrEquals(tc, "https://" PDNS_PUBLIC_RESOLVER_HOST, res.base_url);
    CuAssertPtrEquals_Msg(tc, "host fallback must not inject ip", NULL,
                          (void *) res.server_ip);

    pdns_public_provider_destroy(p);
}

/* 鉴权 path：鉴权不全时生成失败（Provider 未启用即不发请求） */
void test_provider_url_path_requires_auth(CuTest *tc) {
    pdns_public_provider_t *p    = pdns_public_provider_create();
    pdns_server_provider_t *prov = pdns_public_provider_as_provider(p);
    char path[PDNS_URL_PATH_MAX_LEN];

    CuAssert(tc, "no auth -> url path must fail",
             pdns_provider_get_url_path_with_domain(prov, "www.taobao.com", "1", NULL, NULL,
                                                    false, path, sizeof(path)) != 0);

    pdns_public_provider_set_auth(p, PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID,
                                      PDNS_TEST_AK_SECRET);
    CuAssertIntEquals(tc, 0, pdns_provider_get_url_path_with_domain(
                                 prov, "www.taobao.com", "1", NULL, NULL, false,
                                 path, sizeof(path)));
    CuAssert(tc, "path should start with /resolve?", strncmp(path, "/resolve?", 9) == 0);
    CuAssertPtrNotNull(tc, strstr(path, "name=www.taobao.com"));
    CuAssertPtrNotNull(tc, strstr(path, "type=1"));
    CuAssertPtrNotNull(tc, strstr(path, "uid=" PDNS_TEST_ACCOUNT));
    CuAssertPtrNotNull(tc, strstr(path, "ak=" PDNS_TEST_AK_ID));
    CuAssertPtrNotNull(tc, strstr(path, "&key="));
    CuAssertPtrNotNull(tc, strstr(path, "&ts="));
    CuAssertPtrEquals_Msg(tc, "secret must never appear in url", NULL,
                          (void *) strstr(path, PDNS_TEST_AK_SECRET));

    /* short 模式 / ecs / did 追加 */
    CuAssertIntEquals(tc, 0, pdns_provider_get_url_path_with_domain(
                                 prov, "www.taobao.com", "28", "sid123", "1.2.3.0/24",
                                 true, path, sizeof(path)));
    CuAssertPtrNotNull(tc, strstr(path, "&did=sid123"));
    CuAssertPtrNotNull(tc, strstr(path, "&edns_client_subnet=1.2.3.0/24"));
    CuAssertPtrNotNull(tc, strstr(path, "&short=1"));

    pdns_public_provider_destroy(p);
}

/* NULL 防护 */
void test_provider_null_safety(CuTest *tc) {
    bool is_host = false;
    CuAssertPtrEquals(tc, NULL,
                      (void *) pdns_base_provider_get_server_ip_with_request_count(
                          NULL, PDNS_STACK_DUAL, false, 0, &is_host));
    CuAssert(tc, "NULL base not expired", !pdns_base_provider_is_server_ip_expired(NULL));
    pdns_base_provider_update_srtt(NULL, "1.1.1.1", 10);
    pdns_base_provider_punish(NULL, "1.1.1.1");
    pdns_base_provider_reset_srtt(NULL);
    pdns_base_provider_touch_server_expire(NULL, 60);
    pdns_public_provider_merge_server_list(NULL, NULL, 0, NULL, 0, NULL, 0, 60, false);
    pdns_public_provider_destroy(NULL);
    CuAssert(tc, "NULL provider has no name", strcmp(pdns_provider_name(NULL), "None") == 0);

    /* 合法 provider + NULL ip */
    pdns_public_provider_t *p = pdns_public_provider_create();
    pdns_base_provider_update_srtt(pdns_public_provider_as_base(p), NULL, 10);
    pdns_base_provider_punish(pdns_public_provider_as_base(p), NULL);
    pdns_public_provider_destroy(p);
}

void add_pdns_base_provider_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_provider_default_v4_node);
    SUITE_ADD_TEST(suite, test_provider_ipv4_only_stack);
    SUITE_ADD_TEST(suite, test_provider_ipv6_only_stack);
    SUITE_ADD_TEST(suite, test_provider_dual_prefers_v6_on_first_try);
    SUITE_ADD_TEST(suite, test_provider_host_fallback_on_retry_limit);
    SUITE_ADD_TEST(suite, test_provider_none_stack_uses_host);
    SUITE_ADD_TEST(suite, test_provider_untested_node_first);
    SUITE_ADD_TEST(suite, test_provider_picks_lowest_srtt);
    SUITE_ADD_TEST(suite, test_provider_srtt_smoothing);
    SUITE_ADD_TEST(suite, test_provider_punish_moves_selection);
    SUITE_ADD_TEST(suite, test_provider_reset_srtt);
    SUITE_ADD_TEST(suite, test_provider_unknown_ip_ignored);
    SUITE_ADD_TEST(suite, test_provider_merge_server_list);
    SUITE_ADD_TEST(suite, test_provider_merge_inherits_srtt);
    SUITE_ADD_TEST(suite, test_provider_merge_resets_srtt);
    SUITE_ADD_TEST(suite, test_provider_server_ip_expire);
    SUITE_ADD_TEST(suite, test_provider_enabled_requires_auth);
    SUITE_ADD_TEST(suite, test_provider_public_server_url);
    SUITE_ADD_TEST(suite, test_provider_url_path_requires_auth);
    SUITE_ADD_TEST(suite, test_provider_null_safety);
}
