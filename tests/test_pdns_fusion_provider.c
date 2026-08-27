/*
 * 自建 DNS 提供者测试 —— init 校验 / URL 拼装（含端口与 IPv6 方括号）/ 证书校验开关
 *
 * 与公共 DNS 的核心差异：
 *   - 无内置默认节点，全部由 init 传入；
 *   - base_url 直接拼「节点 + 端口」，不做 CURLOPT_RESOLVE 注入（server_ip 为 NULL）；
 *   - 证书校验可关（仅自签证书的私有化部署）。
 */
#include "test_suite_list.h"
#include "pdns_fusion_provider.h"

#define FUSION_HC_DOMAIN "hc.example.com"

static const char *g_v4[] = {"10.0.0.1", "10.0.0.2"};
static const char *g_v6[] = {"2001:db8::1"};
static const char *g_host[] = {"dns.example.com"};

/* 创建并完成一次合法 init */
static pdns_fusion_provider_t *make_fusion(int port) {
    pdns_fusion_provider_t *p = pdns_fusion_provider_create();
    if (p == NULL) {
        return NULL;
    }
    if (pdns_fusion_provider_init_fusion_dns(p, g_v4, 2, NULL, 0, NULL, 0, port,
                                                 FUSION_HC_DOMAIN, PDNS_TEST_ACCOUNT,
                                                 PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET) != 0) {
        pdns_fusion_provider_destroy(p);
        return NULL;
    }
    return p;
}

/* 未 init 时不启用：既无节点也无鉴权 */
void test_fusion_disabled_before_init(CuTest *tc) {
    pdns_fusion_provider_t *p    = pdns_fusion_provider_create();
    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(p);

    CuAssert(tc, "fusion has no builtin node", !pdns_provider_is_server_available(prov));
    CuAssert(tc, "fusion has no auth before init",
             !pdns_provider_is_account_auth_available(prov));
    CuAssert(tc, "fusion disabled before init", !pdns_provider_is_dns_provider_enabled(prov));
    CuAssertStrEquals(tc, "FusionDNS", pdns_provider_name(prov));

    pdns_fusion_provider_destroy(p);
}

/* init 校验：地址、探测域名、鉴权三类必填，任一缺失即失败且不改动状态 */
void test_fusion_init_validation(CuTest *tc) {
    pdns_fusion_provider_t *p    = pdns_fusion_provider_create();
    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(p);

    /* 三个地址数组全空 */
    CuAssert(tc, "no address should fail",
             pdns_fusion_provider_init_fusion_dns(p, NULL, 0, NULL, 0, NULL, 0, 443,
                                                     FUSION_HC_DOMAIN, PDNS_TEST_ACCOUNT,
                                                     PDNS_TEST_AK_ID,
                                                     PDNS_TEST_AK_SECRET) != 0);
    /* 缺 health_check_domain */
    CuAssert(tc, "empty health check domain should fail",
             pdns_fusion_provider_init_fusion_dns(p, g_v4, 2, NULL, 0, NULL, 0, 443,
                                                      "", PDNS_TEST_ACCOUNT,
                                                      PDNS_TEST_AK_ID,
                                                      PDNS_TEST_AK_SECRET) != 0);
    /* 缺 ak / sk 任一项（account_id 不属于必填项，见下一个用例） */
    CuAssert(tc, "empty ak id should fail",
             pdns_fusion_provider_init_fusion_dns(p, g_v4, 2, NULL, 0, NULL, 0, 443,
                                                      FUSION_HC_DOMAIN, PDNS_TEST_ACCOUNT,
                                                      "", PDNS_TEST_AK_SECRET) != 0);
    CuAssert(tc, "empty ak secret should fail",
             pdns_fusion_provider_init_fusion_dns(p, g_v4, 2, NULL, 0, NULL, 0, 443,
                                                      FUSION_HC_DOMAIN, PDNS_TEST_ACCOUNT,
                                                      PDNS_TEST_AK_ID, "") != 0);

    /* 以上失败均不得产生「半配置」状态 */
    CuAssert(tc, "failed init must not enable provider",
             !pdns_provider_is_dns_provider_enabled(prov));
    CuAssert(tc, "failed init must not load any node",
             !pdns_provider_is_server_available(prov));

    /* 合法 init */
    CuAssertIntEquals(tc, 0, pdns_fusion_provider_init_fusion_dns(
                                 p, g_v4, 2, g_v6, 1, g_host, 1, 8443, FUSION_HC_DOMAIN,
                                 PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET));
    CuAssert(tc, "valid init should enable provider",
             pdns_provider_is_dns_provider_enabled(prov));
    CuAssertStrEquals(tc, FUSION_HC_DOMAIN,
                      pdns_fusion_provider_get_health_check_domain(p));

    pdns_fusion_provider_destroy(p);
}

/* account_id 非必填：传空时回退到 PDNS_FUSION_DEFAULT_ACCOUNT_ID。
 * 对外 API pdns_client_init_fusion_dns 根本不收该参数，
 * 本用例走内部接口，验证兜底值确实落到了请求 URL 的 uid= 上。 */
void test_fusion_empty_account_falls_back_to_default(CuTest *tc) {
    pdns_fusion_provider_t *p    = pdns_fusion_provider_create();
    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(p);

    /* account_id 传空串与传 NULL 都应成功 */
    CuAssertIntEquals_Msg(tc, "empty account id should be accepted", 0,
                          pdns_fusion_provider_init_fusion_dns(
                              p, g_v4, 2, NULL, 0, NULL, 0, 443, FUSION_HC_DOMAIN,
                              "", PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET));
    CuAssert(tc, "provider should be enabled with the default account id",
             pdns_provider_is_dns_provider_enabled(prov));

    char path[PDNS_URL_PATH_MAX_LEN];
    CuAssertIntEquals(tc, 0, pdns_provider_get_url_path_with_domain(
                                 prov, "www.taobao.com", "1", NULL, NULL, false,
                                 path, sizeof(path)));
    CuAssertPtrNotNullMsg(tc, "uid should be the fixed fusion account id",
                          strstr(path, "uid=" PDNS_FUSION_DEFAULT_ACCOUNT_ID "&"));

    CuAssertIntEquals_Msg(tc, "NULL account id should be accepted too", 0,
                          pdns_fusion_provider_init_fusion_dns(
                              p, g_v4, 2, NULL, 0, NULL, 0, 443, FUSION_HC_DOMAIN,
                              NULL, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET));
    CuAssert(tc, "still enabled", pdns_provider_is_dns_provider_enabled(prov));

    pdns_fusion_provider_destroy(p);
}

/* base_url 直接拼节点与自定义端口，且不做 IP 注入 */
void test_fusion_server_url_with_port(CuTest *tc) {
    pdns_fusion_provider_t *p    = make_fusion(8443);
    CuAssertPtrNotNull(tc, p);
    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(p);

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals_Msg(tc, "fusion url should embed node and port",
                          "https://10.0.0.1:8443", res.base_url);
    CuAssertPtrEquals_Msg(tc, "fusion must not inject resolve host", NULL,
                          (void *) res.resolve_host);
    CuAssertPtrEquals_Msg(tc, "fusion must not inject server ip", NULL,
                          (void *) res.server_ip);
    /* 但节点标识必须回传（回归防护）：自建的 server_ip 恒为 NULL，
     * 若用 server_ip 当节点标识，SRTT 与失败惩罚将从不执行，
     * 重试会永远命中同一个不可用节点。 */
    CuAssertStrEquals_Msg(tc, "fusion must still report the selected node",
                          "10.0.0.1", res.node_ip);
    CuAssert(tc, "certificate validation is on by default", res.verify_cert);
    CuAssertStrEquals(tc, "FusionDNS", pdns_source_name(res.source));

    pdns_fusion_provider_destroy(p);
}

/* 回归防护：自建必须能随惩罚轮换节点。
 * 旧实现用 server_ip（自建恒为 NULL）作节点标识，惩罚从未生效，
 * 导致实测时 4 次重试全打在同一个不可用节点上。 */
void test_fusion_punish_rotates_node(CuTest *tc) {
    pdns_fusion_provider_t *p    = make_fusion(443);
    CuAssertPtrNotNull(tc, p);
    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(p);
    pdns_base_provider_t   *base = pdns_fusion_provider_as_base(p);

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals(tc, "10.0.0.1", res.node_ip);

    /* 用回传的 node_ip 做惩罚（即 executor 的做法），下一轮应换节点 */
    pdns_base_provider_punish(base, res.node_ip);

    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 1, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals_Msg(tc, "punished node must not be picked again",
                          "10.0.0.2", res.node_ip);
    CuAssertStrEquals(tc, "https://10.0.0.2:443", res.base_url);

    pdns_fusion_provider_destroy(p);
}

/* 端口 <=0 时取默认 443；http 时 scheme 随之变化 */
void test_fusion_default_port_and_scheme(CuTest *tc) {
    pdns_fusion_provider_t *p    = make_fusion(0);
    CuAssertPtrNotNull(tc, p);
    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(p);

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals(tc, "https://10.0.0.1:443", res.base_url);

    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, false, &res));
    CuAssertStrEquals(tc, "http://10.0.0.1:443", res.base_url);

    pdns_fusion_provider_destroy(p);
}

/* IPv6 节点须加方括号，否则与端口分隔符冲突 */
void test_fusion_ipv6_bracket(CuTest *tc) {
    pdns_fusion_provider_t *p = pdns_fusion_provider_create();
    CuAssertIntEquals(tc, 0, pdns_fusion_provider_init_fusion_dns(
                                 p, NULL, 0, g_v6, 1, NULL, 0, 8443, FUSION_HC_DOMAIN,
                                 PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET));

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 pdns_fusion_provider_as_provider(p), 0,
                                 PDNS_STACK_IPV6_ONLY, true, true, &res));
    CuAssertStrEquals_Msg(tc, "ipv6 node must be bracketed",
                          "https://[2001:db8::1]:8443", res.base_url);

    pdns_fusion_provider_destroy(p);
}

/* HOST 兜底：取调用方配置的域名节点，同样带端口 */
void test_fusion_host_fallback_uses_configured_domain(CuTest *tc) {
    pdns_fusion_provider_t *p = pdns_fusion_provider_create();
    CuAssertIntEquals(tc, 0, pdns_fusion_provider_init_fusion_dns(
                                 p, g_v4, 2, NULL, 0, g_host, 1, 8443, FUSION_HC_DOMAIN,
                                 PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET));

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 pdns_fusion_provider_as_provider(p), PDNS_RETRY_COUNT,
                                 PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssertStrEquals_Msg(tc, "host fallback should use the customer domain node",
                          "https://dns.example.com:8443", res.base_url);
    CuAssertPtrEquals_Msg(tc, "host fallback still must not inject ip", NULL,
                          (void *) res.server_ip);

    pdns_fusion_provider_destroy(p);
}

/* 无域名节点时，HOST 兜底回退到 IP 节点继续尝试（基类 getServerIPWithType 的行为：
 * 该类型取不到就退 V4）。公共 DNS 恒有域名节点，故这条回退只在自建才可能触发。 */
void test_fusion_no_host_node_falls_back_to_ip(CuTest *tc) {
    pdns_fusion_provider_t *p = make_fusion(443);
    CuAssertPtrNotNull(tc, p);

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals_Msg(tc, "without host node it should fall back to an ip node", 0,
                          pdns_provider_get_server_url_with_request_count(
                              pdns_fusion_provider_as_provider(p), PDNS_RETRY_COUNT,
                              PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssert(tc, "fallback target should be one of the configured ipv4 nodes",
             strcmp(res.base_url, "https://10.0.0.1:443") == 0 ||
             strcmp(res.base_url, "https://10.0.0.2:443") == 0);

    pdns_fusion_provider_destroy(p);
}

/* 证书校验开关只对自建生效 */
void test_fusion_certificate_validation_switch(CuTest *tc) {
    pdns_fusion_provider_t *p    = make_fusion(443);
    CuAssertPtrNotNull(tc, p);
    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(p);

    pdns_fusion_provider_set_enable_certificate_validation(p, false);

    pdns_server_url_result_t res;
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssert(tc, "verify_cert should follow the switch", !res.verify_cert);

    pdns_fusion_provider_set_enable_certificate_validation(p, true);
    memset(&res, 0, sizeof(res));
    CuAssertIntEquals(tc, 0, pdns_provider_get_server_url_with_request_count(
                                 prov, 0, PDNS_STACK_IPV4_ONLY, false, true, &res));
    CuAssert(tc, "switch back should restore verification", res.verify_cert);

    pdns_fusion_provider_destroy(p);
}

/* is_host_in_fusion_dns：去端口与方括号后比较 */
void test_fusion_is_host_in_fusion_dns(CuTest *tc) {
    pdns_fusion_provider_t *p = pdns_fusion_provider_create();
    CuAssertIntEquals(tc, 0, pdns_fusion_provider_init_fusion_dns(
                                 p, g_v4, 2, g_v6, 1, g_host, 1, 8443, FUSION_HC_DOMAIN,
                                 PDNS_TEST_ACCOUNT, PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET));

    CuAssert(tc, "plain ipv4 node", pdns_fusion_provider_is_host_in_fusion_dns(p, "10.0.0.1"));
    CuAssert(tc, "ipv4 node with port",
             pdns_fusion_provider_is_host_in_fusion_dns(p, "10.0.0.2:8443"));
    CuAssert(tc, "domain node", pdns_fusion_provider_is_host_in_fusion_dns(p, "dns.example.com"));
    CuAssert(tc, "bracketed ipv6 node",
             pdns_fusion_provider_is_host_in_fusion_dns(p, "[2001:db8::1]:8443"));
    CuAssert(tc, "unrelated host", !pdns_fusion_provider_is_host_in_fusion_dns(p, "8.8.8.8"));
    CuAssert(tc, "NULL host", !pdns_fusion_provider_is_host_in_fusion_dns(p, NULL));

    pdns_fusion_provider_destroy(p);
}

/* 鉴权 path：与公共 DNS 共用基类实现，格式一致 */
void test_fusion_url_path(CuTest *tc) {
    pdns_fusion_provider_t *p = make_fusion(443);
    CuAssertPtrNotNull(tc, p);
    char path[PDNS_URL_PATH_MAX_LEN];

    CuAssertIntEquals(tc, 0, pdns_provider_get_url_path_with_domain(
                                 pdns_fusion_provider_as_provider(p), "www.taobao.com",
                                 "1", NULL, NULL, false, path, sizeof(path)));
    CuAssert(tc, "path should start with /resolve?", strncmp(path, "/resolve?", 9) == 0);
    CuAssertPtrNotNull(tc, strstr(path, "uid=" PDNS_TEST_ACCOUNT));
    CuAssertPtrNotNull(tc, strstr(path, "&key="));

    pdns_fusion_provider_destroy(p);
}

/* NULL 防护 */
void test_fusion_null_safety(CuTest *tc) {
    CuAssert(tc, "NULL provider init should fail",
             pdns_fusion_provider_init_fusion_dns(NULL, g_v4, 2, NULL, 0, NULL, 0, 443,
                                                      FUSION_HC_DOMAIN, PDNS_TEST_ACCOUNT,
                                                      PDNS_TEST_AK_ID,
                                                      PDNS_TEST_AK_SECRET) != 0);
    pdns_fusion_provider_set_enable_certificate_validation(NULL, false);
    CuAssertPtrEquals(tc, NULL,
                      (void *) pdns_fusion_provider_get_health_check_domain(NULL));
    CuAssert(tc, "NULL provider host check", !pdns_fusion_provider_is_host_in_fusion_dns(NULL, "x"));
    pdns_fusion_provider_destroy(NULL);
}

void add_pdns_fusion_provider_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_fusion_disabled_before_init);
    SUITE_ADD_TEST(suite, test_fusion_init_validation);
    SUITE_ADD_TEST(suite, test_fusion_empty_account_falls_back_to_default);
    SUITE_ADD_TEST(suite, test_fusion_server_url_with_port);
    SUITE_ADD_TEST(suite, test_fusion_punish_rotates_node);
    SUITE_ADD_TEST(suite, test_fusion_default_port_and_scheme);
    SUITE_ADD_TEST(suite, test_fusion_ipv6_bracket);
    SUITE_ADD_TEST(suite, test_fusion_host_fallback_uses_configured_domain);
    SUITE_ADD_TEST(suite, test_fusion_no_host_node_falls_back_to_ip);
    SUITE_ADD_TEST(suite, test_fusion_certificate_validation_switch);
    SUITE_ADD_TEST(suite, test_fusion_is_host_in_fusion_dns);
    SUITE_ADD_TEST(suite, test_fusion_url_path);
    SUITE_ADD_TEST(suite, test_fusion_null_safety);
}
