/*
 * 测试套件登记表
 *
 * 分层约定：
 *   - 离线单元测试：直接调用 src/ 内部模块接口（cache / acl / provider / manager / sign / rc4 / idn ...），
 *     不依赖网络，结果确定，是 CI 的主体。
 *   - 联网集成测试：通过 include/pdns 公开 API 打真实 HTTPDNS 服务，
 *     受网络环境影响，用 PDNS_TEST_NETWORK 开关控制（默认开启，CI 离线环境可关）。
 *
 * 关闭联网测试：cmake -DPDNS_TEST_NETWORK=OFF
 */
#ifndef PDNS_TEST_SUITE_LIST_H
#define PDNS_TEST_SUITE_LIST_H

#include "CuTest.h"
#include "pdns/pdns_api.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- 测试用鉴权参数（与 examples 保持一致） ---------------- */
/* TODO 请替换鉴权参数
 * 鉴权参数（account_id / access_key_id / access_key_secret）从阿里云控制台获取，
 * 详见移动解析 HTTPDNS 产品文档。https://dnsnext.console.aliyun.com/pdnsDoh
 */
#define PDNS_TEST_ACCOUNT    "******"
#define PDNS_TEST_AK_ID      "******"
#define PDNS_TEST_AK_SECRET  "******"

/* 联网测试用域名 */
#define PDNS_TEST_HOST       "www.taobao.com"
#define PDNS_TEST_HOST2      "www.aliyun.com"
/* 必然不存在的域名，用于否定缓存 / NXDOMAIN 场景 */
#define PDNS_TEST_HOST_NX    "no-such-host-pdns-sdk-test.invalid"

/*
 * 测试用：创建 client 并配置公共 DNS 鉴权。
 * 对外 API 已拆为 create（只建实例）+ init_public_dns（配鉴权，三参数必填）两步，
 * 用例中绝大多数场景只关心「拿到一个可用 client」，故封装此 helper。
 * 任一步失败则返回 NULL（已释放中间状态）。
 */
static inline pdns_client_t *pdns_test_client_create(void) {
    pdns_client_t *client = pdns_client_create();
    if (client == NULL) {
        return NULL;
    }
    pdns_status_t st = pdns_client_init_public_dns(client, PDNS_TEST_ACCOUNT,
                                                   PDNS_TEST_AK_ID, PDNS_TEST_AK_SECRET);
    if (!pdns_status_is_ok(&st)) {
        pdns_client_cleanup(client);
        return NULL;
    }
    return client;
}

/* ---------------- 离线单元测试套件 ---------------- */

void add_pdns_list_tests(CuSuite *suite);

void add_pdns_util_tests(CuSuite *suite);

void add_pdns_sign_tests(CuSuite *suite);

void add_pdns_rc4_tests(CuSuite *suite);

void add_pdns_idn_tests(CuSuite *suite);

void add_pdns_cache_tests(CuSuite *suite);

void add_pdns_acl_tests(CuSuite *suite);

void add_pdns_base_provider_tests(CuSuite *suite);

void add_pdns_fusion_provider_tests(CuSuite *suite);

void add_pdns_failure_tracker_tests(CuSuite *suite);

void add_pdns_server_manager_tests(CuSuite *suite);

/* 熔断与健康检查：只测状态机与前置条件，探测请求本身需联网不在此 */
void add_pdns_health_checker_tests(CuSuite *suite);

void add_pdns_netstack_tests(CuSuite *suite);

void add_pdns_speedtest_tests(CuSuite *suite);

void add_pdns_net_tests(CuSuite *suite);

void add_pdns_log_tests(CuSuite *suite);

void add_pdns_config_tests(CuSuite *suite);

void add_pdns_select_ip_tests(CuSuite *suite);

/* ---------------- 联网集成测试套件 ---------------- */

void add_pdns_api_tests(CuSuite *suite);

void add_pdns_thread_safe_tests(CuSuite *suite);

#endif /* PDNS_TEST_SUITE_LIST_H */
