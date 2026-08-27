/*
 * 保活域名示例
 *
 * 演示：setKeepAliveDomains 登记 → 首次解析写缓存触发保活链
 *       → TTL×0.75 到点自动刷新（scene=timer）→ 写缓存续链（闭环）。
 *
 * 用法：keepalive_resolve [host]
 *   host 不传时默认 MOCK_HOST。
 *
 * 保活特点：
 *   - 登记时不解析、不排期（零副作用），最多 10 个域名；
 *   - 哪个 type 被写缓存就保活哪个 type（本例解析 v4，只有 v4 链）；
 *   - 为便于观察，将 TTL 钳制到 8s → 保活延时 8×0.75=6s，
 *     等待 ~16s 可看到两轮 keepalive refresh 日志。
 */
#include "pdns/pdns_api.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <unistd.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

#define MOCK_HOST       "www.taobao.com"
/* TODO 请替换鉴权参数
 * 鉴权参数（account_id / access_key_id / access_key_secret）从阿里云控制台获取，
 * 详见移动解析 HTTPDNS 产品文档。https://dnsnext.console.aliyun.com/pdnsDoh
 */
#define MOCK_ACCOUNT    "******"
#define MOCK_AK_ID      "******"
#define MOCK_AK_SECRET  "******"

/* 集成方自定义日志回调（演示生产集成路径） */
static void app_logger(pdns_log_level_t level, const char *msg) {
    (void) level;
    fprintf(stdout, "[PDNS] %s\n", msg);
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : MOCK_HOST;

    if (pdns_sdk_init() != PDNS_OK) {
        fprintf(stderr, "[APP] pdns_sdk_init failed\n");
        return 1;
    }

    pdns_log_set_enable(true);
    pdns_log_set_level(PDNS_LOG_LEVEL_DEBUG);
    pdns_log_set_logger(app_logger);

    pdns_client_t *client = pdns_client_create();
    if (!client) {
        fprintf(stderr, "[APP] pdns_client_create failed\n");
        pdns_sdk_cleanup();
        return 1;
    }
    /* 配置公共 DNS 鉴权（3 参数均必填，缺一即返回错误） */
    pdns_status_t auth_st = pdns_client_init_public_dns(client, MOCK_ACCOUNT,
                                                       MOCK_AK_ID, MOCK_AK_SECRET);
    if (!pdns_status_is_ok(&auth_st)) {
        fprintf(stderr, "[APP] pdns_client_init_public_dns failed: %s\n", auth_st.error_msg);
        pdns_client_cleanup(client);
        pdns_sdk_cleanup();
        return 1;
    }
    pdns_client_set_timeout(client, 3000);
    pdns_client_set_enable_cache(client, true);
    /* 缩短 TTL 便于观察保活：钳到 [4,8]s → 保活延时 6s（生产勿设，用默认 [60,3600]） */
    pdns_client_set_min_ttl_cache(client, 4);
    pdns_client_set_max_ttl_cache(client, 8);

    /* 登记保活域名：仅登记，不解析、不排期 */
    pdns_domain_list_t *ka = pdns_domain_list_create();
    pdns_domain_list_add(ka, host);
    pdns_client_set_keep_alive_domains(client, ka);
    pdns_domain_list_cleanup(ka);

    pdns_client_start(client);
    printf("[APP] waiting 2s for acl/conf to load ...\n");
    SLEEP_MS(2000);

    /* 首次同步解析：写缓存 → 触发保活链（观察 keepalive schedule 日志） */
    printf("[APP] first resolve %s (v4) to trigger keepalive chain ...\n", host);
    pdns_result_list_t *results = NULL;
    pdns_status_t st = pdns_resolve_sync(client, host,
                                                     PDNS_QUERY_IPV4, &results);
    if (pdns_status_is_ok(&st)) {
        printf("[APP] resolve ok, %zu IP(s) [source=%s]\n",
               pdns_result_list_size(results),
               pdns_source_name(pdns_result_list_get_source(results, PDNS_QUERY_IPV4)));
    } else {
        fprintf(stderr, "[APP] resolve failed: %s\n", st.error_msg);
    }
    pdns_result_list_cleanup(results);

    /* 等待 ~16s：应观察到两轮 keepalive refresh(scene=timer) + 续链 schedule 日志 */
    printf("[APP] waiting 16s, expect ~2 rounds of keepalive refresh (ttl=8s, delay=6s) ...\n");
    SLEEP_MS(16000);

    /* 验证缓存始终新鲜：保活链持续续期，此刻应命中缓存 */
    pdns_result_list_t *cached = NULL;
    st = pdns_resolve_sync_from_cache(client, host,
                                                  PDNS_QUERY_IPV4, false, &cached);
    printf("[APP] cache check after 16s: %zu IP(s) %s\n",
           pdns_result_list_size(cached),
           (pdns_result_list_size(cached) > 0) ? "(HIT, kept alive)" : "(MISS)");
    pdns_result_list_cleanup(cached);

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
    printf("[APP] OK, Exit.\n");
    return 0;
}
