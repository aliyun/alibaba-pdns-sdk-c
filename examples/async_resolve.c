/*
 * 异步解析示例
 *
 * 用法：async_resolve <host> [qtype]
 *   host  要解析的域名，不传时默认解析 MOCK_HOST。
 *   qtype 查询类型：v4(默认) / v6 / both(双栈) / auto(按网络栈自动)。
 *
 * 演示：日志开关、异步解析（线程池 + 回调）、LocalDNS 降级、缓存刷新。
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

/* 示例：集成方自定义日志回调（演示生产集成路径）。
 * SDK 传入已格式化的纯文本 msg（不含颜色），集成方可自行决定输出目标/加前缀/上色。
 * 注入后 SDK 不再走默认 stderr/stdout 打印。 */
static void app_logger(pdns_log_level_t level, const char *msg) {
    (void) level;
    fprintf(stdout, "[PDNS] %s\n", msg);
}

/* 异步解析完成回调 */
static void on_resolved(const char *host, pdns_query_type_t query_type,
                        pdns_result_list_t *results, void *user_data) {
    (void) user_data;
    size_t count = pdns_result_list_size(results);
    pdns_source_t src   = pdns_result_list_get_source(results, query_type);
    bool          cache = pdns_result_list_is_from_cache(results, query_type);
    printf("[APP] resolve %s done, %zu IP(s) [source=%s from_cache=%s]:\n",
           host, count, pdns_source_name(src), cache ? "true" : "false");
    for (size_t i = 0; i < count; i++) {
        printf("  - %s\n", pdns_result_list_get(results, i));
    }
}

int main(int argc, char **argv) {
    const char         *host    = (argc > 1) ? argv[1] : MOCK_HOST;

    /* 解析查询类型参数（可选，第 2 个参数）：v4(默认)/v6/both/auto */
    pdns_query_type_t qtype      = PDNS_QUERY_IPV4;
    const char       *qtype_name = "v4";
    if (argc > 2) {
        if (strcmp(argv[2], "v6") == 0) {
            qtype = PDNS_QUERY_IPV6; qtype_name = "v6";
        } else if (strcmp(argv[2], "both") == 0) {
            qtype = PDNS_QUERY_BOTH; qtype_name = "both";
        } else if (strcmp(argv[2], "auto") == 0) {
            qtype = PDNS_QUERY_AUTO; qtype_name = "auto";
        }
    }
    printf("[APP] host=%s qtype=%s\n", host, qtype_name);

    if (pdns_sdk_init() != PDNS_OK) {
        fprintf(stderr, "[APP] pdns_sdk_init failed\n");
        return 1;
    }

    /* 打开日志并注入自定义回调（生产集成路径：日志经回调交给集成方） */
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
    pdns_client_set_enable_localdns(client, true);
    pdns_client_start(client);

    /* 异步解析 */
    printf("[APP] submit resolve %s ...\n", host);
    pdns_status_t st = pdns_resolve_async(client, host,
                                                      qtype, on_resolved, NULL);
    if (!pdns_status_is_ok(&st)) {
        fprintf(stderr, "[APP] submit async failed: %s\n", st.error_msg);
    }

    /* 等待异步任务完成（示例用简单 sleep） */
    SLEEP_MS(4000);

    /* 再次从缓存读取，验证异步已写入缓存 */
    pdns_result_list_t *cached = NULL;
    st = pdns_resolve_sync_from_cache(client, host,
                                                  qtype, true, &cached);
    if (pdns_status_is_ok(&st)) {
        printf("[APP] from cache: %zu IP(s) [source=%s from_cache=%s]\n",
               pdns_result_list_size(cached),
               pdns_source_name(pdns_result_list_get_source(cached, qtype)),
               pdns_result_list_is_from_cache(cached, qtype) ? "true" : "false");
        for (size_t i = 0; i < pdns_result_list_size(cached); i++) {
            printf("  - %s\n", pdns_result_list_get(cached, i));
        }
    }
    pdns_result_list_cleanup(cached);

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
    printf("[APP] OK, Exit.\n");
    return 0;
}
