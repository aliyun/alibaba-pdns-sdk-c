/*
 * 预解析示例
 *
 * 演示：批量预解析（scene=PRELOAD）→ 后台异步写缓存 → 从缓存命中验证。
 *
 * 用法：preload_resolve [host1] [host2...] [qtype]
 *   host  可传多个待预解析域名；不传时使用内置 MOCK_HOSTS。
 *   qtype 查询类型：v4(默认) / v6 / both(双栈) / auto(按网络栈自动)。
 *
 * 预解析特点：
 *   - 结果只入缓存、不返回给调用方（无回调）；
 *   - 已有未过期缓存的域名会被跳过（观察 preload skip 日志）；
 *   - both 会对每个域名拆成 v4/v6 两次单类型预解析（观察 type=1 / type=28）。
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

/* TODO 请替换鉴权参数
 * 鉴权参数（account_id / access_key_id / access_key_secret）从阿里云控制台获取，
 * 详见移动解析 HTTPDNS 产品文档。https://dnsnext.console.aliyun.com/pdnsDoh
 */
#define MOCK_ACCOUNT    "******"
#define MOCK_AK_ID      "******"
#define MOCK_AK_SECRET  "******"

/* 内置默认预解析域名（未从命令行传入 host 时使用） */
static const char *MOCK_HOSTS[] = {
    "www.taobao.com",
    "www.douyin.com",
    "www.baidu.com",
};
#define MOCK_HOSTS_NUM (sizeof(MOCK_HOSTS) / sizeof(MOCK_HOSTS[0]))

/* 集成方自定义日志回调（演示生产集成路径） */
static void app_logger(pdns_log_level_t level, const char *msg) {
    (void) level;
    fprintf(stdout, "[PDNS] %s\n", msg);
}

int main(int argc, char **argv) {
    /* 解析查询类型参数：最后一个参数若为 v4/v6/both/auto 则视为 qtype，
     * 其余参数均为域名；否则全部参数均为域名。 */
    pdns_query_type_t qtype      = PDNS_QUERY_IPV4;
    const char       *qtype_name = "v4";
    int               host_count = 0;
    if (argc > 1) {
        const char *last = argv[argc - 1];
        int is_qtype = (strcmp(last, "v4") == 0 || strcmp(last, "v6") == 0 ||
                        strcmp(last, "both") == 0 || strcmp(last, "auto") == 0);
        if (is_qtype) {
            if (strcmp(last, "v6") == 0)   { qtype = PDNS_QUERY_IPV6; qtype_name = "v6"; }
            else if (strcmp(last, "both") == 0) { qtype = PDNS_QUERY_BOTH; qtype_name = "both"; }
            else if (strcmp(last, "auto") == 0) { qtype = PDNS_QUERY_AUTO; qtype_name = "auto"; }
            host_count = argc - 2;
        } else {
            host_count = argc - 1;
        }
    }

    if (pdns_sdk_init() != PDNS_OK) {
        fprintf(stderr, "[APP] pdns_sdk_init failed\n");
        return 1;
    }

    /* 打开日志并注入自定义回调 */
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

    /* 等待黑白名单 conf / 服务列表异步加载完成 */
    printf("[APP] waiting 2s for acl/conf to load ...\n");
    SLEEP_MS(2000);

    /* 组装待预解析域名列表：命令行传入优先，否则用内置默认 */
    pdns_domain_list_t *domains = pdns_domain_list_create();
    if (host_count > 0) {
        for (int i = 1; i <= host_count; i++) {
            pdns_domain_list_add(domains, argv[i]);
        }
    } else {
        for (size_t i = 0; i < MOCK_HOSTS_NUM; i++) {
            pdns_domain_list_add(domains, MOCK_HOSTS[i]);
        }
    }

    size_t dn = pdns_domain_list_size(domains);
    printf("[APP] preload %zu domain(s), qtype=%s:\n", dn, qtype_name);
    for (size_t i = 0; i < dn; i++) {
        printf("  - %s\n", pdns_domain_list_get(domains, i));
    }

    /* 发起批量预解析（scene=PRELOAD，结果只入缓存不返回） */
    pdns_client_add_pre_load_domains(client, qtype, domains);

    /* 等待后台预解析任务完成 */
    printf("[APP] waiting 4s for preload tasks ...\n");
    SLEEP_MS(4000);

    /* 逐个从缓存读取，验证预解析已写入缓存（is_allow_exp=true） */
    printf("\n[APP] verify cache after preload:\n");
    for (size_t i = 0; i < dn; i++) {
        const char *host = pdns_domain_list_get(domains, i);
        pdns_result_list_t *cached = NULL;
        pdns_status_t st = pdns_resolve_sync_from_cache(
            client, host, qtype, true, &cached);
        size_t count = pdns_result_list_size(cached);
        if (pdns_status_is_ok(&st) && count > 0) {
            printf("  [HIT ] %s -> %zu IP(s) [source=%s]:\n", host, count,
                   pdns_source_name(pdns_result_list_get_source(cached, qtype)));
            for (size_t j = 0; j < count; j++) {
                printf("         - %s\n", pdns_result_list_get(cached, j));
            }
        } else {
            printf("  [MISS] %s（未命中缓存或被拦截）\n", host);
        }
        pdns_result_list_cleanup(cached);
    }

    /* 再次预解析同一批域名：应命中新鲜缓存并被跳过（观察 preload skip 日志） */
    printf("\n[APP] preload again (expect skip on fresh cache):\n");
    pdns_client_add_pre_load_domains(client, qtype, domains);
    SLEEP_MS(1000);

    pdns_domain_list_cleanup(domains);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
    printf("\n[APP] OK, Exit.\n");
    return 0;
}
