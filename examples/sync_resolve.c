/*
 * 同步解析示例
 *
 * 用法：sync_resolve <host> [qtype]
 *   host  要解析的域名，不传时默认解析 MOCK_HOST。
 *   qtype 查询类型：v4(默认) / v6 / both(双栈) / auto(按网络栈自动)。
 *   测试黑白名单：先在控制台配置好黑/白名单，再传入对应域名
 *   观察日志中的 acl detail 与解析结果是否被拦截（ACL_REJECTED）。
 *   测试双栈：传 both，可观察到 type=1 与 type=28 两次单类型请求。
 */
#include "pdns/pdns_api.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

int main(int argc, char **argv) {
    const char         *host    = (argc > 1) ? argv[1] : MOCK_HOST;
    pdns_client_t      *client  = NULL;
    pdns_result_list_t *results = NULL;
    pdns_status_t       status;

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

    /* 打开日志并注入自定义回调（生产集成路径：日志经回调交给集成方） */
    pdns_log_set_enable(true);
    pdns_log_set_logger(app_logger);

    /* 1. SDK 初始化 */
    if (pdns_sdk_init() != PDNS_OK) {
        fprintf(stderr, "[APP] pdns_sdk_init failed\n");
        return 1;
    }

    /* 2. 创建客户端（不含任何 DNS 服务配置） */
    client = pdns_client_create();
    if (!client) {
        fprintf(stderr, "[APP] pdns_client_create failed\n");
        pdns_sdk_cleanup();
        return 1;
    }

    /* 2.1 配置公共 DNS 鉴权（3 参数均必填，缺一即返回错误） */
    status = pdns_client_init_public_dns(client, MOCK_ACCOUNT, MOCK_AK_ID, MOCK_AK_SECRET);
    if (!pdns_status_is_ok(&status)) {
        fprintf(stderr, "[APP] pdns_client_init_public_dns failed: %s\n", status.error_msg);
        pdns_client_cleanup(client);
        pdns_sdk_cleanup();
        return 1;
    }

    /* 3. 配置（可选） */
    pdns_client_set_timeout(client, 3000);
    pdns_client_set_enable_cache(client, true);
    pdns_client_set_schema_type(client, PDNS_SCHEMA_HTTPS);

    /* 4. 启动 */
    status = pdns_client_start(client);
    if (!pdns_status_is_ok(&status)) {
        fprintf(stderr, "[APP] client start failed: %s\n", status.error_msg);
        pdns_client_cleanup(client);
        pdns_sdk_cleanup();
        return 1;
    }

    /* 5. 等待黑白名单 conf 异步加载完成（首次 start 后 conf/服务列表为后台拉取，
     *    若立即解析可能早于 ACL 生效、无法命中黑白名单）。测试用固定等待 2s。 */
    printf("[APP] waiting 2s for acl/conf to load ...\n");
    sleep(2);

    /* 6. 同步解析 */
    status = pdns_resolve_sync(client, host, qtype, &results);
    size_t count = pdns_result_list_size(results);
    if (pdns_status_is_ok(&status)) {
        if (count == 0 && strcmp(status.error_code, "ACL_REJECTED") == 0) {
            printf("[APP] host=%s 命中黑/白名单拦截：返回空结果，未走 LocalDNS 兜底（error_code=%s）\n",
                   host, status.error_code);
        } else if (count == 0) {
            printf("[APP] resolve %s ok，但无 IP（NXDOMAIN/NODATA 等否定结果）\n", host);
        } else {
            /* 来源：按本次查询类型取（AUTO/BOTH 会自动取有结果的那一族） */
            pdns_source_t src   = pdns_result_list_get_source(results, qtype);
            bool          cache = pdns_result_list_is_from_cache(results, qtype);
            printf("[APP] resolve %s ok, %zu IP(s) [source=%s from_cache=%s]:\n",
                   host, count, pdns_source_name(src), cache ? "true" : "false");
            for (size_t i = 0; i < count; i++) {
                printf("  - %s\n", pdns_result_list_get(results, i));
            }
        }
    } else {
        fprintf(stderr, "[APP] resolve failed: code=%d error_code=%s msg=%s\n",
                status.code, status.error_code, status.error_msg);
    }
    sleep(2);
    /* 7. 验证缓存：从缓存读取（应命中上一步 sync 写入的结果；命中黑白名单时无缓存）。
     *    此时 from_cache 应为 true，而 source 仍为当初写入缓存的真实来源。 */
    pdns_result_list_t *cached = NULL;
    status = pdns_resolve_sync_from_cache(client, host, qtype, true, &cached);
    if (pdns_status_is_ok(&status)) {
        pdns_source_t src   = pdns_result_list_get_source(cached, qtype);
        bool          cache = pdns_result_list_is_from_cache(cached, qtype);
        printf("[APP] from cache: %zu IP(s) [source=%s from_cache=%s]:\n",
               pdns_result_list_size(cached), pdns_source_name(src), cache ? "true" : "false");
        for (size_t i = 0; i < pdns_result_list_size(cached); i++) {
            printf("  - %s\n", pdns_result_list_get(cached, i));
        }
    }
    pdns_result_list_cleanup(cached);

    /* 8. 释放资源 */
    pdns_result_list_cleanup(results);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();

    printf("[APP] OK, Exit.\n");
    return 0;
}
