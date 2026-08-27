/*
 * 自建 DNS 示例 —— 演示 4 种服务配置组合
 *
 * 用法：fusion_resolve [mode] [host]
 *   mode: public          仅公共 DNS
 *         fusion          仅自建 DNS
 *         public-first    公共主用 + 自建备用（默认降级阈值 4）
 *         fusion-first    自建主用 + 公共备用（默认降级阈值 2，默认模式）
 *         fallback-demo   自建主用（故意配不可达节点）+ 公共备用，阈值 2，
 *                         可在日志中观察到 2 次自建失败后切到 PublicDNS 并解析成功
 *   host: 待解析域名，默认 MOCK_HOST
 *
 * 主备关系由「init 的调用顺序」决定，先配置者为主用；单次解析中主用累计失败
 * 达到降级阈值后，剩余重试自动切到备用（阈值可用
 * pdns_client_set_fallback_threshold 覆盖，须在两个 init 之后调用）。
 *
 * 注意：本文件里的自建节点与密钥是**测试环境**的真实值，仅用于验证；
 * 接入时请换成控制台为你的自建实例给出的节点、端口与密钥。
 * 自建的鉴权密钥与公共 DNS **完全独立**，且不需要 account_id
 * （uid 由 SDK 内部固定）。
 */
#include "pdns/pdns_api.h"
#include <stdio.h>
#include <string.h>

#define MOCK_HOST       "www.taobao.com"

/* 公共 DNS 鉴权（需 account_id + ak + sk） */
/* TODO 请替换鉴权参数
 * 鉴权参数（account_id / access_key_id / access_key_secret）从阿里云控制台获取，
 * 详见移动解析 HTTPDNS 产品文档。https://dnsnext.console.aliyun.com/pdnsDoh
 */
#define MOCK_ACCOUNT    "******"
#define MOCK_AK_ID      "******"
#define MOCK_AK_SECRET  "******"

/* 自建鉴权（只需 ak + sk，与公共 DNS 互不相干） */
#define MOCK_FUSION_AK_ID     "******"
#define MOCK_FUSION_AK_SECRET "******"

#define MOCK_FUSION_PORT    443
/* 熔断后用于探测节点是否恢复的域名（必填） */
#define MOCK_FUSION_HC      "www.taobao.com"

/* fallback-demo 用的不可达节点：RFC 5737 保留的文档用地址，永不可路由，
 * 因此自建每次尝试都会超时失败，从而稳定触发降级。 */
#define MOCK_FUSION_DEAD_IP "192.0.2.1"

static void app_logger(pdns_log_level_t level, const char *msg) {
    (void) level;
    fprintf(stdout, "[PDNS] %s\n", msg);
}

/*
 * 配置自建：本例只有 IPv4 节点，IPv6 与域名节点为空。
 *
 * 未配域名（HOST）节点时，末次重试会回退到 IPv4 节点继续尝试，
 * 而不是像公共 DNS 那样切到服务域名走系统 DNS。
 */
static pdns_status_t init_fusion(pdns_client_t *client) {
    /* 测试环境的自建节点 */
    const char *v4_arr[] = {
        "***.***.***.***", "***.***.***.***",
        "***.***.***.***", "***.***.***.***",
        "***.***.***.***", "***.***.***.***",
    };
    return pdns_client_init_fusion_dns(client,
                                       v4_arr, 6,          /* IPv4 节点 */
                                       NULL, 0,            /* IPv6 节点 */
                                       NULL, 0,            /* 域名节点 */
                                       MOCK_FUSION_PORT,
                                       MOCK_FUSION_HC,
                                       MOCK_FUSION_AK_ID, MOCK_FUSION_AK_SECRET);
}

static pdns_status_t init_public(pdns_client_t *client) {
    return pdns_client_init_public_dns(client, MOCK_ACCOUNT, MOCK_AK_ID, MOCK_AK_SECRET);
}

/* 配置一个必然失败的自建（仅 fallback-demo 用，见 MOCK_FUSION_DEAD_IP 说明） */
static pdns_status_t init_fusion_dead(pdns_client_t *client) {
    const char *v4_arr[] = {MOCK_FUSION_DEAD_IP};
    return pdns_client_init_fusion_dns(client, v4_arr, 1, NULL, 0, NULL, 0,
                                       MOCK_FUSION_PORT, MOCK_FUSION_HC,
                                       MOCK_FUSION_AK_ID, MOCK_FUSION_AK_SECRET);
}

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "fusion-first";
    const char *host = (argc > 2) ? argv[2] : MOCK_HOST;

    printf("[APP] mode=%s host=%s\n", mode, host);

    pdns_log_set_enable(true);
    pdns_log_set_logger(app_logger);

    if (pdns_sdk_init() != PDNS_OK) {
        fprintf(stderr, "[APP] pdns_sdk_init failed\n");
        return 1;
    }

    pdns_client_t *client = pdns_client_create();
    if (!client) {
        fprintf(stderr, "[APP] pdns_client_create failed\n");
        pdns_sdk_cleanup();
        return 1;
    }

    /* 按 mode 决定 init 调用顺序 —— 顺序即主备关系 */
    pdns_status_t status;
    if (strcmp(mode, "public") == 0) {
        status = init_public(client);
    } else if (strcmp(mode, "fusion") == 0) {
        status = init_fusion(client);
    } else if (strcmp(mode, "public-first") == 0) {
        status = init_public(client);
        if (pdns_status_is_ok(&status)) {
            status = init_fusion(client);
        }
    } else if (strcmp(mode, "fallback-demo") == 0) {
        status = init_fusion_dead(client);
        if (pdns_status_is_ok(&status)) {
            status = init_public(client);
        }
    } else {   /* fusion-first（默认） */
        status = init_fusion(client);
        if (pdns_status_is_ok(&status)) {
            status = init_public(client);
        }
    }
    if (!pdns_status_is_ok(&status)) {
        fprintf(stderr, "[APP] init dns service failed: %s\n", status.error_msg);
        pdns_client_cleanup(client);
        pdns_sdk_cleanup();
        return 1;
    }

    /* 可选：覆盖默认降级阈值。0 表示不给主用机会直接走备用，便于验证降级链路。
     * 必须放在两个 init 之后——init 会重建主备关系并把阈值重置为默认值。 */
    /* pdns_client_set_fallback_threshold(client, 0); */

    if (strcmp(mode, "fallback-demo") == 0) {
        /* 主用最多试 2 次即降级；并把超时压到 1s，避免演示时等太久 */
        pdns_client_set_fallback_threshold(client, 2);
        pdns_client_set_timeout(client, 1000);
    }

    /* 可选：自建自签证书的私有化部署可关闭证书校验（仅测试环境，生产不要关） */
    /* pdns_client_set_fusion_certificate_validation(client, false); */

    status = pdns_client_start(client);
    if (!pdns_status_is_ok(&status)) {
        fprintf(stderr, "[APP] pdns_client_start failed: %s\n", status.error_msg);
        pdns_client_cleanup(client);
        pdns_sdk_cleanup();
        return 1;
    }

    /* 解析：结果携带的 source 表明本次实际由哪个 provider 服务（与日志 source= 一致） */
    pdns_result_list_t *results = NULL;
    status = pdns_resolve_sync(client, host, PDNS_QUERY_IPV4, &results);
    if (pdns_status_is_ok(&status)) {
        size_t n = pdns_result_list_size(results);
        printf("[APP] resolve %s ok, %zu IP(s) [source=%s from_cache=%s]:\n", host, n,
               pdns_source_name(pdns_result_list_get_source(results, PDNS_QUERY_IPV4)),
               pdns_result_list_is_from_cache(results, PDNS_QUERY_IPV4) ? "true" : "false");
        for (size_t i = 0; i < n; i++) {
            printf("  - %s\n", pdns_result_list_get(results, i));
        }
    } else {
        printf("[APP] resolve %s failed: %s\n", host, status.error_msg);
    }
    pdns_result_list_cleanup(results);

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
    printf("[APP] OK, Exit.\n");
    return 0;
}
