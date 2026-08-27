/*
 * DNS 服务节点健康检查实现
 */
#include "pdns_health_checker.h"
#include "pdns_base_provider.h"
#include "pdns_resolver.h"   /* pdns_query_type_url_str */
#include "pdns_http.h"
#include "pdns_log.h"

#include <stdio.h>
#include <string.h>

/* 探测请求的 HTTP 成功判定：仅 200 视为节点已恢复。
 * 4xx/5xx 说明节点虽可连通但服务异常，不应放回调度池。 */
#define PDNS_HEALTH_CHECK_OK_CODE 200

bool pdns_health_check_probe_node(pdns_fusion_provider_t *fusion,
                                  const char *node,
                                  pdns_query_type_t query_type,
                                  const char *session_id,
                                  int timeout_ms,
                                  bool using_https) {
    if (fusion == NULL || node == NULL || node[0] == '\0') {
        return false;
    }
    const char *probe_domain = pdns_fusion_provider_get_health_check_domain(fusion);
    if (probe_domain == NULL || probe_domain[0] == '\0') {
        return false;   /* 无探测域名即熔断功能关闭 */
    }

    pdns_server_provider_t *prov = pdns_fusion_provider_as_provider(fusion);

    /* 鉴权 path：与正常解析同一套签名实现，只是域名换成探测域名 */
    char url_path[PDNS_URL_PATH_MAX_LEN];
    if (pdns_provider_get_url_path_with_domain(prov, probe_domain,
                                               pdns_query_type_url_str(query_type),
                                               session_id, NULL, false,
                                               url_path, sizeof(url_path)) != 0) {
        PDNS_LOGW("health check skip: node=%s build auth path failed", node);
        return false;
    }

    /* base_url 绕过选点直指该节点，复用 provider 的拼接规则（端口 / IPv6 方括号） */
    char base_url[PDNS_BASE_URL_MAX_LEN];
    if (pdns_fusion_provider_build_base_url(fusion, node, using_https,
                                                base_url, sizeof(base_url)) != 0) {
        PDNS_LOGW("health check skip: node=%s build base url failed", node);
        return false;
    }

    char url[2048];
    snprintf(url, sizeof(url), "%s%s", base_url, url_path);

    pdns_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.url         = url;
    req.using_https = using_https;
    req.timeout_ms  = timeout_ms;
    /* 自建节点已在 URL 内，不做 CURLOPT_RESOLVE 直连注入（同正常解析路径） */
    req.resolve_host = NULL;
    req.server_ip    = NULL;
    /* 证书校验沿用调用方对自建的设置：探测与正常请求走同样的信任策略，
     * 否则自签部署下探测会恒失败、节点永不恢复。 */
    req.skip_cert_verify = !fusion->enable_certificate_validation;

    pdns_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    int  rc      = pdns_http_get(&req, &resp);
    bool success = (rc == 0) && (resp.http_code == PDNS_HEALTH_CHECK_OK_CODE);

    PDNS_LOGD("health check probe: node=%s domain=%s http=%ld rtt=%ldms -> %s",
              node, probe_domain, resp.http_code, resp.rtt_ms,
              success ? "OK" : "FAIL");

    pdns_http_response_free(&resp);
    return success;
}

int pdns_health_check_run(pdns_fusion_provider_t *fusion,
                          pdns_netstack_type_t stack,
                          const char *session_id,
                          int timeout_ms,
                          bool using_https) {
    if (fusion == NULL) {
        return 0;
    }
    /* 前置条件 1：provider 未启用（未配置自建 / 鉴权不全）则整轮跳过 */
    if (!pdns_provider_is_dns_provider_enabled(
            pdns_fusion_provider_as_provider(fusion))) {
        return 0;
    }
    /* 前置条件 2：探测域名为空等价于熔断关闭 */
    const char *probe_domain = pdns_fusion_provider_get_health_check_domain(fusion);
    if (probe_domain == NULL || probe_domain[0] == '\0') {
        return 0;
    }

    pdns_base_provider_t *base = pdns_fusion_provider_as_base(fusion);

    /* 快照已熔断节点后再逐个探测：不在持锁状态下发网络请求 */
    char broken[PDNS_HEALTH_CHECK_MAX_NODES][PDNS_IP_ADDRESS_STRING_LENGTH];
    int  n = pdns_base_provider_collect_broken_nodes(
        base, stack, broken, PDNS_HEALTH_CHECK_MAX_NODES);
    if (n <= 0) {
        return 0;   /* 无熔断节点：不产生任何网络请求 */
    }

    PDNS_LOGI("health check start: %d broken node(s), domain=%s", n, probe_domain);

    int recovered = 0;
    for (int i = 0; i < n; i++) {
        /* 按被探测节点的地址族选择查询类型：IPv6 节点用 AAAA，其余用 A。
         * 私有域名（host 类型，不含 ':'）按 A 处理。 */
        pdns_query_type_t qtype = (strchr(broken[i], ':') != NULL)
                                      ? PDNS_QUERY_IPV6
                                      : PDNS_QUERY_IPV4;
        bool ok = pdns_health_check_probe_node(fusion, broken[i], qtype,
                                              session_id, timeout_ms, using_https);
        if (pdns_base_provider_record_probe_result(base, broken[i], ok)) {
            recovered++;
        }
    }

    PDNS_LOGI("health check done: probed=%d recovered=%d", n, recovered);
    return recovered;
}
