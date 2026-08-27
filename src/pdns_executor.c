/*
 * 带重试的 HTTPDNS 请求执行器实现
 *
 * 多服务器 failover 重试循环的实现。
 */
#include "pdns_executor.h"
#include "pdns_base_provider.h"
#include "pdns_idn.h"
#include "pdns_log.h"

#include <stdio.h>
#include <string.h>

/* 跳过 URL scheme（"https://"），日志只显示域名部分 */
static inline const char *strip_scheme(const char *url) {
    const char *p = strstr(url, "://");
    return p ? (p + 3) : url;
}

pdns_status_t pdns_execute_resolve_with_retry(pdns_server_manager_t *manager,
                                              pdns_netstack_type_t stack,
                                              bool enable_ipv6,
                                              pdns_resolve_req_t *req,
                                              pdns_result_list_t *out,
                                              int *out_ttl,
                                              bool *out_is_negative,
                                              long *out_conf_version) {
    pdns_status_t st;
    memset(&st, 0, sizeof(st));
    st.code = 2;
    strncpy(st.error_msg, "resolve failed", PDNS_ERROR_MSG_LEN - 1);

    int  ttl          = 0;
    bool is_negative  = false;
    long conf_version = -1;

    const char *type_str = pdns_query_type_url_str(req->query_type);

    /* 无任何可用 provider（未配置，或全部 provider 在当前网络栈下无可调度节点）：
     * 直接失败，不进入循环（maxTotalRetryCount()==0 时不发请求）。 */
    int max_total = pdns_server_manager_max_total_retry_count(manager, stack,
                                                                  enable_ipv6);
    if (max_total <= 0) {
        PDNS_LOGW("resolve abort: rid=%s host=%s no available dns server",
                  req->request_id ? req->request_id : "-", req->host);
        strncpy(st.error_msg, "no available dns server", PDNS_ERROR_MSG_LEN - 1);
        return st;
    }

    /* 中文域名转 punycode（用时转）：请求 URL 的 name= 与签名 content 均用
     * 转换后的 ASCII 域名。整个重试循环只需转一次，故放在循环外；
     * 转换失败尽力而为，回退原始 host 继续。
     * 注：缓存 key / 黑白名单 ACL / 回调 / 失败计数 key 仍用原始域名（不经本转换）。 */
    char ascii_host[256];
    if (!pdns_idn_to_ascii(req->host, ascii_host, sizeof(ascii_host))) {
        PDNS_LOGW("idn convert failed, use original host: %s", req->host);
    }

    /* 总尝试次数 = max_total + 1，多出的 1 次是末尾的 HOST 域名兜底 */
    int total_attempts = max_total + 1;

    for (int attempt = 0; attempt < total_attempts; attempt++) {
        /* 向 manager 索取本次的服务端地址：内部完成主备降级决策，
         * 再由选中的 provider 完成「优选节点 → HOST 兜底」的选点 */
        pdns_server_url_result_t     url_res;
        pdns_server_provider_t  *provider = NULL;
        memset(&url_res, 0, sizeof(url_res));
        if (pdns_server_manager_get_server_url_with_request_count(
                manager, attempt, req->host, type_str, req->request_id,
                stack, enable_ipv6, req->using_https, &url_res, &provider) != 0) {
            /* 主备均无可用节点：后续尝试也不会有，提前结束 */
            PDNS_LOGW("resolve abort: rid=%s host=%s attempt=%d no server url",
                      req->request_id ? req->request_id : "-", req->host, attempt);
            strncpy(st.error_msg, "no available dns server", PDNS_ERROR_MSG_LEN - 1);
            break;
        }

        /* 鉴权 path 每次尝试重新生成：ts 与签名随时间变化，且降级后 provider 可能已换 */
        char url_path[PDNS_URL_PATH_MAX_LEN];
        if (pdns_provider_get_url_path_with_domain(provider, ascii_host, type_str,
                                                   req->session_id, req->ecs,
                                                   req->enable_short,
                                                   url_path, sizeof(url_path)) != 0) {
            PDNS_LOGW("resolve abort: rid=%s host=%s provider=%s build url path failed",
                      req->request_id ? req->request_id : "-", req->host,
                      pdns_provider_name(provider));
            strncpy(st.error_msg, "incomplete auth parameters", PDNS_ERROR_MSG_LEN - 1);
            break;
        }

        req->base_url         = url_res.base_url;
        req->url_path         = url_path;
        req->resolve_host     = url_res.resolve_host;
        req->server_ip        = url_res.server_ip;   /* NULL 时不做直连 */
        req->skip_cert_verify = !url_res.verify_cert;
        req->source           = url_res.source;      /* 日志用；返回后即末次实际来源 */

        ttl          = 0;
        is_negative  = false;
        conf_version = -1;
        long rtt_ms = 0;

        const char *node_label = url_res.node_ip ? url_res.node_ip : strip_scheme(url_res.base_url);

        PDNS_LOGI("resolve [%d/%d]: rid=%s host=%s type=%s scene=%s source=%s node=%s srtt=%.1f",
                  attempt + 1, total_attempts,
                  req->request_id ? req->request_id : "-", req->host,
                  type_str, pdns_scene_name(req->scene),
                  pdns_source_name(url_res.source),
                  node_label, url_res.node_srtt);

        st = pdns_do_resolve(req, out, &ttl, &rtt_ms, &is_negative, &conf_version);

        /* SRTT 与惩罚一律按 node_ip（本次选中的节点）归属，而不是 server_ip：
         * 自建的 server_ip 恒为 NULL（节点已在 base_url 里），用它判断会导致自建从不记分、从不惩罚，重试永远死活同一个节点。
         * HOST 域名兜底时 node_ip 为 NULL（无具体节点），自然跳过。 */
        pdns_base_provider_t *base = pdns_base_of(provider);
        if (pdns_status_is_ok(&st)) {
            if (url_res.node_ip != NULL) {
                pdns_base_provider_update_srtt(base, url_res.node_ip, rtt_ms);
                pdns_server_manager_update_consecutive_success(manager, provider,
                                                                   url_res.node_ip);
            }
            pdns_server_manager_on_request_success(manager, req->host, type_str,
                                                       req->request_id);
            PDNS_LOGI("resolve [%d/%d] success: rid=%s host=%s type=%s scene=%s source=%s node=%s srtt=%.1f rtt=%ldms",
                      attempt + 1, total_attempts,
                      req->request_id ? req->request_id : "-", req->host,
                      type_str, pdns_scene_name(req->scene),
                      pdns_source_name(url_res.source),
                      node_label, url_res.node_srtt, rtt_ms);
            break;
        }

        PDNS_LOGW("resolve [%d/%d] failed: rid=%s host=%s type=%s scene=%s source=%s node=%s srtt=%.1f",
                  attempt + 1, total_attempts,
                  req->request_id ? req->request_id : "-", req->host,
                  type_str, pdns_scene_name(req->scene),
                  pdns_source_name(url_res.source),
                  node_label, url_res.node_srtt);
        if (url_res.node_ip != NULL) {
            pdns_base_provider_punish(base, url_res.node_ip);
            pdns_server_manager_update_consecutive_failure(manager, provider,
                                                               url_res.node_ip);
        }
        /* 累加失败计数：达到 fallback_threshold 后，下一轮 manager 自动切备用 provider */
        pdns_server_manager_on_request_failure(manager, req->host, type_str,
                                                   req->request_id);
    }

    /* 无条件清理本次请求的失败计数。
     * 成功路径上 on_request_success 已清过一次，这里重复调用是幂等的；
     * 之所以放在函数出口而非仅「重试用尽」分支，是为了保证任何提前 break
     * （无可用节点 / 鉴权失败）也不会把计数残留在表里。 */
    pdns_server_manager_on_request_finish(manager, req->host, type_str,
                                              req->request_id);

    if (out_ttl != NULL) {
        *out_ttl = ttl;
    }
    if (out_is_negative != NULL) {
        *out_is_negative = is_negative;
    }
    if (out_conf_version != NULL) {
        *out_conf_version = conf_version;
    }
    return st;
}
