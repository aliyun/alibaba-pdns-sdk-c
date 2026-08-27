/*
 * 解析模块实现 —— 拼接服务端 URL + 复用 HTTP 传输层 + pdns_cJSON 解析
 *
 * 本层不负责寻址与签名：base_url / url_path / resolve_host / server_ip 均由
 * pdns_executor 从 pdns_server_manager 选中的 provider 取得后填入 req，
 * 使本层对「公共 DNS / 自建」两种来源完全无感。
 */
#include "pdns_resolver.h"
#include "pdns_log.h"
#include "pdns_http.h"
#include "pdns_reqstat.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "pdns_cjson.h"

/* ---------------- 内部辅助 ---------------- */

static pdns_status_t status_ok(void) {
    pdns_status_t s;
    memset(&s, 0, sizeof(s));
    s.code = PDNS_OK;
    return s;
}

static pdns_status_t status_err(int code, const char *msg) {
    pdns_status_t s;
    memset(&s, 0, sizeof(s));
    s.code = code;
    if (msg) {
        strncpy(s.error_msg, msg, PDNS_ERROR_MSG_LEN - 1);
    }
    return s;
}

/* query_type 映射已上提为 pdns_resolver.h 的 pdns_query_type_url_str（executor 也需要） */
#define query_type_url_str pdns_query_type_url_str

/* 判断 Answer 中记录 type 是否与查询类型匹配（每次请求均为单类型） */
static bool type_match(pdns_query_type_t qt, const char *ans_type) {
    if (ans_type == NULL) {
        return false;
    }
    switch (qt) {
        case PDNS_QUERY_IPV6:
            return strcmp(ans_type, "28") == 0;
        default:      /* AUTO / IPV4 */
            return strcmp(ans_type, "1") == 0;
    }
}

/* 解析 short 模式响应：纯 IP 字符串数组 ["1.2.3.4","5.6.7.8"]。
 * short 模式无服务端 TTL，统一使用 min_ttl；不支持否定缓存。 */
static void parse_short_answer(const char *body, pdns_result_list_t *out_ips,
                               int min_ttl, int *out_ttl) {
    pdns_cJSON *root = pdns_cJSON_Parse(body);
    if (root == NULL) {
        return;
    }
    if (pdns_cJSON_IsArray(root)) {
        int n = pdns_cJSON_GetArraySize(root);
        for (int i = 0; i < n; i++) {
            pdns_cJSON *item = pdns_cJSON_GetArrayItem(root, i);
            if (pdns_cJSON_IsString(item) && item->valuestring != NULL &&
                item->valuestring[0] != '\0') {
                pdns_result_list_add(out_ips, item->valuestring);
            }
        }
        if (out_ttl != NULL && pdns_result_list_size(out_ips) > 0) {
            *out_ttl = min_ttl;
        }
    }
    pdns_cJSON_Delete(root);
}

/* 读取 pdns_cJSON 节点为整数：数字直接取，字符串 atoi，其余返回 def */
static int json_int(const pdns_cJSON *node, int def) {
    if (pdns_cJSON_IsNumber(node)) {
        return node->valueint;
    }
    if (pdns_cJSON_IsString(node) && node->valuestring != NULL) {
        return atoi(node->valuestring);
    }
    return def;
}

/* 从 Authority 数组构造否定缓存 TTL：
 * 取 SOA 记录(type=6)中最短 TTL，无 SOA 用 60，最后钳制到 max_negative。 */
static int negative_ttl_from_authority(const pdns_cJSON *root, int max_negative) {
    const pdns_cJSON *authority = pdns_cJSON_GetObjectItem(root, "Authority");
    int neg_ttl = -1;
    if (pdns_cJSON_IsArray(authority)) {
        int n = pdns_cJSON_GetArraySize(authority);
        for (int i = 0; i < n; i++) {
            pdns_cJSON *item = pdns_cJSON_GetArrayItem(authority, i);
            int rtype = json_int(pdns_cJSON_GetObjectItem(item, "type"), -1);
            /* 否定缓存只取 SOA(type=6) 的 TTL，无 SOA 记录给默认 60 */
            int t = (rtype == 6) ? json_int(pdns_cJSON_GetObjectItem(item, "TTL"), 60) : 60;
            if (neg_ttl < 0 || t < neg_ttl) {
                neg_ttl = t;
            }
        }
    }
    if (neg_ttl < 0) {
        neg_ttl = 60;
    }
    if (neg_ttl > max_negative) {
        neg_ttl = max_negative;
    }
    return neg_ttl;
}

/* 解析标准响应 JSON：
 *   - 校验 Status：0=正常，3=NXDOMAIN
 *   - Status==0 且 Answer 有匹配类型记录：提取 IP，TTL 钳制到 [min_ttl, max_ttl]
 *   - 无匹配记录（NODATA）或 Status==3（NXDOMAIN）：按 Authority/SOA 建否定缓存
 */
static void parse_answer(const char *body, pdns_query_type_t qt, pdns_result_list_t *out_ips,
                         int min_ttl, int max_ttl, int max_negative,
                         int *out_ttl, bool *out_is_negative) {
    pdns_cJSON *root = pdns_cJSON_Parse(body);
    if (root == NULL) {
        return;
    }
    /* Status 缺失记为 -1（未知），不当作正常/否定处理（仅认 0/3） */
    int    status_val = json_int(pdns_cJSON_GetObjectItem(root, "Status"), -1);
    pdns_cJSON *answer      = pdns_cJSON_GetObjectItem(root, "Answer");
    bool   has_answer  = (status_val == 0 && pdns_cJSON_IsArray(answer));
    int    matched     = 0;

    if (has_answer) {
        int n = pdns_cJSON_GetArraySize(answer);
        for (int i = 0; i < n; i++) {
            pdns_cJSON *item = pdns_cJSON_GetArrayItem(answer, i);
            pdns_cJSON *data = pdns_cJSON_GetObjectItem(item, "data");

            /* type 可能是字符串或数字，统一转成字符串比较 */
            char        type_buf[16];
            const char *type_str = NULL;
            pdns_cJSON      *type      = pdns_cJSON_GetObjectItem(item, "type");
            if (pdns_cJSON_IsString(type)) {
                type_str = type->valuestring;
            } else if (pdns_cJSON_IsNumber(type)) {
                snprintf(type_buf, sizeof(type_buf), "%d", type->valueint);
                type_str = type_buf;
            }

            if (type_str != NULL && pdns_cJSON_IsString(data) && type_match(qt, type_str)) {
                pdns_result_list_add(out_ips, data->valuestring);
                matched++;
                /* 取首个匹配记录的 TTL，钳制到 [min_ttl, max_ttl] */
                if (out_ttl != NULL && *out_ttl <= 0) {
                    int ttl = json_int(pdns_cJSON_GetObjectItem(item, "TTL"), min_ttl);
                    if (ttl > max_ttl) {
                        ttl = max_ttl;
                    }
                    if (ttl < min_ttl) {
                        ttl = min_ttl;
                    }
                    *out_ttl = ttl;
                }
            }
        }
    }

    /* 否定缓存：Status==3（NXDOMAIN）或 Status==0 但无匹配记录（NODATA） */
    if (matched == 0 && max_negative > 0 && (status_val == 3 || has_answer)) {
        if (out_ttl != NULL) {
            *out_ttl = negative_ttl_from_authority(root, max_negative);
        }
        if (out_is_negative != NULL) {
            *out_is_negative = true;
        }
    }
    pdns_cJSON_Delete(root);
}

/* ---------------- 对外（模块内）入口 ---------------- */

pdns_status_t pdns_do_resolve(const pdns_resolve_req_t *req, pdns_result_list_t *out_ips,
                              int *out_ttl, long *out_rtt_ms, bool *out_is_negative,
                              long *out_conf_version) {
    if (out_ttl != NULL) {
        *out_ttl = 0;
    }
    if (out_rtt_ms != NULL) {
        *out_rtt_ms = 0;
    }
    if (out_is_negative != NULL) {
        *out_is_negative = false;
    }
    if (out_conf_version != NULL) {
        *out_conf_version = -1;
    }
    if (req == NULL || req->host == NULL || out_ips == NULL) {
        return status_err(1, "invalid argument");
    }
    /*
     * base_url / url_path 缺一即不可发请求。两者分别来自 provider 的
     * get_server_url_with_request_count 与 get_url_path_with_domain；后者在鉴权
     * 不全时会失败，因此本检查同时兼任「鉴权完整性」的最后一道防线。
     *
     * getUrlPathWithDomain 存在无签名分支，但被 isDNSProviderEnabled
     * （= isAccountAuthAvailable && isServerAvailable）前置拦截——鉴权不全时 Provider
     * 不启用、不参与调度，该分支为不可达的防御代码。
     */
    if (req->base_url == NULL || req->base_url[0] == '\0' ||
        req->url_path == NULL || req->url_path[0] == '\0') {
        return status_err(1, "incomplete server url or auth parameters");
    }

    /* 拼接完整 URL：base_url 与 url_path 已由 provider 分别完成寻址与签名。
     * 中文域名的 punycode 转换已在 executor 内完成（整个重试循环只需转一次），
     * 故本层的 req->host 仅用于日志与请求级统计的 key。 */
    char url[2048];
    snprintf(url, sizeof(url), "%s%s", req->base_url, req->url_path);

    /* 服务节点 IP（provider 选出）：
     *   - 非空：IP 直连（CURLOPT_RESOLVE，仅公共 DNS 走此路）
     *   - 为空：不做直连。两种情形：HOST 域名兜底（系统 DNS 解析服务域名），
     *     或自建——它的节点已直接拼在 base_url 里，无需注入 */
    const char *server_ip = (req->server_ip && req->server_ip[0]) ? req->server_ip : NULL;
    /* 日志用的目标描述：直连时打 IP；不直连时打 base_url——自建的节点就在
     * base_url 里，若一律打 "HOST" 会让人误以为走了系统 DNS 兜底。 */
    const char *server_log = server_ip ? server_ip : req->base_url;

    /* 通过统一 HTTP 传输层发起请求（连接池复用 + Date 头时间校正） */
    pdns_http_request_t  hreq;
    memset(&hreq, 0, sizeof(hreq));
    hreq.url              = url;
    hreq.resolve_host     = req->resolve_host;
    hreq.server_ip        = server_ip;
    hreq.using_https      = req->using_https;
    hreq.timeout_ms       = req->timeout_ms;
    hreq.use_http2        = req->use_http2;
    hreq.request_id       = req->request_id;
    hreq.skip_cert_verify = req->skip_cert_verify;

    /* 请求级统计头 c/ne/se：仅 IP 直连时按 (ip,host,qtype) 读取并消费。
     * HOST 域名兜底（server_ip=NULL）无具体节点，不带统计头。 */
    const char *qtype_str = query_type_url_str(req->query_type);
    char c_buf[16]  = {0};
    char ne_buf[16] = {0};
    char se_buf[16] = {0};
    if (server_ip != NULL) {
        int s_rtt = 0, s_ne = 0, s_se = 0;
        pdns_reqstat_take(server_ip, req->host, qtype_str, &s_rtt, &s_ne, &s_se);
        if (s_rtt > 0) {
            snprintf(c_buf, sizeof(c_buf), "%d", s_rtt);
            hreq.hdr_c = c_buf;
        }
        if (s_ne > 0) {
            snprintf(ne_buf, sizeof(ne_buf), "%d", s_ne);
            hreq.hdr_ne = ne_buf;
        }
        if (s_se > 0) {
            snprintf(se_buf, sizeof(se_buf), "%d", s_se);
            hreq.hdr_se = se_buf;
        }
    }

    pdns_http_response_t hresp;
    int rc = pdns_http_get(&hreq, &hresp);

    if (out_rtt_ms != NULL) {
        *out_rtt_ms = hresp.rtt_ms;
    }
    /* 回传响应头 Cv（服务端当前 ACL 版本），供上层驱动 conf 刷新 */
    if (out_conf_version != NULL) {
        *out_conf_version = hresp.conf_version;
    }

    /* 更新请求级统计（供下次 c/ne/se），仅 IP 直连有具体节点时：
     *   - 传输失败（rc!=0）→ 网络错误 ne+1
     *   - HTTP 200 → 成功，存 RTT（钳到 timeout）、清 ne
     *   - 其余状态码（5xx/401 等）→ 服务器错误 se+1 */
    if (server_ip != NULL) {
        if (rc != 0) {
            pdns_reqstat_on_net_error(server_ip, req->host, qtype_str);
        } else if (hresp.http_code == 200) {
            pdns_reqstat_on_success(server_ip, req->host, qtype_str,
                                    hresp.rtt_ms, req->timeout_ms);
        } else {
            pdns_reqstat_on_server_error(server_ip, req->host, qtype_str);
        }
    }

    pdns_status_t st;
    if (rc == 0 && hresp.body != NULL) {
        if (req->enable_short) {
            parse_short_answer(hresp.body, out_ips, req->min_ttl, out_ttl);
        } else {
            parse_answer(hresp.body, req->query_type, out_ips,
                         req->min_ttl, req->max_ttl, req->max_negative,
                         out_ttl, out_is_negative);
        }
        PDNS_LOGI("resolve ok: rid=%s scene=%s host=%s type=%s source=%s server=%s count=%zu%s",
                  req->request_id ? req->request_id : "-", pdns_scene_name(req->scene),
                  req->host, query_type_url_str(req->query_type),
                  pdns_source_name(req->source), server_log,
                  pdns_result_list_size(out_ips),
                  (out_is_negative && *out_is_negative) ? " (negative)" : "");
        st = status_ok();
    } else {
        PDNS_LOGW("resolve failed: rid=%s scene=%s host=%s type=%s source=%s server=%s",
                  req->request_id ? req->request_id : "-", pdns_scene_name(req->scene),
                  req->host, query_type_url_str(req->query_type),
                  pdns_source_name(req->source), server_log);
        st = status_err(2, "http request failed");
    }

    pdns_http_response_free(&hresp);
    return st;
}
