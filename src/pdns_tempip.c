/*
 * 服务 IP 优选拉取模块实现 —— 拉取 SRV 优选记录 + 分类解析 + 合并写回 provider
 */
#include "pdns_tempip.h"
#include "pdns_http.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "pdns_cjson.h"

/* 优选拉取固定接口（uid=9999 且无签名）。
 * 该接口不走 provider 的 get_url_path_with_domain（那是带签名的解析 path），
 * 只向 provider 索取 base_url 与寻址信息。 */
#define PDNS_TEMPIP_QUERY         "/resolve?name=auto.sdk.alidns.com&type=SRV&uid=9999"

/* SRV target 分类后缀 */
#define PDNS_SUFFIX_IPV4          ".ipv4."
#define PDNS_SUFFIX_IPV6          ".ipv6."
#define PDNS_SUFFIX_DOMAIN        ".domain."

/* 每类型最多收集的下发节点数 */
#define PDNS_TEMPIP_MAX_PER_TYPE  16

/* 否定/Authority TTL 上限 */
#define PDNS_TEMPIP_MAX_NEG       3600

typedef struct {
    char v4[PDNS_TEMPIP_MAX_PER_TYPE][PDNS_IP_ADDRESS_STRING_LENGTH];
    int  v4_count;
    char v6[PDNS_TEMPIP_MAX_PER_TYPE][PDNS_IP_ADDRESS_STRING_LENGTH];
    int  v6_count;
    char host[PDNS_TEMPIP_MAX_PER_TYPE][PDNS_IP_ADDRESS_STRING_LENGTH];
    int  host_count;
    int  ttl;            /* 首个下发记录的 TTL，用作 serverTtl */
    int  authority_ttl;  /* 无下发 IP 时取 Authority SOA(type=6) TTL（钳到 3600），用作重试间隔 */
} pdns_tempip_set_t;

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

/* s 是否以 suffix 结尾 */
static bool ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s);
    size_t lf = strlen(suffix);
    return ls >= lf && strcmp(s + (ls - lf), suffix) == 0;
}

/* 取 data 字符串以空格分隔的第 4 个 token（index=3）。
 * 未达 4 个 token 返回 NULL；否则将 target 拷入 out（不含首尾空格）。 */
static const char *srv_target_token(const char *data, char *out, size_t out_len) {
    int    idx = 0;
    const char *p = data;
    while (*p) {
        /* 跳过前导空格 */
        while (*p == ' ') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        const char *start = p;
        while (*p != ' ' && *p != '\0') {
            p++;
        }
        if (idx == 3) {
            size_t n = (size_t) (p - start);
            if (n >= out_len) {
                n = out_len - 1;
            }
            memcpy(out, start, n);
            out[n] = '\0';
            return out;
        }
        idx++;
    }
    return NULL;
}

/* 追加一个 IP/域名到对应类型数组（去后缀后的字符串） */
static void set_add(char arr[][PDNS_IP_ADDRESS_STRING_LENGTH], int *count, const char *val) {
    if (*count >= PDNS_TEMPIP_MAX_PER_TYPE || val == NULL || val[0] == '\0') {
        return;
    }
    strncpy(arr[*count], val, PDNS_IP_ADDRESS_STRING_LENGTH - 1);
    arr[*count][PDNS_IP_ADDRESS_STRING_LENGTH - 1] = '\0';
    (*count)++;
}

/* 去掉 target 的分类后缀，写入 out（不含尾部 suffix） */
static void strip_suffix(const char *target, const char *suffix, char *out, size_t out_len) {
    size_t lt = strlen(target);
    size_t lf = strlen(suffix);
    size_t n  = (lt >= lf) ? (lt - lf) : 0;
    if (n >= out_len) {
        n = out_len - 1;
    }
    memcpy(out, target, n);
    out[n] = '\0';
}

/* 将 IPv6 target 中的 '-' 还原为 ':' */
static void dash_to_colon(char *s) {
    for (; *s; s++) {
        if (*s == '-') {
            *s = ':';
        }
    }
}

/* 从 Authority 数组取 SOA(type=6) 的 TTL（钳到 3600）写入 set->authority_ttl */
static void parse_authority_soa(const pdns_cJSON *root, pdns_tempip_set_t *set) {
    const pdns_cJSON *authority = pdns_cJSON_GetObjectItem(root, "Authority");
    if (!pdns_cJSON_IsArray(authority)) {
        return;
    }
    int n = pdns_cJSON_GetArraySize(authority);
    for (int i = 0; i < n; i++) {
        pdns_cJSON *item = pdns_cJSON_GetArrayItem(authority, i);
        pdns_cJSON *type = pdns_cJSON_GetObjectItem(item, "type");
        int    rtype = pdns_cJSON_IsNumber(type) ? type->valueint
                       : (pdns_cJSON_IsString(type) && type->valuestring ? atoi(type->valuestring) : -1);
        if (rtype != 6) {   /* 否定缓存只取 SOA(type=6) */
            continue;
        }
        pdns_cJSON *ttl = pdns_cJSON_GetObjectItem(item, "TTL");
        int    t = pdns_cJSON_IsNumber(ttl) ? ttl->valueint
                   : (pdns_cJSON_IsString(ttl) && ttl->valuestring ? atoi(ttl->valuestring) : 0);
        if (t > PDNS_TEMPIP_MAX_NEG) {
            t = PDNS_TEMPIP_MAX_NEG;
        }
        if (t > 0) {
            set->authority_ttl = t;
        }
    }
}

/* 解析 SRV 响应，按后缀分类填充 set：
 *   - Status==0 且有 Answer：提取优选节点
 *   - Status==0 无 Answer 或 Status==3（NXDOMAIN）：取 Authority SOA TTL 作重试间隔 */
static void parse_srv(const char *body, pdns_tempip_set_t *set) {
    pdns_cJSON *root = pdns_cJSON_Parse(body);
    if (root == NULL) {
        return;
    }
    pdns_cJSON *status = pdns_cJSON_GetObjectItem(root, "Status");
    int    status_val = -1;
    if (pdns_cJSON_IsNumber(status)) {
        status_val = status->valueint;
    } else if (pdns_cJSON_IsString(status) && status->valuestring != NULL) {
        status_val = atoi(status->valuestring);
    }

    pdns_cJSON *answer = pdns_cJSON_GetObjectItem(root, "Answer");
    if (status_val == 0 && pdns_cJSON_IsArray(answer)) {
        int n = pdns_cJSON_GetArraySize(answer);
        for (int i = 0; i < n; i++) {
            pdns_cJSON *item = pdns_cJSON_GetArrayItem(answer, i);
            pdns_cJSON *data = pdns_cJSON_GetObjectItem(item, "data");
            if (!pdns_cJSON_IsString(data) || data->valuestring == NULL) {
                continue;
            }
            /* 记录首个 TTL 作为 serverTtl */
            if (set->ttl <= 0) {
                pdns_cJSON *ttl = pdns_cJSON_GetObjectItem(item, "TTL");
                if (pdns_cJSON_IsNumber(ttl)) {
                    set->ttl = ttl->valueint;
                } else if (pdns_cJSON_IsString(ttl) && ttl->valuestring != NULL) {
                    set->ttl = atoi(ttl->valuestring);
                }
            }

            char target[PDNS_IP_ADDRESS_STRING_LENGTH];
            if (srv_target_token(data->valuestring, target, sizeof(target)) == NULL) {
                continue;   /* token 不足 4 个，非合法 SRV target */
            }

            char val[PDNS_IP_ADDRESS_STRING_LENGTH];
            if (ends_with(target, PDNS_SUFFIX_IPV6)) {
                strip_suffix(target, PDNS_SUFFIX_IPV6, val, sizeof(val));
                dash_to_colon(val);
                set_add(set->v6, &set->v6_count, val);
            } else if (ends_with(target, PDNS_SUFFIX_IPV4)) {
                strip_suffix(target, PDNS_SUFFIX_IPV4, val, sizeof(val));
                set_add(set->v4, &set->v4_count, val);
            } else if (ends_with(target, PDNS_SUFFIX_DOMAIN)) {
                strip_suffix(target, PDNS_SUFFIX_DOMAIN, val, sizeof(val));
                set_add(set->host, &set->host_count, val);
            }
        }
    } else if (status_val == 0 || status_val == 3) {
        /* 无 Answer（NODATA）或 NXDOMAIN：取 Authority SOA TTL */
        parse_authority_soa(root, set);
    }
    pdns_cJSON_Delete(root);
}

/* 将定长二维数组转成 const char* 指针表（供 provider 合并接口） */
static void to_ptr_array(char arr[][PDNS_IP_ADDRESS_STRING_LENGTH], int count,
                         const char *ptrs[]) {
    for (int i = 0; i < count; i++) {
        ptrs[i] = arr[i];
    }
}

pdns_status_t pdns_tempip_fetch(pdns_public_provider_t *provider,
                                pdns_netstack_type_t stack,
                                bool enable_ipv6,
                                bool using_https,
                                int timeout_ms,
                                bool is_expire) {
    if (provider == NULL) {
        return status_err(1, "invalid argument");
    }

    pdns_base_provider_t   *base = pdns_public_provider_as_base(provider);
    pdns_server_provider_t *prov = pdns_public_provider_as_provider(provider);

    /* 向 provider 索取服务端地址（request_count=0 即首选优节点；server_ip 为 NULL
     * 时走 HOST 域名兜底，由系统 DNS 解析服务域名） */
    pdns_server_url_result_t url_res;
    memset(&url_res, 0, sizeof(url_res));
    if (pdns_provider_get_server_url_with_request_count(prov, 0, stack, enable_ipv6,
                                                        using_https, &url_res) != 0) {
        PDNS_LOGW("tempip fetch skipped: no available node");
        pdns_base_provider_touch_server_expire(base, 60);
        return status_err(2, "no available dns server");
    }

    char url[512];
    snprintf(url, sizeof(url), "%s%s", url_res.base_url, PDNS_TEMPIP_QUERY);

    pdns_http_request_t hreq;
    memset(&hreq, 0, sizeof(hreq));
    hreq.url              = url;
    hreq.resolve_host     = url_res.resolve_host;
    hreq.server_ip        = url_res.server_ip;   /* NULL 时不直连，走 HOST 域名兜底 */
    hreq.using_https      = using_https;
    hreq.timeout_ms       = timeout_ms;
    hreq.skip_cert_verify = !url_res.verify_cert;

    pdns_http_response_t hresp;
    int rc = pdns_http_get(&hreq, &hresp);

    if (rc != 0 || hresp.body == NULL || hresp.http_code != 200) {
        PDNS_LOGW("tempip fetch failed: server=%s http=%ld",
                  url_res.server_ip ? url_res.server_ip : "HOST", hresp.http_code);
        pdns_http_response_free(&hresp);
        /* 拉取失败：短暂节流后允许重试（不改动现有节点列表） */
        pdns_base_provider_touch_server_expire(base, 60);
        return status_err(2, "tempip http request failed");
    }

    pdns_tempip_set_t set;
    memset(&set, 0, sizeof(set));
    parse_srv(hresp.body, &set);
    pdns_http_response_free(&hresp);

    if (set.v4_count == 0 && set.v6_count == 0 && set.host_count == 0) {
        /* 无下发优选节点：用 Authority SOA TTL 作重试间隔，无则默认 60s */
        int retry = set.authority_ttl > 0 ? set.authority_ttl : 60;
        PDNS_LOGI("tempip fetch: no server nodes issued, keep defaults, retry in %ds", retry);
        pdns_base_provider_touch_server_expire(base, retry);
        return status_ok();
    }

    const char *v4p[PDNS_TEMPIP_MAX_PER_TYPE];
    const char *v6p[PDNS_TEMPIP_MAX_PER_TYPE];
    const char *hostp[PDNS_TEMPIP_MAX_PER_TYPE];
    to_ptr_array(set.v4, set.v4_count, v4p);
    to_ptr_array(set.v6, set.v6_count, v6p);
    to_ptr_array(set.host, set.host_count, hostp);

    /* is_expire=true（TTL 过期刷新）继承 SRTT；否则（首次/网络切换）归零。
     * 默认 bootstrap 节点的补齐在 public provider 内部完成。 */
    pdns_public_provider_merge_server_list(provider, v4p, set.v4_count,
                                              v6p, set.v6_count,
                                              hostp, set.host_count,
                                              set.ttl, is_expire);
    return status_ok();
}
