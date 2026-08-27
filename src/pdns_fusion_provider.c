/*
 * 自建 DNS 提供者实现
 */
#include "pdns_fusion_provider.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <apr_strings.h>   /* apr_pstrdup */

/* ---------------- vtable 实现 ---------------- */

static bool fusion_is_server_available(pdns_server_provider_t *self) {
    return pdns_base_provider_is_server_available((pdns_base_provider_t *) self);
}

static bool fusion_is_account_auth_available(pdns_server_provider_t *self) {
    return pdns_base_provider_is_account_auth_available((pdns_base_provider_t *) self);
}

static bool fusion_is_dns_provider_enabled(pdns_server_provider_t *self) {
    /* 启用条件：isAccountAuthAvailable && isServerAvailable。
     * 自建未 init 时既无节点也无鉴权，故此处自然为 false，不会进入 provider 组。 */
    return fusion_is_account_auth_available(self) && fusion_is_server_available(self);
}

static bool fusion_has_active_servers(pdns_server_provider_t *self,
                                      pdns_netstack_type_t stack, bool enable_ipv6) {
    return pdns_base_provider_has_active_servers((pdns_base_provider_t *) self,
                                                     stack, enable_ipv6);
}

/* 节点是否为 IPv6 字面量（含 ':' 即视为 IPv6，域名不含 ':'） */
static bool is_ipv6_literal(const char *s) {
    return (s != NULL) && (strchr(s, ':') != NULL);
}

int pdns_fusion_provider_build_base_url(pdns_fusion_provider_t *p,
                                            const char *node, bool using_https,
                                            char *out, size_t out_len) {
    if (p == NULL || node == NULL || node[0] == '\0' || out == NULL || out_len == 0) {
        return 1;
    }
    /* IPv6 字面量需用方括号包裹才能与端口共存 */
    int n = is_ipv6_literal(node)
                ? snprintf(out, out_len, "%s://[%s]:%d",
                           using_https ? "https" : "http", node, p->port)
                : snprintf(out, out_len, "%s://%s:%d",
                           using_https ? "https" : "http", node, p->port);
    return (n > 0 && (size_t) n < out_len) ? 0 : 1;
}

/*
 * 自建的 base_url 直接拼「选中节点 + 端口」：
 * 节点可能是 IP 也可能是私有域名，两者都直接作为 URL host，
 * 故不使用 CURLOPT_RESOLVE 注入（resolve_host / server_ip 置 NULL）。
 * IPv6 字面量需用方括号包裹才能与端口共存。
 */
static int fusion_get_server_url_with_request_count(pdns_server_provider_t *self,
                                                    int request_count,
                                                    pdns_netstack_type_t stack,
                                                    bool enable_ipv6,
                                                    bool using_https,
                                                    pdns_server_url_result_t *out) {
    pdns_fusion_provider_t *p    = (pdns_fusion_provider_t *) self;
    pdns_base_provider_t   *base = &p->base;

    bool        is_host = false;
    const char *ip      = pdns_base_provider_get_server_ip_with_request_count(
        base, stack, enable_ipv6, request_count, &is_host);

    /* HOST 兜底：自建的 host 列表存的是私有域名，需取出来直接作为 URL host
     * （公共 DNS 的 HOST 兜底是固定服务域名，无需取值，这是两者的又一处差异）。
     * 必须经由 alive_host_node 选取：直接取 host[0] 会选中已熔断的节点。 */
    const char *target = ip;
    if (target == NULL && is_host) {
        target = pdns_base_provider_alive_host_node(base);
    }
    if (target == NULL) {
        return 1;   /* 当前无可用节点 */
    }

    memset(out, 0, sizeof(*out));
    if (pdns_fusion_provider_build_base_url(p, target, using_https,
                                                out->base_url, sizeof(out->base_url)) != 0) {
        return 1;
    }
    /* 节点地址已在 URL 内，不做 IP 直连注入 */
    out->resolve_host = NULL;
    out->server_ip    = NULL;
    /* 但节点标识必须回传：否则上层无法对本次用的节点做 SRTT 更新与失败惩罚，
     * 重试时会反复选中同一个不可用节点（因为它的 srtt 永远停在未测量状态）。 */
    out->node_ip      = target;
    out->verify_cert  = p->enable_certificate_validation;
    out->source       = PDNS_SOURCE_FUSION_DNS;
    out->node_srtt    = pdns_base_provider_get_node_srtt(base, target);
    return 0;
}

static int fusion_get_url_path_with_domain(pdns_server_provider_t *self,
                                           const char *ascii_host, const char *type_str,
                                           const char *session_id, const char *ecs,
                                           bool enable_short, char *out, size_t out_len) {
    /* 签名算法与公共 DNS 完全一致（差异仅在「鉴权不全是否允许降级」，
     * 而鉴权不全的 provider 不会被启用，故无需在此分支）。 */
    return pdns_base_provider_build_auth_url_path((pdns_base_provider_t *) self,
                                                      ascii_host, type_str, session_id,
                                                      ecs, enable_short, out, out_len);
}

static const char *fusion_provider_name(pdns_server_provider_t *self) {
    (void) self;
    return "FusionDNS";
}

static const pdns_server_provider_vtbl_t g_fusion_vtbl = {
    fusion_is_dns_provider_enabled,
    fusion_is_server_available,
    fusion_is_account_auth_available,
    fusion_has_active_servers,
    fusion_get_server_url_with_request_count,
    fusion_get_url_path_with_domain,
    fusion_provider_name,
};

/* ---------------- 构造 / 析构 ---------------- */

pdns_fusion_provider_t *pdns_fusion_provider_create(void) {
    pdns_fusion_provider_t *p =
        (pdns_fusion_provider_t *) calloc(1, sizeof(pdns_fusion_provider_t));
    if (p == NULL) {
        return NULL;
    }
    /* 等价 [super init] */
    if (pdns_base_provider_init(&p->base, &g_fusion_vtbl) != 0) {
        free(p);
        return NULL;
    }
    p->port                          = PDNS_FUSION_DEFAULT_PORT;
    p->enable_certificate_validation = true;
    p->health_check_domain           = NULL;
    /* 不装载任何默认节点：自建地址必须由调用方显式传入 */
    return p;
}

void pdns_fusion_provider_destroy(pdns_fusion_provider_t *p) {
    if (p == NULL) {
        return;
    }
    /* health_check_domain 由 base->pool 分配，随基类析构一并回收 */
    pdns_base_provider_destroy(&p->base);
    free(p);
}

/* ---------------- 自建专属能力 ---------------- */

int pdns_fusion_provider_init_fusion_dns(pdns_fusion_provider_t *p,
                                             const char *const *server_ipv4_arr, int v4_count,
                                             const char *const *server_ipv6_arr, int v6_count,
                                             const char *const *server_host_arr, int host_count,
                                             int         port,
                                             const char *health_check_domain,
                                             const char *account_id,
                                             const char *access_key_id,
                                             const char *access_key_secret) {
    if (p == NULL) {
        return 1;
    }
    /* 三个地址数组至少一个非空 */
    bool has_any = (server_ipv4_arr != NULL && v4_count > 0) ||
                   (server_ipv6_arr != NULL && v6_count > 0) ||
                   (server_host_arr != NULL && host_count > 0);
    if (!has_any) {
        PDNS_LOGE("init fusion dns failed: server address is required");
        return 1;
    }
    /* 健康检查域名必填 */
    if (health_check_domain == NULL || health_check_domain[0] == '\0') {
        PDNS_LOGE("init fusion dns failed: health_check_domain is required");
        return 1;
    }
    /* 鉴权校验：先校验再落地，避免半配置状态。
     * ak / sk 必填；account_id 不属于调用方输入（自建不按账号区分调用方），
     * 为空时回退到 PDNS_FUSION_DEFAULT_ACCOUNT_ID。 */
    if (access_key_id == NULL || access_key_id[0] == '\0' ||
        access_key_secret == NULL || access_key_secret[0] == '\0') {
        PDNS_LOGE("init fusion dns failed: access_key_id / access_key_secret are required");
        return 1;
    }
    const char *uid = (account_id != NULL && account_id[0] != '\0')
                          ? account_id : PDNS_FUSION_DEFAULT_ACCOUNT_ID;

    if (pdns_base_provider_set_auth(&p->base, uid,
                                        access_key_id, access_key_secret) != 0) {
        return 1;
    }
    pdns_base_provider_setup_servers(&p->base,
                                         server_ipv4_arr, v4_count,
                                         server_ipv6_arr, v6_count,
                                         server_host_arr, host_count);
    p->port = (port > 0) ? port : PDNS_FUSION_DEFAULT_PORT;

    apr_thread_mutex_lock(p->base.lock);
    p->health_check_domain = apr_pstrdup(p->base.pool, health_check_domain);
    apr_thread_mutex_unlock(p->base.lock);

    PDNS_LOGI("fusion dns configured: v4=%d v6=%d host=%d port=%d hc_domain=%s uid=%s",
              v4_count, v6_count, host_count, p->port, health_check_domain, uid);
    return 0;
}

void pdns_fusion_provider_set_enable_certificate_validation(pdns_fusion_provider_t *p,
                                                                bool enable) {
    if (p == NULL) {
        return;
    }
    p->enable_certificate_validation = enable;
    if (!enable) {
        PDNS_LOGW("fusion dns certificate validation disabled "
                  "(test environment only, never in production)");
    }
}

const char *pdns_fusion_provider_get_health_check_domain(pdns_fusion_provider_t *p) {
    return (p != NULL) ? p->health_check_domain : NULL;
}

/* 去掉端口与方括号，便于与节点列表逐一比较。 */
static void clean_host(const char *host, char *out, size_t out_len) {
    if (host == NULL || out == NULL || out_len == 0) {
        return;
    }
    const char *start = host;
    size_t      len   = strlen(host);

    /* 形如 [2001:db8::1]:443 或 [2001:db8::1] */
    if (start[0] == '[') {
        const char *rb = strchr(start, ']');
        if (rb != NULL) {
            size_t n = (size_t) (rb - start - 1);
            if (n >= out_len) {
                n = out_len - 1;
            }
            memcpy(out, start + 1, n);
            out[n] = '\0';
            return;
        }
    }
    /* 形如 1.2.3.4:443（IPv6 裸写含多个 ':'，不能按端口截断） */
    const char *colon = strchr(start, ':');
    if (colon != NULL && strchr(colon + 1, ':') == NULL) {
        len = (size_t) (colon - start);
    }
    if (len >= out_len) {
        len = out_len - 1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
}

bool pdns_fusion_provider_is_host_in_fusion_dns(pdns_fusion_provider_t *p,
                                                    const char *host) {
    if (p == NULL || host == NULL || host[0] == '\0') {
        return false;
    }
    char clean[PDNS_IP_ADDRESS_STRING_LENGTH];
    clean[0] = '\0';
    clean_host(host, clean, sizeof(clean));
    if (clean[0] == '\0') {
        return false;
    }

    bool found = false;
    apr_thread_mutex_lock(p->base.lock);
    for (int i = 0; i < p->base.host_count && !found; i++) {
        found = (strcmp(p->base.host[i].ip, clean) == 0);
    }
    for (int i = 0; i < p->base.v4_count && !found; i++) {
        found = (strcmp(p->base.v4[i].ip, clean) == 0);
    }
    for (int i = 0; i < p->base.v6_count && !found; i++) {
        found = (strcmp(p->base.v6[i].ip, clean) == 0);
    }
    apr_thread_mutex_unlock(p->base.lock);
    return found;
}
