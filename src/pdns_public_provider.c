/*
 * 公共 DNS 提供者实现
 */
#include "pdns_public_provider.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* 默认 bootstrap 节点 */
static const char *PDNS_PUBLIC_DEFAULT_V4[]   = {"223.5.5.5", "223.6.6.6"};
static const char *PDNS_PUBLIC_DEFAULT_V6[]   = {"2400:3200::1", "2400:3200:baba::1"};
static const char *PDNS_PUBLIC_DEFAULT_HOST[] = {PDNS_PUBLIC_RESOLVER_HOST};

#define PUBLIC_DEF_V4_COUNT \
    ((int) (sizeof(PDNS_PUBLIC_DEFAULT_V4) / sizeof(PDNS_PUBLIC_DEFAULT_V4[0])))
#define PUBLIC_DEF_V6_COUNT \
    ((int) (sizeof(PDNS_PUBLIC_DEFAULT_V6) / sizeof(PDNS_PUBLIC_DEFAULT_V6[0])))
#define PUBLIC_DEF_HOST_COUNT \
    ((int) (sizeof(PDNS_PUBLIC_DEFAULT_HOST) / sizeof(PDNS_PUBLIC_DEFAULT_HOST[0])))

/* ---------------- vtable 实现 ---------------- */

static bool public_is_server_available(pdns_server_provider_t *self) {
    return pdns_base_provider_is_server_available((pdns_base_provider_t *) self);
}

static bool public_is_account_auth_available(pdns_server_provider_t *self) {
    return pdns_base_provider_is_account_auth_available((pdns_base_provider_t *) self);
}

static bool public_is_dns_provider_enabled(pdns_server_provider_t *self) {
    /* 启用条件：isAccountAuthAvailable && isServerAvailable */
    return public_is_account_auth_available(self) && public_is_server_available(self);
}

static bool public_has_active_servers(pdns_server_provider_t *self,
                                      pdns_netstack_type_t stack, bool enable_ipv6) {
    return pdns_base_provider_has_active_servers((pdns_base_provider_t *) self,
                                                     stack, enable_ipv6);
}

/*
 * 公共 DNS 的 base_url 固定为服务域名，选中节点通过 resolve_host + server_ip
 * 交由 CURLOPT_RESOLVE 注入：TCP 连 IP，TLS/SNI 仍按 dns.alidns.com 校验。
 * 本实现保留域名校验（不依赖证书 IP SAN）。
 */
static int public_get_server_url_with_request_count(pdns_server_provider_t *self,
                                                    int request_count,
                                                    pdns_netstack_type_t stack,
                                                    bool enable_ipv6,
                                                    bool using_https,
                                                    pdns_server_url_result_t *out) {
    pdns_base_provider_t *base = (pdns_base_provider_t *) self;

    bool        is_host = false;
    const char *ip      = pdns_base_provider_get_server_ip_with_request_count(
        base, stack, enable_ipv6, request_count, &is_host);

    /* 既没选到 IP 也不是 HOST 兜底 → 该 provider 当前无可用节点 */
    if (ip == NULL && !is_host) {
        return 1;
    }

    memset(out, 0, sizeof(*out));
    snprintf(out->base_url, sizeof(out->base_url), "%s://%s",
             using_https ? "https" : "http", PDNS_PUBLIC_RESOLVER_HOST);
    out->resolve_host = (ip != NULL) ? PDNS_PUBLIC_RESOLVER_HOST : NULL;
    out->server_ip    = ip;      /* NULL 表示 HOST 域名兜底，交由系统 DNS 解析 */
    /* 公共 DNS 上「节点标识」与「直连目标」恰好是同一个值；HOST 兜底时两者均为 NULL
     * （无具体节点，不参与 SRTT 记分）。 */
    out->node_ip      = ip;
    out->verify_cert  = true;    /* 公共 DNS 恒校验证书，无对外开关 */
    out->source       = PDNS_SOURCE_PUBLIC_DNS;
    out->node_srtt    = (ip != NULL)
        ? pdns_base_provider_get_node_srtt(base, ip) : 0.0f;
    return 0;
}

static int public_get_url_path_with_domain(pdns_server_provider_t *self,
                                           const char *ascii_host, const char *type_str,
                                           const char *session_id, const char *ecs,
                                           bool enable_short, char *out, size_t out_len) {
    return pdns_base_provider_build_auth_url_path((pdns_base_provider_t *) self,
                                                      ascii_host, type_str, session_id,
                                                      ecs, enable_short, out, out_len);
}

static const char *public_provider_name(pdns_server_provider_t *self) {
    (void) self;
    return "PublicDNS";
}

static const pdns_server_provider_vtbl_t g_public_vtbl = {
    public_is_dns_provider_enabled,
    public_is_server_available,
    public_is_account_auth_available,
    public_has_active_servers,
    public_get_server_url_with_request_count,
    public_get_url_path_with_domain,
    public_provider_name,
};

/* ---------------- 构造 / 析构 ---------------- */

pdns_public_provider_t *pdns_public_provider_create(void) {
    pdns_public_provider_t *p =
        (pdns_public_provider_t *) calloc(1, sizeof(pdns_public_provider_t));
    if (p == NULL) {
        return NULL;
    }
    /* 等价 [super init]：先初始化基类并绑定 vtable */
    if (pdns_base_provider_init(&p->base, &g_public_vtbl) != 0) {
        free(p);
        return NULL;
    }
    /* 装载默认 bootstrap 节点 */
    pdns_base_provider_setup_servers(&p->base,
                                         PDNS_PUBLIC_DEFAULT_V4, PUBLIC_DEF_V4_COUNT,
                                         PDNS_PUBLIC_DEFAULT_V6, PUBLIC_DEF_V6_COUNT,
                                         PDNS_PUBLIC_DEFAULT_HOST, PUBLIC_DEF_HOST_COUNT);
    return p;
}

void pdns_public_provider_destroy(pdns_public_provider_t *p) {
    if (p == NULL) {
        return;
    }
    pdns_base_provider_destroy(&p->base);
    free(p);
}

/* ---------------- 公共 DNS 专属能力 ---------------- */

int pdns_public_provider_set_auth(pdns_public_provider_t *p,
                                      const char *account_id,
                                      const char *access_key_id,
                                      const char *access_key_secret) {
    if (p == NULL) {
        return 1;
    }
    int rc = pdns_base_provider_set_auth(&p->base, account_id,
                                             access_key_id, access_key_secret);
    if (rc == 0) {
        PDNS_LOGI("public dns provider auth configured: uid=%s ak=%s",
                  account_id, access_key_id);
    }
    return rc;
}

void pdns_public_provider_merge_server_list(pdns_public_provider_t *p,
                                                const char *const *v4, int v4_count,
                                                const char *const *v6, int v6_count,
                                                const char *const *host, int host_count,
                                                int ttl_sec, bool inherit_srtt) {
    if (p == NULL) {
        return;
    }
    /* 下发节点在前、默认 bootstrap 节点在后（去重） */
    pdns_base_provider_merge_server_list(&p->base,
                                             v4, v4_count, v6, v6_count, host, host_count,
                                             PDNS_PUBLIC_DEFAULT_V4, PUBLIC_DEF_V4_COUNT,
                                             PDNS_PUBLIC_DEFAULT_V6, PUBLIC_DEF_V6_COUNT,
                                             PDNS_PUBLIC_DEFAULT_HOST, PUBLIC_DEF_HOST_COUNT,
                                             ttl_sec, inherit_srtt);
}
