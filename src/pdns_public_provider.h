/*
 * 公共 DNS 提供者（内部）
 *
 * 与自建的差异（仅 4 处落在本文件，其余能力全在基类）：
 *   1. 内置默认 bootstrap 节点（223.5.5.5 等），自建无默认节点
 *   2. base_url 固定为服务域名，选中 IP 交由 CURLOPT_RESOLVE 注入（保留 SNI 校验）
 *   3. 支持 SRV 优选拉取（auto.sdk.alidns.com），自建无此能力
 *   4. 证书校验恒开启（无对外开关）
 */
#ifndef PDNS_PUBLIC_DNS_PROVIDER_H
#define PDNS_PUBLIC_DNS_PROVIDER_H

#include "pdns_base_provider.h"

#include <stddef.h>

/* 公共 DNS 服务域名：既是 HOST 兜底节点，也是 IP 直连时的 SNI/证书校验域名 */
#define PDNS_PUBLIC_RESOLVER_HOST "dns.alidns.com"

/* 公共 DNS 的重试预算，
 * 由 pdns_server_manager 计算 max_total_retry_count 时使用。
 * 与基类 PDNS_RETRY_COUNT 的区别：后者是「本 provider 内第几次起切 HOST 兜底」。 */
#define PDNS_PUBLIC_RETRY_COUNT 3

typedef struct {
    /* 必须是第一个成员：向上转型为 pdns_base_provider_t* / provider_t* 的前提 */
    pdns_base_provider_t base;
    bool is_temp_ip_expire;   /* 本次 SRV 优选是否因 serverTtl 过期触发 */
} pdns_public_provider_t;

/* 首成员布局契约：向上转型依赖 base 位于偏移 0，用编译期断言钉死 */
typedef char pdns_assert_public_base_offset[
    offsetof(pdns_public_provider_t, base) == 0 ? 1 : -1];

/*
 * 创建公共 DNS 提供者并装载默认 bootstrap 节点。
 * 鉴权需随后通过 pdns_public_provider_set_auth 配置。
 */
pdns_public_provider_t *pdns_public_provider_create(void);

void pdns_public_provider_destroy(pdns_public_provider_t *p);

/* 配置鉴权（三参数必填，缺一返回非 0）。 */
int pdns_public_provider_set_auth(pdns_public_provider_t *p,
                                      const char *account_id,
                                      const char *access_key_id,
                                      const char *access_key_secret);

/*
 * 合并服务端下发的 SRV 优选节点（内部自动补齐默认 bootstrap 节点）。
 * 即「下发节点 + 默认节点」合并。
 */
void pdns_public_provider_merge_server_list(pdns_public_provider_t *p,
                                                const char *const *v4, int v4_count,
                                                const char *const *v6, int v6_count,
                                                const char *const *host, int host_count,
                                                int ttl_sec, bool inherit_srtt);

/* 向上转型辅助（可读性优于到处写强制转换） */
static inline pdns_server_provider_t *
pdns_public_provider_as_provider(pdns_public_provider_t *p) {
    return (pdns_server_provider_t *) p;
}

static inline pdns_base_provider_t *
pdns_public_provider_as_base(pdns_public_provider_t *p) {
    return (pdns_base_provider_t *) p;
}

#endif /* PDNS_PUBLIC_DNS_PROVIDER_H */
