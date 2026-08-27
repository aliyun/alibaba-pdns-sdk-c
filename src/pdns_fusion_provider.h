/*
 * 自建 DNS 提供者（内部）
 *
 * 与公共 DNS 的差异（仅 4 处落在本文件，其余能力全在基类）：
 *   1. 无内置默认节点，全部由调用方通过 init 传入（至少一个地址数组非空）
 *   2. base_url 直接拼「选中节点 + 自定义端口」，不做 CURLOPT_RESOLVE 注入；
 *      IPv6 节点自动加方括号
 *   3. 无 SRV 优选拉取能力
 *   4. 提供证书校验开关（自签证书的私有化部署可关，仅限测试环境）
 *
 * 另需 health_check_domain：熔断后由健康检查定时器用它探测节点是否恢复。
 */
#ifndef PDNS_FUSION_DNS_PROVIDER_H
#define PDNS_FUSION_DNS_PROVIDER_H

#include "pdns_base_provider.h"

#include <stddef.h>

/* 自建默认端口 */
#define PDNS_FUSION_DEFAULT_PORT 443

/* 自建的重试预算，
 * 由 pdns_server_manager 计算 max_total_retry_count 时使用。 */
#define PDNS_FUSION_RETRY_COUNT 3

/*
 * 自建的固定 account_id。
 *
 * 自建服务不按阿里云账号维度区分调用方（服务本身就部署在集成方侧），故
 * uid 不由调用方传入：对外 pdns_client_init_fusion_dns 不收 account_id，由 pdns_api
 * 传本常量；本层仍保留 account_id 形参（与基类鉴权模型一致，也便于未来服务端
 * 真需要区分账号时无需改结构），传空时自动回退到本常量。
 */
#define PDNS_FUSION_DEFAULT_ACCOUNT_ID "1"

typedef struct {
    /* 必须是第一个成员：向上转型为 pdns_base_provider_t* / provider_t* 的前提 */
    pdns_base_provider_t base;
    int   port;                             /* 服务端口，默认 443 */
    bool  enable_certificate_validation;    /* 是否校验服务端证书，默认 true */
    char *health_check_domain;              /* 熔断恢复探测域名（必填，由 pool 持有） */
} pdns_fusion_provider_t;

/* 首成员布局契约：向上转型依赖 base 位于偏移 0，用编译期断言钉死 */
typedef char pdns_assert_fusion_base_offset[
    offsetof(pdns_fusion_provider_t, base) == 0 ? 1 : -1];

/* 创建自建提供者（不含任何节点与鉴权，须随后 init）。 */
pdns_fusion_provider_t *pdns_fusion_provider_create(void);

void pdns_fusion_provider_destroy(pdns_fusion_provider_t *p);

/*
 * 初始化自建 DNS。
 * 校验规则见下，任一不满足即返回非 0 且不改动现有状态：
 *   - 三个地址数组至少一个非空
 *   - health_check_domain 必填
 *   - access_key_id / access_key_secret 必填
 * @param[in] port <=0 时取默认 443
 * @param[in] account_id 为空时取 PDNS_FUSION_DEFAULT_ACCOUNT_ID；
 *                       对外 API 不暴露此参数，由 pdns_api 传入固定值
 */
int pdns_fusion_provider_init_fusion_dns(pdns_fusion_provider_t *p,
                                             const char *const *server_ipv4_arr, int v4_count,
                                             const char *const *server_ipv6_arr, int v6_count,
                                             const char *const *server_host_arr, int host_count,
                                             int         port,
                                             const char *health_check_domain,
                                             const char *account_id,
                                             const char *access_key_id,
                                             const char *access_key_secret);

/* 证书校验开关（默认 true，仅对自建生效） */
void pdns_fusion_provider_set_enable_certificate_validation(pdns_fusion_provider_t *p,
                                                                bool enable);

/* 熔断恢复探测域名（健康检查使用）；未配置返回 NULL */
const char *pdns_fusion_provider_get_health_check_domain(pdns_fusion_provider_t *p);

/*
 * 为指定节点拼接 base_url（scheme + 节点 + 端口，IPv6 自动加方括号）。
 * 选点路径与健康检查共用本函数：后者需绕过选点直探指定的已熔断节点，
 * 两处拼接规则必须一致，故只保留一份实现。
 * @return 0 成功；非 0 表示参数无效或缓冲不足。
 */
int pdns_fusion_provider_build_base_url(pdns_fusion_provider_t *p,
                                            const char *node, bool using_https,
                                            char *out, size_t out_len);

/*
 * 判断某个 host/IP 是否属于本自建的服务节点。
 * 入参会去除端口与方括号后比较。
 */
bool pdns_fusion_provider_is_host_in_fusion_dns(pdns_fusion_provider_t *p,
                                                    const char *host);

/* 向上转型辅助 */
static inline pdns_server_provider_t *
pdns_fusion_provider_as_provider(pdns_fusion_provider_t *p) {
    return (pdns_server_provider_t *) p;
}

static inline pdns_base_provider_t *
pdns_fusion_provider_as_base(pdns_fusion_provider_t *p) {
    return (pdns_base_provider_t *) p;
}

#endif /* PDNS_FUSION_DNS_PROVIDER_H */
