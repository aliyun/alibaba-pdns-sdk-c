/*
 * DNS 服务地址提供者接口（内部）
 *
 * 统一「公共 DNS」与「自建 DNS」两类服务来源的调用方式，使上层（executor /
 * resolver / conf / tempip）无需关心当前用的是哪一种。
 *
 * C 语言用「结构体嵌入 + vtable 函数指针表」表达「接口 + 抽象基类 + 子类继承」：
 *   pdns_public_provider_t / pdns_fusion_provider_t
 *       └─ 首成员 pdns_base_provider_t base
 *              └─ 首成员 const pdns_server_provider_vtbl_t *vtbl
 * C 标准保证结构体首成员地址等于结构体自身地址，故子类指针可安全向上转型为
 * pdns_server_provider_t*。该布局由各子类头文件中的编译期断言钉死。
 *
 * 一处必要差异：addressMode / enableIPv6 为 client 级配置，故作为
 * 参数显式传入。
 */
#ifndef PDNS_DNS_SERVER_PROVIDER_H
#define PDNS_DNS_SERVER_PROVIDER_H

#include "pdns/pdns_api.h"
#include "pdns_netstack.h"

#include <apr_time.h>

/* URL 缓冲上限：base_url（scheme + IP/域名 + 可选端口）与鉴权 path 各自的长度上限 */
#define PDNS_BASE_URL_MAX_LEN  128
#define PDNS_URL_PATH_MAX_LEN  1024

/* 节点类型（v4 / v6 / 域名） */
typedef enum {
    PDNS_SVR_IP_TYPE_V4,
    PDNS_SVR_IP_TYPE_V6,
    PDNS_SVR_IP_TYPE_HOST
} pdns_svr_ip_type_t;

/*
 * 服务节点模型。
 * 熔断相关字段随熔断与健康检查能力启用而参与判定，初始化阶段仅创建。
 */
typedef struct {
    char               ip[PDNS_IP_ADDRESS_STRING_LENGTH];
    pdns_svr_ip_type_t type;
    float              srtt;                       /* 平滑 RTT(ms)，0=尚未测量 */
    bool               is_alive;                   /* 是否存活（未熔断） */
    int                consecutive_failure_count;  /* 连续失败计数 */
    int                consecutive_success_count;  /* 连续成功计数 */
    apr_time_t         last_failed_time;           /* 最近失败时间 */
} pdns_server_ip_model_t;

typedef struct pdns_server_provider_s pdns_server_provider_t;

/*
 * 选点结果。
 *
 * 两类 provider 的寻址方式不同，本结构同时容纳：
 *   - 公共 DNS：base_url 固定为服务域名（https://dns.alidns.com），选中节点通过
 *     resolve_host + server_ip 交由 CURLOPT_RESOLVE 注入——TCP 连 IP，TLS/SNI 仍按域名
 *     校验，不依赖证书的 IP SAN（比直接拼 IP 更稳妥）。
 *   - 自建：节点由调用方传入（可为 IP 也可为域名）且带自定义端口，故直接拼入
 *     base_url，resolve_host / server_ip 置 NULL 不做注入。
 */
typedef struct {
    char        base_url[PDNS_BASE_URL_MAX_LEN];  /* 如 https://dns.alidns.com 或 https://1.2.3.4:8443 */
    /*
     * 本次选中节点在节点池中的标识，供调用方回写 SRTT / 执行失败惩罚。
     * 必须与 server_ip 分开：两者语义不同，且在自建上并不重合——
     *   - server_ip 回答的是「要不要做 CURLOPT_RESOLVE 直连注入」
     *   - node_ip   回答的是「本次用的是哪个节点」
     * 自建把节点直接拼进 URL，server_ip 恒为 NULL，若用它当节点标识，
     * SRTT 与惩罚就永远不会执行，导致重试始终死活同一个不可用节点。
     * HOST 域名兜底（公共 DNS）时为 NULL：那是系统 DNS 解析，无具体节点可记分。
     */
    const char *node_ip;
    const char *resolve_host;  /* IP 直连时用于 SNI/证书校验的域名；NULL=不做直连注入 */
    const char *server_ip;     /* 直连目标 IP；NULL=不做直连（HOST 兜底或自建模式） */
    bool        verify_cert;   /* 是否校验服务端证书（仅自建可关） */
    /*
     * 本次选中的来源，透传到解析结果供使用方查询（见 pdns_result_list_get_source）。
     * 用枚举而非字符串：来源要跨模块传递并最终落到对外 API 与缓存条目里，
     * 保留字符串会形成「字符串 + 枚举」两份真值，日志统一用 pdns_source_name() 转换。
     */
    pdns_source_t source;
    float       node_srtt;  /* 选中节点当前 SRTT(ms)，0=未测量；日志用 */
} pdns_server_url_result_t;

/* 虚函数表 */
typedef struct {
    /* 当前提供者是否可用 = 鉴权可用 && 有服务器配置 */
    bool (*is_dns_provider_enabled)(pdns_server_provider_t *self);
    /* 是否有可用的服务器配置（v4/v6/host 任一非空） */
    bool (*is_server_available)(pdns_server_provider_t *self);
    /* 是否有可用鉴权参数（三参数须全非空） */
    bool (*is_account_auth_available)(pdns_server_provider_t *self);
    /* 当前网络栈下是否有可调度节点 */
    bool (*has_active_servers)(pdns_server_provider_t *self,
                               pdns_netstack_type_t stack, bool enable_ipv6);
    /*
     * 按重试序号取服务端 URL。
     * @return 0 成功并填充 out；非 0 表示当前无可用节点。
     */
    int (*get_server_url_with_request_count)(pdns_server_provider_t *self,
                                             int request_count,
                                             pdns_netstack_type_t stack,
                                             bool enable_ipv6,
                                             bool using_https,
                                             pdns_server_url_result_t *out);
    /*
     * 生成带鉴权的 URL path。
     * 输出形如 /resolve?name=...&type=...&uid=...&ts=...&key=...&ak=...&did=...
     * @return 0 成功；非 0 失败（鉴权不全 / 缓冲不足）。
     */
    int (*get_url_path_with_domain)(pdns_server_provider_t *self,
                                    const char *ascii_host,
                                    const char *type_str,
                                    const char *session_id,
                                    const char *ecs,
                                    bool        enable_short,
                                    char *out, size_t out_len);
    /* 提供者名称，用于日志与来源标记（"PublicDNS" / "FusionDNS"） */
    const char *(*provider_name)(pdns_server_provider_t *self);
} pdns_server_provider_vtbl_t;

/* 接口对象：仅含 vtable 指针，实体由各子类提供 */
struct pdns_server_provider_s {
    const pdns_server_provider_vtbl_t *vtbl;
};

/* ---------------- 接口调用包装 ---------------- */

static inline bool pdns_provider_is_dns_provider_enabled(pdns_server_provider_t *p) {
    return (p != NULL) && p->vtbl->is_dns_provider_enabled(p);
}

static inline bool pdns_provider_is_server_available(pdns_server_provider_t *p) {
    return (p != NULL) && p->vtbl->is_server_available(p);
}

static inline bool pdns_provider_is_account_auth_available(pdns_server_provider_t *p) {
    return (p != NULL) && p->vtbl->is_account_auth_available(p);
}

static inline bool pdns_provider_has_active_servers(pdns_server_provider_t *p,
                                                    pdns_netstack_type_t stack,
                                                    bool enable_ipv6) {
    return (p != NULL) && p->vtbl->has_active_servers(p, stack, enable_ipv6);
}

static inline int pdns_provider_get_server_url_with_request_count(
        pdns_server_provider_t *p, int request_count,
        pdns_netstack_type_t stack, bool enable_ipv6, bool using_https,
        pdns_server_url_result_t *out) {
    if (p == NULL || out == NULL) {
        return 1;
    }
    return p->vtbl->get_server_url_with_request_count(p, request_count, stack,
                                                      enable_ipv6, using_https, out);
}

static inline int pdns_provider_get_url_path_with_domain(
        pdns_server_provider_t *p, const char *ascii_host, const char *type_str,
        const char *session_id, const char *ecs, bool enable_short,
        char *out, size_t out_len) {
    if (p == NULL || out == NULL) {
        return 1;
    }
    return p->vtbl->get_url_path_with_domain(p, ascii_host, type_str, session_id,
                                             ecs, enable_short, out, out_len);
}

static inline const char *pdns_provider_name(pdns_server_provider_t *p) {
    return (p != NULL) ? p->vtbl->provider_name(p) : "None";
}

#endif /* PDNS_DNS_SERVER_PROVIDER_H */
