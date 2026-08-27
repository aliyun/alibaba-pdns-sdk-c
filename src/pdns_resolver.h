/*
 * 解析模块（内部）—— 向 HTTPDNS 服务端发起解析请求并解析响应
 *
 * 解析协议：
 *   - 服务端寻址与鉴权 path 均由 pdns_server_manager 选出的 provider 提供
 *     （公共 DNS：域名 + CURLOPT_RESOLVE 注入 IP；自建：节点+端口直接入 URL）
 *   - GET <base_url>/resolve?name=&type=&uid=&pf=&sv=&ts=&key=&ak=[&did=][&edns_client_subnet=]
 *   - 签名 SHA-256(account_id + access_key_secret + ts + host + access_key_id)
 *   - 响应 {"Status":0,"Answer":[{"data":IP,"TTL":n,"type":1}]}
 */
#ifndef PDNS_RESOLVER_H
#define PDNS_RESOLVER_H

#include "pdns/pdns_api.h"
#include "pdns_list.h"

/* 解析场景（sync/preload/cache_async/timer），驱动 LocalDNS 兜底策略与日志。 */
typedef enum {
    PDNS_SCENE_SYNC        = 0,   /* 同步解析（用户阻塞调用） */
    PDNS_SCENE_PRELOAD     = 1,   /* 预解析 */
    PDNS_SCENE_CACHE_ASYNC = 2,   /* 缓存 miss/过期的后台异步刷新 */
    PDNS_SCENE_TIMER       = 3    /* 保活域名定时刷新 */
} pdns_scene_t;

/* scene 名称（日志用）；static inline 供多个 TU 共用。 */
static inline const char *pdns_scene_name(pdns_scene_t s) {
    switch (s) {
        case PDNS_SCENE_PRELOAD:     return "preload";
        case PDNS_SCENE_CACHE_ASYNC: return "cache_async";
        case PDNS_SCENE_TIMER:       return "timer";
        default:                     return "sync";
    }
}

/* query_type 映射到 URL 的 type 参数（服务端只支持单类型查询）。
 * 同时用作失败计数 key 中的 type 字段（domain:type:requestId）。
 * 注：BOTH 已在上层（pdns_resolve_both）拆成 v4/v6 两次单类型请求，不应到达此处。 */
static inline const char *pdns_query_type_url_str(pdns_query_type_t t) {
    return (t == PDNS_QUERY_IPV6) ? "28" : "1";   /* AUTO / IPV4 均为 1 */
}

/* 解析请求参数（内部使用：寻址与鉴权字段由 pdns_executor 从 provider 填充，
 * 其余字段由 client 配置填充） */
typedef struct {
    /* ===== 以下 6 项由选中的 provider 提供（每次重试可能不同） ===== */
    const char       *base_url;     /* 如 https://dns.alidns.com 或 https://1.2.3.4:8443 */
    const char       *url_path;     /* 带签名的 path，如 /resolve?name=...&key=...&ak=... */
    const char       *resolve_host; /* CURLOPT_RESOLVE 的 SNI/证书校验域名；NULL=不注入 */
    const char       *server_ip;    /* 直连目标 IP；NULL=不直连（HOST 兜底或自建） */
    bool              skip_cert_verify; /* 跳过证书校验（仅自建可开） */
    /*
     * 本次尝试所用的来源（日志 + 回填结果列表的 meta）。
     * executor 每轮重试都会回填，故执行器返回后此字段即「末次实际使用的来源」，
     * 调用方可直接读取（无需额外的出参）。
     */
    pdns_source_t     source;

    const char       *host;         /* 待解析域名（原始形式，用于日志与请求级统计） */
    const char       *ecs;          /* EDNS Client Subnet，可为 NULL（由 executor 传给 provider） */
    const char       *session_id;   /* 会话 ID（&did= 上报），可为 NULL（同上） */
    const char       *request_id;   /* 请求跟踪 ID（日志 + 失败计数 key），可为 NULL */
    pdns_query_type_t query_type;
    pdns_scene_t      scene;         /* 解析场景（日志用；兜底策略在上层按 scene 决定） */
    bool              using_https;
    bool              enable_short;  /* short 模式：请求加 &short=1，响应为纯 IP 数组 */
    int32_t           min_ttl;       /* TTL 钳制下限；short 模式直接用作 TTL */
    int32_t           max_ttl;       /* TTL 钳制上限 */
    int32_t           max_negative;  /* 否定缓存最大 TTL，<=0 关闭否定缓存 */
    int32_t           timeout_ms;
    bool              use_http2;     /* 启用 HTTP/2（ALPN 协商，失败回落 1.1）；默认 true */
} pdns_resolve_req_t;

/*
 * 执行一次同步 HTTPDNS 解析，将解析出的 IP 字符串追加到 out_ips 链表。
 * TTL 钳制与否定缓存判定均在本层完成。
 * @param[out] out_ttl         首个匹配记录的 TTL（已钳制，秒）；否定响应为否定 TTL。可为 NULL。
 * @param[out] out_rtt_ms      本次请求耗时（毫秒），用于 SRTT 更新。可为 NULL。
 * @param[out] out_is_negative 是否为否定响应（NXDOMAIN / NODATA）。可为 NULL。
 * @param[out] out_conf_version 响应头 Cv（服务端当前 ACL 版本），<0 表未携带。可为 NULL。
 * @return pdns_status_t，code=0（PDNS_OK）表示成功（含否定响应）。
 */
pdns_status_t pdns_do_resolve(const pdns_resolve_req_t *req, pdns_result_list_t *out_ips,
                              int *out_ttl, long *out_rtt_ms, bool *out_is_negative,
                              long *out_conf_version);

#endif /* PDNS_RESOLVER_H */
