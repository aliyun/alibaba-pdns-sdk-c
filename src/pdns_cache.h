/*
 * 缓存模块（内部）—— LRU + TTL 内存缓存
 *
 * 缓存 Key：host + "_" + query_type。
 * 支持：TTL 上下限钳制、否定缓存、不可变缓存（永不过期）、LRU 淘汰。
 * 线程安全：内部使用 APR 互斥量保护。
 */
#ifndef PDNS_CACHE_H
#define PDNS_CACHE_H

#include "pdns/pdns_api.h"
#include "pdns_list.h"

typedef struct pdns_cache_s pdns_cache_t;

/* 缓存配置（来自 client） */
typedef struct {
    int32_t max_ttl;        /* 缓存 TTL 上限（秒） */
    int32_t min_ttl;        /* 缓存 TTL 下限（秒） */
    int32_t max_negative;   /* 否定缓存最大 TTL（秒） */
    int32_t max_size;       /* 缓存条目上限 */
    bool    immutable;      /* 不可变缓存：永不过期 */
} pdns_cache_config_t;

/* 缓存查询结果 */
typedef enum {
    PDNS_CACHE_MISS = 0,    /* 未命中 */
    PDNS_CACHE_HIT,         /* 命中且未过期 */
    PDNS_CACHE_HIT_SOON,    /* 命中未过期，但剩余TTL不足(快过期)——返回并触发预刷新 */
    PDNS_CACHE_STALE_TRUST, /* 过期但在信任窗口(30s)内，旧值仍可用（stale-while-revalidate） */
    PDNS_CACHE_EXPIRED      /* 过期且超出信任窗口 */
} pdns_cache_result_t;

/* 测速 RTT 常量：
 *   测速成功值 < 3000(connect超时) < 未测速 5000 < 超时/失败 9999，三区间互斥，
 *   rtt==PDNS_RTT_DEFAULT 可唯一判定“未测速”。 */
#define PDNS_RTT_DEFAULT 5000.0f
#define PDNS_RTT_TIMEOUT 9999.0f

pdns_cache_t *pdns_cache_create(const pdns_cache_config_t *cfg);
void          pdns_cache_destroy(pdns_cache_t *cache);

/* 更新缓存配置（客户端配置变化时同步） */
void pdns_cache_set_config(pdns_cache_t *cache, const pdns_cache_config_t *cfg);

/* 清空全部缓存条目（max_cache_size 置 0 时调用） */
void pdns_cache_clear(pdns_cache_t *cache);

/*
 * 查询缓存。命中（含过期）时把 IP 复制到 out_ips，并回填该地址族的 meta
 * （source = 当初写入缓存的真实来源，from_cache = true）。
 * @return HIT（未过期）/ EXPIRED（已过期）/ MISS（未命中）
 */
pdns_cache_result_t pdns_cache_get(pdns_cache_t *cache,
                                   const char *host,
                                   pdns_query_type_t query_type,
                                   pdns_result_list_t *out_ips);

/* 写入缓存（ttl 已由解析层钳制；is_negative 使用 max_negative 作为 TTL）
 * source：本次结果的来源。兼作两用：
 *   1) 随条目持久化，供缓存命中时告知使用方「这批 IP 最初是谁解析的」；
 *   2) 覆盖保护——LocalDNS 结果不会覆盖已有的 HTTPDNS 结果。 */
void pdns_cache_put(pdns_cache_t *cache,
                    const char *host,
                    pdns_query_type_t query_type,
                    const pdns_result_list_t *ips,
                    int ttl,
                    bool is_negative,
                    pdns_source_t source);

/* ---------------- 测速支撑 ---------------- */

/* 回写单 IP 测速结果（条目/IP 不存在则忽略） */
void pdns_cache_update_ip_rtt(pdns_cache_t *cache, const char *host,
                              pdns_query_type_t query_type,
                              const char *ip, float rtt);

/* 条目内按 rtt 升序重排（测速完成后调用；单条目内同族，无需让分） */
void pdns_cache_sort_entry(pdns_cache_t *cache, const char *host,
                           pdns_query_type_t query_type);

/*
 * 获取条目 (ip, rtt) 快照（供双栈合并混排）：
 * IP 追加到 out_ips，rtt 写入 out_rtts[i]（最多 max_n 个）。
 * @return 实际写入数量；未命中/否定条目返回 0。
 */
size_t pdns_cache_get_rtts(pdns_cache_t *cache, const char *host,
                           pdns_query_type_t query_type,
                           pdns_list_impl_t *out_ips,
                           float *out_rtts, size_t max_n);

#endif /* PDNS_CACHE_H */
