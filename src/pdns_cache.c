/*
 * 缓存模块实现 —— LRU 双向链表 + TTL，APR 互斥量保护
 */
#include "pdns_cache.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <apr_pools.h>
#include <apr_thread_mutex.h>

/* ---------------- 内部结构 ---------------- */

typedef struct cache_entry_s {
    char                 *key;
    pdns_list_impl_t     *ips;         /* 存储的 IP 列表副本（顺序即排序结果） */
    float                *rtts;        /* 与 ips 一一对应的测速 RTT（ms）；未测速=PDNS_RTT_DEFAULT */
    time_t                insert_time;
    int                   ttl;
    bool                  is_negative;
    pdns_source_t         source;      /* 解析来源：随条目持久化，兼作覆盖保护判据 */
    struct cache_entry_s *prev;
    struct cache_entry_s *next;
} cache_entry_t;

struct pdns_cache_s {
    apr_pool_t         *pool;
    apr_thread_mutex_t *lock;
    cache_entry_t      *head;   /* LRU 头（最近使用） */
    cache_entry_t      *tail;   /* LRU 尾（最久未用） */
    int                 size;
    pdns_cache_config_t cfg;
};

/* ---------------- 内部辅助 ---------------- */

static char *dup_str(const char *s) {
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *p = (char *) malloc(n);
    if (p) {
        memcpy(p, s, n);
    }
    return p;
}

/* 信任窗口（秒）：过期时长在此值内的条目旧值仍可用 */
#define PDNS_CACHE_TRUST_TIME 30

static void make_key(char *buf, size_t n, const char *host, pdns_query_type_t qt) {
    /* 以 DNS 记录类型码作为 key 后缀（A=1，AAAA=28），与请求 URL 的 type= 一致，语义更清晰。
     * 注：BOTH 已在上层拆成 v4/v6 单类型，不会以 BOTH 作 key；AUTO 已在解析层归一。 */
    int type_code = (qt == PDNS_QUERY_IPV6) ? 28 : 1;
    snprintf(buf, n, "%s_%d", host, type_code);
}

/*
 * 地址族归一，必须与 make_key 的判定保持一致：非 IPv6 一律归为 IPv4。
 * 否则会出现「key 落在 v4 桶、但 meta 因 family 非法而没填」的不一致
 * （AUTO 正常已在解析层归一，此处作兜底）。
 */
static pdns_query_type_t normalize_family(pdns_query_type_t qt) {
    return (qt == PDNS_QUERY_IPV6) ? PDNS_QUERY_IPV6 : PDNS_QUERY_IPV4;
}

/* 判定是否为 HTTPDNS 来源（公共 DNS 与自建均属之） */
static bool is_httpdns_source(pdns_source_t s) {
    return s == PDNS_SOURCE_PUBLIC_DNS || s == PDNS_SOURCE_FUSION_DNS;
}

/* 结果列表 → 内部存储 */
static void copy_from_result(pdns_list_impl_t *dst, const pdns_result_list_t *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    size_t n = pdns_result_list_size(src);
    for (size_t i = 0; i < n; i++) {
        const char *s = pdns_result_list_get(src, i);
        if (s) {
            pdns_list_impl_add(dst, s);
        }
    }
}

/* 内部存储 → 结果列表 */
static void copy_to_result(pdns_result_list_t *dst, const pdns_list_impl_t *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    size_t n = pdns_list_impl_size(src);
    for (size_t i = 0; i < n; i++) {
        const char *s = pdns_list_impl_get(src, i);
        if (s) {
            pdns_result_list_add(dst, s);
        }
    }
}

static void entry_free(cache_entry_t *e) {
    if (e == NULL) {
        return;
    }
    free(e->key);
    pdns_list_impl_destroy(e->ips);
    free(e->rtts);
    free(e);
}

static void list_remove(pdns_cache_t *c, cache_entry_t *e) {
    if (e->prev) {
        e->prev->next = e->next;
    } else {
        c->head = e->next;
    }
    if (e->next) {
        e->next->prev = e->prev;
    } else {
        c->tail = e->prev;
    }
    e->prev = NULL;
    e->next = NULL;
}

static void list_push_front(pdns_cache_t *c, cache_entry_t *e) {
    e->prev = NULL;
    e->next = c->head;
    if (c->head) {
        c->head->prev = e;
    } else {
        c->tail = e;
    }
    c->head = e;
}

static cache_entry_t *find_entry(pdns_cache_t *c, const char *key) {
    for (cache_entry_t *e = c->head; e != NULL; e = e->next) {
        if (strcmp(e->key, key) == 0) {
            return e;
        }
    }
    return NULL;
}

/* 在 (ips, rtts) 中查同 IP 的 rtt（RTT 复用，复用旧缓存 rtt）；
 * 查不到返回 PDNS_RTT_DEFAULT（未测速） */
static float lookup_rtt(const pdns_list_impl_t *ips, const float *rtts, const char *ip) {
    if (ips == NULL || rtts == NULL || ip == NULL) {
        return PDNS_RTT_DEFAULT;
    }
    size_t n = pdns_list_impl_size(ips);
    for (size_t i = 0; i < n; i++) {
        const char *s = pdns_list_impl_get(ips, i);
        if (s && strcmp(s, ip) == 0) {
            return rtts[i];
        }
    }
    return PDNS_RTT_DEFAULT;
}

/* 为新 IP 列表构建 rtts 数组：同 IP 复用旧 rtt，新 IP 置未测速默认值 */
static float *build_rtts(const pdns_list_impl_t *new_ips,
                         const pdns_list_impl_t *old_ips, const float *old_rtts) {
    size_t n = pdns_list_impl_size(new_ips);
    if (n == 0) {
        return NULL;
    }
    float *rtts = (float *) malloc(sizeof(float) * n);
    if (rtts == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        rtts[i] = lookup_rtt(old_ips, old_rtts, pdns_list_impl_get(new_ips, i));
    }
    return rtts;
}

/* ---------------- 生命周期 ---------------- */

pdns_cache_t *pdns_cache_create(const pdns_cache_config_t *cfg) {
    pdns_cache_t *c = (pdns_cache_t *) calloc(1, sizeof(pdns_cache_t));
    if (c == NULL) {
        return NULL;
    }
    if (apr_pool_create(&c->pool, NULL) != APR_SUCCESS) {
        free(c);
        return NULL;
    }
    apr_thread_mutex_create(&c->lock, APR_THREAD_MUTEX_DEFAULT, c->pool);
    if (cfg) {
        c->cfg = *cfg;
    } else {
        c->cfg.max_ttl      = 3600;
        c->cfg.min_ttl      = 60;
        c->cfg.max_negative = 30;
        c->cfg.max_size     = 100;
        c->cfg.immutable    = false;
    }
    return c;
}

void pdns_cache_destroy(pdns_cache_t *cache) {
    if (cache == NULL) {
        return;
    }
    cache_entry_t *e = cache->head;
    while (e != NULL) {
        cache_entry_t *next = e->next;
        entry_free(e);
        e = next;
    }
    if (cache->lock) {
        apr_thread_mutex_destroy(cache->lock);
    }
    if (cache->pool) {
        apr_pool_destroy(cache->pool);
    }
    free(cache);
}

void pdns_cache_set_config(pdns_cache_t *cache, const pdns_cache_config_t *cfg) {
    if (cache == NULL || cfg == NULL) {
        return;
    }
    apr_thread_mutex_lock(cache->lock);
    cache->cfg = *cfg;
    apr_thread_mutex_unlock(cache->lock);
}

void pdns_cache_clear(pdns_cache_t *cache) {
    if (cache == NULL) {
        return;
    }
    apr_thread_mutex_lock(cache->lock);
    cache_entry_t *e = cache->head;
    while (e != NULL) {
        cache_entry_t *next = e->next;
        entry_free(e);
        e = next;
    }
    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;
    apr_thread_mutex_unlock(cache->lock);
}

/* ---------------- 查询 / 写入 ---------------- */

pdns_cache_result_t pdns_cache_get(pdns_cache_t *cache,
                                   const char *host,
                                   pdns_query_type_t query_type,
                                   pdns_result_list_t *out_ips) {
    if (cache == NULL || host == NULL || out_ips == NULL) {
        return PDNS_CACHE_MISS;
    }
    char key[300];
    make_key(key, sizeof(key), host, query_type);

    apr_thread_mutex_lock(cache->lock);
    cache_entry_t *e = find_entry(cache, key);
    if (e == NULL) {
        apr_thread_mutex_unlock(cache->lock);
        return PDNS_CACHE_MISS;
    }
    /* LRU：命中后移到头部 */
    list_remove(cache, e);
    list_push_front(cache, e);

    if (!e->is_negative) {
        copy_to_result(out_ips, e->ips);
    }
    /* 命中即回填该族 meta：source 为当初写入缓存的真实来源（而非笼统的 Cache），
     * from_cache=true 表示本次未走网络。否定条目也填：“无记录”这个结论同样有来源。 */
    pdns_result_list_set_meta(out_ips, normalize_family(query_type), e->source, true);

    pdns_cache_result_t result;
    if (cache->cfg.immutable) {
        result = PDNS_CACHE_HIT;
    } else {
        long age = (long) (time(NULL) - e->insert_time);
        if (age < e->ttl) {
            /* 未过期：检查是否快到期（剩余 < max(ttl/10, 1)，触发预刷新） */
            long soon = e->ttl / 10;
            if (soon < 1) soon = 1;
            if (e->ttl - age < soon) {
                result = PDNS_CACHE_HIT_SOON;
            } else {
                result = PDNS_CACHE_HIT;
            }
        } else if (age - e->ttl < PDNS_CACHE_TRUST_TIME) {
            /* 过期但在信任窗口(30s)内：旧值仍可用（stale-while-revalidate） */
            result = PDNS_CACHE_STALE_TRUST;
        } else {
            result = PDNS_CACHE_EXPIRED;
        }
    }
    apr_thread_mutex_unlock(cache->lock);

    return result;
}

void pdns_cache_put(pdns_cache_t *cache,
                    const char *host,
                    pdns_query_type_t query_type,
                    const pdns_result_list_t *ips,
                    int ttl,
                    bool is_negative,
                    pdns_source_t source) {
    if (cache == NULL || host == NULL) {
        return;
    }
    char key[300];
    make_key(key, sizeof(key), host, query_type);

    /* TTL 已由解析层钳制（正常 [min,max]；否定≤max_negative），本层直接存储。 */

    apr_thread_mutex_lock(cache->lock);
    if (cache->cfg.max_size <= 0) {
        /* max_size=0：缓存禁写 */
        apr_thread_mutex_unlock(cache->lock);
        return;
    }
    cache_entry_t *e = find_entry(cache, key);
    if (e != NULL) {
        /* 覆盖保护：
         *   仅当“新值来自 LocalDNS 且旧值来自 HTTPDNS”时跳过覆盖，保留更优的 HTTPDNS 结果；
         *   其余情况（新值为 HTTPDNS、或旧值本就是 LocalDNS）正常更新。
         * 注：不能写成枚举值大小比较——PublicDNS 与 FusionDNS 之间必须互相允许覆盖
         * （两者都是 HTTPDNS 结果，主备降级后就应当用新的），只有 LocalDNS 是例外。 */
        if (source == PDNS_SOURCE_LOCAL_DNS && is_httpdns_source(e->source)) {
            apr_thread_mutex_unlock(cache->lock);
            return;
        }
        /* 更新已有条目（先留旧 ips/rtts 供 RTT 复用，再替换释放） */
        pdns_list_impl_t *old_ips  = e->ips;
        float            *old_rtts = e->rtts;
        e->ips  = pdns_list_impl_create();
        copy_from_result(e->ips, ips);
        e->rtts = build_rtts(e->ips, old_ips, old_rtts);
        pdns_list_impl_destroy(old_ips);
        free(old_rtts);
        e->ttl         = ttl;
        e->insert_time = time(NULL);
        e->is_negative = is_negative;
        e->source      = source;
        list_remove(cache, e);
        list_push_front(cache, e);
    } else {
        /* 新建条目 */
        e = (cache_entry_t *) calloc(1, sizeof(cache_entry_t));
        if (e == NULL) {
            apr_thread_mutex_unlock(cache->lock);
            return;
        }
        e->key         = dup_str(key);
        e->ips         = pdns_list_impl_create();
        copy_from_result(e->ips, ips);
        e->rtts        = build_rtts(e->ips, NULL, NULL);
        e->ttl         = ttl;
        e->insert_time = time(NULL);
        e->is_negative = is_negative;
        e->source      = source;
        list_push_front(cache, e);
        cache->size++;

        /* LRU 淘汰 */
        while (cache->size > cache->cfg.max_size && cache->tail != NULL) {
            cache_entry_t *old = cache->tail;
            list_remove(cache, old);
            entry_free(old);
            cache->size--;
        }
    }
    apr_thread_mutex_unlock(cache->lock);
}

/* ---------------- 测速支撑 ---------------- */

void pdns_cache_update_ip_rtt(pdns_cache_t *cache, const char *host,
                              pdns_query_type_t query_type,
                              const char *ip, float rtt) {
    if (cache == NULL || host == NULL || ip == NULL) {
        return;
    }
    char key[300];
    make_key(key, sizeof(key), host, query_type);

    apr_thread_mutex_lock(cache->lock);
    cache_entry_t *e = find_entry(cache, key);
    if (e != NULL && e->rtts != NULL) {
        size_t n = pdns_list_impl_size(e->ips);
        for (size_t i = 0; i < n; i++) {
            const char *s = pdns_list_impl_get(e->ips, i);
            if (s && strcmp(s, ip) == 0) {
                e->rtts[i] = rtt;
                break;
            }
        }
    }
    apr_thread_mutex_unlock(cache->lock);
}

void pdns_cache_sort_entry(pdns_cache_t *cache, const char *host,
                           pdns_query_type_t query_type) {
    if (cache == NULL || host == NULL) {
        return;
    }
    char key[300];
    make_key(key, sizeof(key), host, query_type);

    apr_thread_mutex_lock(cache->lock);
    cache_entry_t *e = find_entry(cache, key);
    if (e == NULL || e->is_negative || e->rtts == NULL) {
        apr_thread_mutex_unlock(cache->lock);
        return;
    }
    size_t n = pdns_list_impl_size(e->ips);
    if (n < 2) {
        apr_thread_mutex_unlock(cache->lock);
        return;
    }
    /* 构建索引数组按 rtt 稳定插入排序（n 小，单条目内同族，纯 RTT 升序无让分），
     * 再重建 ips 链表与 rtts 数组保持一一对应。 */
    size_t *idx = (size_t *) malloc(sizeof(size_t) * n);
    if (idx == NULL) {
        apr_thread_mutex_unlock(cache->lock);
        return;
    }
    for (size_t i = 0; i < n; i++) idx[i] = i;
    for (size_t i = 1; i < n; i++) {
        size_t cur = idx[i];
        size_t j   = i;
        while (j > 0 && e->rtts[idx[j - 1]] > e->rtts[cur]) {
            idx[j] = idx[j - 1];
            j--;
        }
        idx[j] = cur;
    }
    pdns_list_impl_t *new_ips  = pdns_list_impl_create();
    float            *new_rtts = (float *) malloc(sizeof(float) * n);
    if (new_ips == NULL || new_rtts == NULL) {
        pdns_list_impl_destroy(new_ips);
        free(new_rtts);
        free(idx);
        apr_thread_mutex_unlock(cache->lock);
        return;
    }
    for (size_t i = 0; i < n; i++) {
        pdns_list_impl_add(new_ips, pdns_list_impl_get(e->ips, idx[i]));
        new_rtts[i] = e->rtts[idx[i]];
    }
    pdns_list_impl_destroy(e->ips);
    free(e->rtts);
    e->ips  = new_ips;
    e->rtts = new_rtts;
    free(idx);
    apr_thread_mutex_unlock(cache->lock);
}

size_t pdns_cache_get_rtts(pdns_cache_t *cache, const char *host,
                           pdns_query_type_t query_type,
                           pdns_list_impl_t *out_ips,
                           float *out_rtts, size_t max_n) {
    if (cache == NULL || host == NULL || out_ips == NULL || out_rtts == NULL) {
        return 0;
    }
    char key[300];
    make_key(key, sizeof(key), host, query_type);

    apr_thread_mutex_lock(cache->lock);
    cache_entry_t *e = find_entry(cache, key);
    if (e == NULL || e->is_negative) {
        apr_thread_mutex_unlock(cache->lock);
        return 0;
    }
    size_t n = pdns_list_impl_size(e->ips);
    if (n > max_n) {
        n = max_n;
    }
    for (size_t i = 0; i < n; i++) {
        pdns_list_impl_add(out_ips, pdns_list_impl_get(e->ips, i));
        out_rtts[i] = (e->rtts != NULL) ? e->rtts[i] : PDNS_RTT_DEFAULT;
    }
    apr_thread_mutex_unlock(cache->lock);
    return n;
}
