/*
 * 缓存模块测试 —— LRU + TTL + 否定缓存 + 永久缓存 + 测速 RTT 支撑 + 来源元信息
 *
 * 说明：
 *   - TTL 钳制在解析层完成（见 pdns_cache.c 注释），缓存层按传入 TTL 直接存储，
 *     故此处不对钳制做断言。
 *   - PDNS_CACHE_HIT_SOON 需消耗 90% 以上 TTL 才会出现（soon=max(ttl/10,1)），
 *     PDNS_CACHE_EXPIRED 需超出 30s 信任窗口，二者无法在秒级单测内稳定触发，
 *     故本文件覆盖 MISS / HIT / STALE_TRUST 三态，另两态由联网/长跑用例覆盖。
 *   - 缓存条目携带来源（pdns_source_t），命中时回填到结果列表 meta。
 */
#include "test_suite_list.h"
#include "pdns_cache.h"
#include "pdns_list.h"

#include <apr_time.h>

/* 构造一份便于测试的缓存配置 */
static pdns_cache_config_t make_cfg(int max_size, bool immutable) {
    pdns_cache_config_t cfg;
    cfg.max_ttl      = 3600;
    cfg.min_ttl      = 60;
    cfg.max_negative = 30;
    cfg.max_size     = max_size;
    cfg.immutable    = immutable;
    return cfg;
}

/* 往缓存写入一条含 n 个 IP 的正常记录（来源统一记为公共 DNS） */
static void put_ips(pdns_cache_t *cache, const char *host, pdns_query_type_t qt,
                    const char *const *ips, int n, int ttl) {
    pdns_result_list_t *list = pdns_result_list_create();
    for (int i = 0; i < n; i++) {
        pdns_result_list_add(list, ips[i]);
    }
    pdns_cache_put(cache, host, qt, list, ttl, false, PDNS_SOURCE_PUBLIC_DNS);
    pdns_result_list_cleanup(list);
}

/* 未写入的域名应 MISS */
void test_cache_miss(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    pdns_result_list_t *out   = pdns_result_list_create();
    CuAssertPtrNotNull(tc, cache);

    CuAssertIntEquals_Msg(tc, "unknown host should miss", PDNS_CACHE_MISS,
                          pdns_cache_get(cache, "nope.com", PDNS_QUERY_IPV4, out));
    CuAssertIntEquals(tc, 0, (int) pdns_result_list_size(out));

    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 写入后命中，且 IP 顺序与写入一致 */
void test_cache_hit_and_order(CuTest *tc) {
    pdns_cache_config_t cfg     = make_cfg(100, false);
    pdns_cache_t       *cache   = pdns_cache_create(&cfg);
    const char *const   ips[]   = {"1.1.1.1", "2.2.2.2", "3.3.3.3"};
    pdns_result_list_t *out     = pdns_result_list_create();

    put_ips(cache, "a.com", PDNS_QUERY_IPV4, ips, 3, 300);
    CuAssertIntEquals_Msg(tc, "should hit", PDNS_CACHE_HIT,
                          pdns_cache_get(cache, "a.com", PDNS_QUERY_IPV4, out));
    CuAssertIntEquals(tc, 3, (int) pdns_result_list_size(out));
    CuAssertStrEquals(tc, "1.1.1.1", pdns_result_list_get(out, 0));
    CuAssertStrEquals(tc, "2.2.2.2", pdns_result_list_get(out, 1));
    CuAssertStrEquals(tc, "3.3.3.3", pdns_result_list_get(out, 2));

    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 命中时应回填来源 meta：source 为写入时的真实来源，from_cache=true */
void test_cache_get_fills_source_meta(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    /* 写入一条自建来源的记录 */
    pdns_result_list_t *in = pdns_result_list_create();
    pdns_result_list_add(in, ips[0]);
    pdns_cache_put(cache, "src.com", PDNS_QUERY_IPV4, in, 300, false, PDNS_SOURCE_FUSION_DNS);
    pdns_result_list_cleanup(in);

    pdns_result_list_t *out = pdns_result_list_create();
    CuAssertIntEquals(tc, PDNS_CACHE_HIT, pdns_cache_get(cache, "src.com", PDNS_QUERY_IPV4, out));
    CuAssertIntEquals_Msg(tc, "cache hit should carry the original source",
                          PDNS_SOURCE_FUSION_DNS,
                          pdns_result_list_get_source(out, PDNS_QUERY_IPV4));
    CuAssert(tc, "cache hit must be marked from_cache",
             pdns_result_list_is_from_cache(out, PDNS_QUERY_IPV4));
    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 缓存键包含 DNS 类型码：同域名的 v4 / v6 互不干扰 */
void test_cache_key_separates_query_type(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   v4[]  = {"1.1.1.1"};
    const char *const   v6[]  = {"2400:3200::1"};

    put_ips(cache, "dual.com", PDNS_QUERY_IPV4, v4, 1, 300);

    pdns_result_list_t *out6 = pdns_result_list_create();
    CuAssertIntEquals_Msg(tc, "v6 should miss when only v4 cached", PDNS_CACHE_MISS,
                          pdns_cache_get(cache, "dual.com", PDNS_QUERY_IPV6, out6));
    pdns_result_list_cleanup(out6);

    put_ips(cache, "dual.com", PDNS_QUERY_IPV6, v6, 1, 300);

    pdns_result_list_t *g4 = pdns_result_list_create();
    pdns_result_list_t *g6 = pdns_result_list_create();
    CuAssertIntEquals(tc, PDNS_CACHE_HIT, pdns_cache_get(cache, "dual.com", PDNS_QUERY_IPV4, g4));
    CuAssertIntEquals(tc, PDNS_CACHE_HIT, pdns_cache_get(cache, "dual.com", PDNS_QUERY_IPV6, g6));
    CuAssertStrEquals(tc, "1.1.1.1", pdns_result_list_get(g4, 0));
    CuAssertStrEquals(tc, "2400:3200::1", pdns_result_list_get(g6, 0));

    pdns_result_list_cleanup(g4);
    pdns_result_list_cleanup(g6);
    pdns_cache_destroy(cache);
}

/* AUTO / IPV4 / BOTH 归一到同一 key（类型码 1）；仅 IPV6 用 28 */
void test_cache_key_non_v6_maps_to_type1(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    put_ips(cache, "k.com", PDNS_QUERY_IPV4, ips, 1, 300);

    pdns_result_list_t *o1 = pdns_result_list_create();
    pdns_result_list_t *o2 = pdns_result_list_create();
    CuAssertIntEquals_Msg(tc, "AUTO should share type-1 key", PDNS_CACHE_HIT,
                          pdns_cache_get(cache, "k.com", PDNS_QUERY_AUTO, o1));
    CuAssertIntEquals_Msg(tc, "BOTH should share type-1 key", PDNS_CACHE_HIT,
                          pdns_cache_get(cache, "k.com", PDNS_QUERY_BOTH, o2));
    pdns_result_list_cleanup(o1);
    pdns_result_list_cleanup(o2);
    pdns_cache_destroy(cache);
}

/* 重复写入同一 key 应覆盖内容而不新增条目 */
void test_cache_update_overwrites(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   old[] = {"1.1.1.1"};
    const char *const   neu[] = {"9.9.9.9", "8.8.8.8"};

    put_ips(cache, "u.com", PDNS_QUERY_IPV4, old, 1, 300);
    put_ips(cache, "u.com", PDNS_QUERY_IPV4, neu, 2, 300);

    pdns_result_list_t *out = pdns_result_list_create();
    CuAssertIntEquals(tc, PDNS_CACHE_HIT, pdns_cache_get(cache, "u.com", PDNS_QUERY_IPV4, out));
    CuAssertIntEquals_Msg(tc, "content should be replaced", 2, (int) pdns_result_list_size(out));
    CuAssertStrEquals(tc, "9.9.9.9", pdns_result_list_get(out, 0));

    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 否定缓存：命中但不返回任何 IP */
void test_cache_negative_entry(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);

    pdns_cache_put(cache, "nx.com", PDNS_QUERY_IPV4, NULL, 30, true, PDNS_SOURCE_PUBLIC_DNS);

    pdns_result_list_t *out = pdns_result_list_create();
    int                 r   = pdns_cache_get(cache, "nx.com", PDNS_QUERY_IPV4, out);
    CuAssertIntEquals_Msg(tc, "negative entry should be a hit", PDNS_CACHE_HIT, r);
    CuAssertIntEquals_Msg(tc, "negative entry must yield no ip", 0, (int) pdns_result_list_size(out));

    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 过期但在 30s 信任窗口内：返回 STALE_TRUST，且旧值仍可用 */
void test_cache_stale_trust_window(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    put_ips(cache, "s.com", PDNS_QUERY_IPV4, ips, 1, 1);
    apr_sleep(2 * APR_USEC_PER_SEC);   /* age=2 > ttl=1，且 age-ttl=1 < 30 */

    pdns_result_list_t *out = pdns_result_list_create();
    CuAssertIntEquals_Msg(tc, "expired within trust window should be STALE_TRUST",
                          PDNS_CACHE_STALE_TRUST,
                          pdns_cache_get(cache, "s.com", PDNS_QUERY_IPV4, out));
    CuAssertIntEquals_Msg(tc, "stale value must still be returned", 1, (int) pdns_result_list_size(out));
    CuAssertStrEquals(tc, "1.1.1.1", pdns_result_list_get(out, 0));

    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 永久缓存（immutable）：即使 TTL 已过也恒定命中 */
void test_cache_immutable_never_expires(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, true);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    put_ips(cache, "i.com", PDNS_QUERY_IPV4, ips, 1, 1);
    apr_sleep(2 * APR_USEC_PER_SEC);

    pdns_result_list_t *out = pdns_result_list_create();
    CuAssertIntEquals_Msg(tc, "immutable cache must always hit", PDNS_CACHE_HIT,
                          pdns_cache_get(cache, "i.com", PDNS_QUERY_IPV4, out));
    CuAssertIntEquals(tc, 1, (int) pdns_result_list_size(out));

    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* LRU 淘汰：超过 max_size 时淘汰最久未使用的条目 */
void test_cache_lru_eviction(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(2, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    put_ips(cache, "h1.com", PDNS_QUERY_IPV4, ips, 1, 300);
    put_ips(cache, "h2.com", PDNS_QUERY_IPV4, ips, 1, 300);

    /* 访问 h1 使其成为最近使用，h2 变为最久未用 */
    pdns_result_list_t *touch = pdns_result_list_create();
    pdns_cache_get(cache, "h1.com", PDNS_QUERY_IPV4, touch);
    pdns_result_list_cleanup(touch);

    /* 写入第 3 条触发淘汰，应淘汰 h2 */
    put_ips(cache, "h3.com", PDNS_QUERY_IPV4, ips, 1, 300);

    pdns_result_list_t *o1 = pdns_result_list_create();
    pdns_result_list_t *o2 = pdns_result_list_create();
    pdns_result_list_t *o3 = pdns_result_list_create();
    CuAssertIntEquals_Msg(tc, "recently used h1 should survive", PDNS_CACHE_HIT,
                          pdns_cache_get(cache, "h1.com", PDNS_QUERY_IPV4, o1));
    CuAssertIntEquals_Msg(tc, "least recently used h2 should be evicted", PDNS_CACHE_MISS,
                          pdns_cache_get(cache, "h2.com", PDNS_QUERY_IPV4, o2));
    CuAssertIntEquals_Msg(tc, "newest h3 should exist", PDNS_CACHE_HIT,
                          pdns_cache_get(cache, "h3.com", PDNS_QUERY_IPV4, o3));

    pdns_result_list_cleanup(o1);
    pdns_result_list_cleanup(o2);
    pdns_result_list_cleanup(o3);
    pdns_cache_destroy(cache);
}

/* max_size=0：缓存容量上限为 0 时禁止写入 */
void test_cache_max_size_zero_rejects_write(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(0, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    put_ips(cache, "z.com", PDNS_QUERY_IPV4, ips, 1, 300);

    pdns_result_list_t *out = pdns_result_list_create();
    CuAssertIntEquals_Msg(tc, "max_size=0 should reject writes", PDNS_CACHE_MISS,
                          pdns_cache_get(cache, "z.com", PDNS_QUERY_IPV4, out));
    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 运行期改小 max_size 后再写入，条目数受新上限约束 */
void test_cache_set_config_takes_effect(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(10, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    put_ips(cache, "c1.com", PDNS_QUERY_IPV4, ips, 1, 300);
    put_ips(cache, "c2.com", PDNS_QUERY_IPV4, ips, 1, 300);

    cfg.max_size = 1;
    pdns_cache_set_config(cache, &cfg);
    put_ips(cache, "c3.com", PDNS_QUERY_IPV4, ips, 1, 300);   /* 触发淘汰至 1 条 */

    int alive = 0;
    const char *hosts[] = {"c1.com", "c2.com", "c3.com"};
    for (int i = 0; i < 3; i++) {
        pdns_result_list_t *o = pdns_result_list_create();
        if (pdns_cache_get(cache, hosts[i], PDNS_QUERY_IPV4, o) != PDNS_CACHE_MISS) {
            alive++;
        }
        pdns_result_list_cleanup(o);
    }
    CuAssertIntEquals_Msg(tc, "only 1 entry should remain", 1, alive);
    pdns_cache_destroy(cache);
}

/* clear 清空全部条目 */
void test_cache_clear(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1"};

    put_ips(cache, "x1.com", PDNS_QUERY_IPV4, ips, 1, 300);
    put_ips(cache, "x2.com", PDNS_QUERY_IPV4, ips, 1, 300);
    pdns_cache_clear(cache);

    pdns_result_list_t *o1 = pdns_result_list_create();
    pdns_result_list_t *o2 = pdns_result_list_create();
    CuAssertIntEquals(tc, PDNS_CACHE_MISS, pdns_cache_get(cache, "x1.com", PDNS_QUERY_IPV4, o1));
    CuAssertIntEquals(tc, PDNS_CACHE_MISS, pdns_cache_get(cache, "x2.com", PDNS_QUERY_IPV4, o2));
    pdns_result_list_cleanup(o1);
    pdns_result_list_cleanup(o2);

    /* 清空后仍可正常写入 */
    put_ips(cache, "x3.com", PDNS_QUERY_IPV4, ips, 1, 300);
    pdns_result_list_t *o3 = pdns_result_list_create();
    CuAssertIntEquals(tc, PDNS_CACHE_HIT, pdns_cache_get(cache, "x3.com", PDNS_QUERY_IPV4, o3));
    pdns_result_list_cleanup(o3);
    pdns_cache_destroy(cache);
}

/* 覆盖保护：LocalDNS 结果不得覆盖已有的 HTTPDNS 结果 */
void test_cache_localdns_not_override_httpdns(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);

    pdns_result_list_t *http_ips = pdns_result_list_create();
    pdns_result_list_add(http_ips, "1.1.1.1");
    pdns_cache_put(cache, "p.com", PDNS_QUERY_IPV4, http_ips, 300, false, PDNS_SOURCE_PUBLIC_DNS);
    pdns_result_list_cleanup(http_ips);

    pdns_result_list_t *local_ips = pdns_result_list_create();
    pdns_result_list_add(local_ips, "5.5.5.5");
    pdns_cache_put(cache, "p.com", PDNS_QUERY_IPV4, local_ips, 300, false, PDNS_SOURCE_LOCAL_DNS);
    pdns_result_list_cleanup(local_ips);

    pdns_result_list_t *out = pdns_result_list_create();
    pdns_cache_get(cache, "p.com", PDNS_QUERY_IPV4, out);
    CuAssertStrEquals_Msg(tc, "localdns must not override httpdns result",
                          "1.1.1.1", pdns_result_list_get(out, 0));
    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* HTTPDNS 结果可以覆盖已有的 LocalDNS 结果（反方向允许） */
void test_cache_httpdns_overrides_localdns(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);

    pdns_result_list_t *local_ips = pdns_result_list_create();
    pdns_result_list_add(local_ips, "5.5.5.5");
    pdns_cache_put(cache, "q.com", PDNS_QUERY_IPV4, local_ips, 300, false, PDNS_SOURCE_LOCAL_DNS);
    pdns_result_list_cleanup(local_ips);

    pdns_result_list_t *http_ips = pdns_result_list_create();
    pdns_result_list_add(http_ips, "1.1.1.1");
    pdns_cache_put(cache, "q.com", PDNS_QUERY_IPV4, http_ips, 300, false, PDNS_SOURCE_PUBLIC_DNS);
    pdns_result_list_cleanup(http_ips);

    pdns_result_list_t *out = pdns_result_list_create();
    pdns_cache_get(cache, "q.com", PDNS_QUERY_IPV4, out);
    CuAssertStrEquals_Msg(tc, "httpdns should override localdns result",
                          "1.1.1.1", pdns_result_list_get(out, 0));
    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* Fusion 与 Public 之间必须互相允许覆盖（都是 HTTPDNS，主备降级后应用新的） */
void test_cache_fusion_public_override_each_other(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);

    pdns_result_list_t *fus = pdns_result_list_create();
    pdns_result_list_add(fus, "1.1.1.1");
    pdns_cache_put(cache, "f.com", PDNS_QUERY_IPV4, fus, 300, false, PDNS_SOURCE_FUSION_DNS);
    pdns_result_list_cleanup(fus);

    pdns_result_list_t *pub = pdns_result_list_create();
    pdns_result_list_add(pub, "2.2.2.2");
    pdns_cache_put(cache, "f.com", PDNS_QUERY_IPV4, pub, 300, false, PDNS_SOURCE_PUBLIC_DNS);
    pdns_result_list_cleanup(pub);

    pdns_result_list_t *out = pdns_result_list_create();
    pdns_cache_get(cache, "f.com", PDNS_QUERY_IPV4, out);
    CuAssertStrEquals_Msg(tc, "public should override fusion (both httpdns)",
                          "2.2.2.2", pdns_result_list_get(out, 0));
    CuAssertIntEquals_Msg(tc, "source should update to public", PDNS_SOURCE_PUBLIC_DNS,
                          pdns_result_list_get_source(out, PDNS_QUERY_IPV4));
    pdns_result_list_cleanup(out);
    pdns_cache_destroy(cache);
}

/* 新写入条目的 RTT 初值应为「未测速」哨兵 5000 */
void test_cache_rtt_default_for_new_entry(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1", "2.2.2.2"};

    put_ips(cache, "r.com", PDNS_QUERY_IPV4, ips, 2, 300);

    pdns_list_impl_t *out = pdns_list_impl_create();
    float             rtts[8];
    size_t            n = pdns_cache_get_rtts(cache, "r.com", PDNS_QUERY_IPV4, out, rtts, 8);
    CuAssertIntEquals(tc, 2, (int) n);
    CuAssertDblEquals_Msg(tc, "new ip rtt should be untested sentinel",
                          PDNS_RTT_DEFAULT, rtts[0], 0.01);
    CuAssertDblEquals(tc, PDNS_RTT_DEFAULT, rtts[1], 0.01);

    pdns_list_impl_destroy(out);
    pdns_cache_destroy(cache);
}

/* 回写 RTT 并按升序排序，最快 IP 应排到首位 */
void test_cache_update_rtt_and_sort(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1", "2.2.2.2", "3.3.3.3"};

    put_ips(cache, "sp.com", PDNS_QUERY_IPV4, ips, 3, 300);
    pdns_cache_update_ip_rtt(cache, "sp.com", PDNS_QUERY_IPV4, "1.1.1.1", 120.0f);
    pdns_cache_update_ip_rtt(cache, "sp.com", PDNS_QUERY_IPV4, "2.2.2.2", 30.0f);
    pdns_cache_update_ip_rtt(cache, "sp.com", PDNS_QUERY_IPV4, "3.3.3.3", 80.0f);
    pdns_cache_sort_entry(cache, "sp.com", PDNS_QUERY_IPV4);

    pdns_list_impl_t *out = pdns_list_impl_create();
    float             rtts[8];
    size_t            n = pdns_cache_get_rtts(cache, "sp.com", PDNS_QUERY_IPV4, out, rtts, 8);

    CuAssertIntEquals(tc, 3, (int) n);
    CuAssertStrEquals_Msg(tc, "fastest ip should rank first", "2.2.2.2", pdns_list_impl_get(out, 0));
    CuAssertStrEquals(tc, "3.3.3.3", pdns_list_impl_get(out, 1));
    CuAssertStrEquals(tc, "1.1.1.1", pdns_list_impl_get(out, 2));
    CuAssertDblEquals(tc, 30.0, rtts[0], 0.01);
    CuAssertDblEquals(tc, 80.0, rtts[1], 0.01);
    CuAssertDblEquals(tc, 120.0, rtts[2], 0.01);

    /* 排序后 get 返回的顺序也应是排序结果 */
    pdns_result_list_t *hit = pdns_result_list_create();
    pdns_cache_get(cache, "sp.com", PDNS_QUERY_IPV4, hit);
    CuAssertStrEquals_Msg(tc, "cache get should follow sorted order",
                          "2.2.2.2", pdns_result_list_get(hit, 0));

    pdns_result_list_cleanup(hit);
    pdns_list_impl_destroy(out);
    pdns_cache_destroy(cache);
}

/* 重新写入时，仍存在的 IP 应复用已测得的 RTT，新 IP 用默认值 */
void test_cache_rtt_reuse_on_update(CuTest *tc) {
    pdns_cache_config_t cfg    = make_cfg(100, false);
    pdns_cache_t       *cache  = pdns_cache_create(&cfg);
    const char *const   first[] = {"1.1.1.1", "2.2.2.2"};
    const char *const   again[] = {"2.2.2.2", "7.7.7.7"};

    put_ips(cache, "reuse.com", PDNS_QUERY_IPV4, first, 2, 300);
    pdns_cache_update_ip_rtt(cache, "reuse.com", PDNS_QUERY_IPV4, "2.2.2.2", 42.0f);

    /* 重新下发：2.2.2.2 保留、1.1.1.1 消失、7.7.7.7 新增 */
    put_ips(cache, "reuse.com", PDNS_QUERY_IPV4, again, 2, 300);

    pdns_list_impl_t *out = pdns_list_impl_create();
    float             rtts[8];
    size_t            n = pdns_cache_get_rtts(cache, "reuse.com", PDNS_QUERY_IPV4, out, rtts, 8);

    CuAssertIntEquals(tc, 2, (int) n);
    CuAssertStrEquals(tc, "2.2.2.2", pdns_list_impl_get(out, 0));
    CuAssertDblEquals_Msg(tc, "existing ip should reuse measured rtt", 42.0, rtts[0], 0.01);
    CuAssertStrEquals(tc, "7.7.7.7", pdns_list_impl_get(out, 1));
    CuAssertDblEquals_Msg(tc, "new ip should be untested", PDNS_RTT_DEFAULT, rtts[1], 0.01);

    pdns_list_impl_destroy(out);
    pdns_cache_destroy(cache);
}

/* 否定条目不参与测速排序，get_rtts 返回 0 */
void test_cache_get_rtts_on_negative(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);

    pdns_cache_put(cache, "nx2.com", PDNS_QUERY_IPV4, NULL, 30, true, PDNS_SOURCE_PUBLIC_DNS);

    pdns_list_impl_t *out = pdns_list_impl_create();
    float             rtts[4];
    CuAssertIntEquals_Msg(tc, "negative entry has no rtt snapshot", 0,
                          (int) pdns_cache_get_rtts(cache, "nx2.com", PDNS_QUERY_IPV4, out, rtts, 4));
    pdns_list_impl_destroy(out);
    pdns_cache_destroy(cache);
}

/* get_rtts 受 max_n 截断保护 */
void test_cache_get_rtts_truncation(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    const char *const   ips[] = {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"};

    put_ips(cache, "t.com", PDNS_QUERY_IPV4, ips, 4, 300);

    pdns_list_impl_t *out = pdns_list_impl_create();
    float             rtts[2];
    CuAssertIntEquals_Msg(tc, "result must be capped by max_n", 2,
                          (int) pdns_cache_get_rtts(cache, "t.com", PDNS_QUERY_IPV4, out, rtts, 2));
    CuAssertIntEquals(tc, 2, (int) pdns_list_impl_size(out));
    pdns_list_impl_destroy(out);
    pdns_cache_destroy(cache);
}

/* NULL 入参防护：各接口均不得崩溃 */
void test_cache_null_safety(CuTest *tc) {
    pdns_cache_config_t cfg   = make_cfg(100, false);
    pdns_cache_t       *cache = pdns_cache_create(&cfg);
    pdns_result_list_t *out   = pdns_result_list_create();
    pdns_list_impl_t   *rout  = pdns_list_impl_create();
    float               rtts[2];

    CuAssertIntEquals(tc, PDNS_CACHE_MISS, pdns_cache_get(NULL, "a.com", PDNS_QUERY_IPV4, out));
    CuAssertIntEquals(tc, PDNS_CACHE_MISS, pdns_cache_get(cache, NULL, PDNS_QUERY_IPV4, out));
    CuAssertIntEquals(tc, PDNS_CACHE_MISS, pdns_cache_get(cache, "a.com", PDNS_QUERY_IPV4, NULL));

    pdns_cache_put(NULL, "a.com", PDNS_QUERY_IPV4, NULL, 60, false, PDNS_SOURCE_PUBLIC_DNS);
    pdns_cache_put(cache, NULL, PDNS_QUERY_IPV4, NULL, 60, false, PDNS_SOURCE_PUBLIC_DNS);
    pdns_cache_update_ip_rtt(NULL, "a.com", PDNS_QUERY_IPV4, "1.1.1.1", 1.0f);
    pdns_cache_update_ip_rtt(cache, "a.com", PDNS_QUERY_IPV4, NULL, 1.0f);
    pdns_cache_sort_entry(NULL, "a.com", PDNS_QUERY_IPV4);
    pdns_cache_sort_entry(cache, "missing.com", PDNS_QUERY_IPV4);
    pdns_cache_set_config(cache, NULL);
    pdns_cache_clear(NULL);
    CuAssertIntEquals(tc, 0, (int) pdns_cache_get_rtts(NULL, "a.com", PDNS_QUERY_IPV4, rout, rtts, 2));

    pdns_result_list_cleanup(out);
    pdns_list_impl_destroy(rout);
    pdns_cache_destroy(cache);
    pdns_cache_destroy(NULL);
}

void add_pdns_cache_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_cache_miss);
    SUITE_ADD_TEST(suite, test_cache_hit_and_order);
    SUITE_ADD_TEST(suite, test_cache_get_fills_source_meta);
    SUITE_ADD_TEST(suite, test_cache_key_separates_query_type);
    SUITE_ADD_TEST(suite, test_cache_key_non_v6_maps_to_type1);
    SUITE_ADD_TEST(suite, test_cache_update_overwrites);
    SUITE_ADD_TEST(suite, test_cache_negative_entry);
    SUITE_ADD_TEST(suite, test_cache_stale_trust_window);
    SUITE_ADD_TEST(suite, test_cache_immutable_never_expires);
    SUITE_ADD_TEST(suite, test_cache_lru_eviction);
    SUITE_ADD_TEST(suite, test_cache_max_size_zero_rejects_write);
    SUITE_ADD_TEST(suite, test_cache_set_config_takes_effect);
    SUITE_ADD_TEST(suite, test_cache_clear);
    SUITE_ADD_TEST(suite, test_cache_localdns_not_override_httpdns);
    SUITE_ADD_TEST(suite, test_cache_httpdns_overrides_localdns);
    SUITE_ADD_TEST(suite, test_cache_fusion_public_override_each_other);
    SUITE_ADD_TEST(suite, test_cache_rtt_default_for_new_entry);
    SUITE_ADD_TEST(suite, test_cache_update_rtt_and_sort);
    SUITE_ADD_TEST(suite, test_cache_rtt_reuse_on_update);
    SUITE_ADD_TEST(suite, test_cache_get_rtts_on_negative);
    SUITE_ADD_TEST(suite, test_cache_get_rtts_truncation);
    SUITE_ADD_TEST(suite, test_cache_null_safety);
}
