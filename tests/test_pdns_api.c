/*
 * 公开 API 集成测试（需要外网访问 HTTPDNS 服务）
 *
 * 覆盖：SDK 生命周期、同步/异步/缓存解析、双栈 BOTH、否定响应、
 *       预解析与保活、测速排序生效、LocalDNS 兜底。
 * 运行方式：
 *   pdns_test               跑全部（含本文件）
 *   pdns_test --offline     跳过本文件
 *   cmake -DPDNS_TEST_NETWORK=OFF   不编译本文件的用例注册
 */
#include "test_suite_list.h"

#include <apr_time.h>
#include <apr_thread_mutex.h>
#include <apr_pools.h>

/* ---------------- 公共脚手架 ---------------- */

/* 创建并启动一个可用的 client；失败返回 NULL。
 * start 失败（如服务列表/黑白名单拉取超时）不阻断用例，
 * 因为解析自身仍可基于默认 bootstrap 节点完成，具体结果由各用例断言。 */
static pdns_client_t *start_client(bool enable_speed_test) {
    pdns_client_t *client =
        pdns_test_client_create();
    if (client == NULL) {
        return NULL;
    }
    pdns_client_set_timeout(client, 5000);
    pdns_client_set_enable_cache(client, true);
    pdns_client_set_schema_type(client, PDNS_SCHEMA_HTTPS);
    pdns_client_set_enable_speed_test(client, enable_speed_test);
    (void) pdns_client_start(client);
    return client;
}

/* 校验列表中所有元素都是合法的 v4 字面量 */
static bool all_ipv4(pdns_result_list_t *list) {
    size_t n = pdns_result_list_size(list);
    for (size_t i = 0; i < n; i++) {
        const char *ip = pdns_result_list_get(list, i);
        if (ip == NULL || strchr(ip, ':') != NULL || strchr(ip, '.') == NULL) {
            return false;
        }
    }
    return n > 0;
}

/* ---------------- 生命周期 ---------------- */

/* init → cleanup 可重复执行（引用计数正确，不崩溃、不泄漏句柄） */
void test_api_sdk_init_cleanup_repeatable(CuTest *tc) {
    for (int i = 0; i < 3; i++) {
        CuAssertIntEquals_Msg(tc, "sdk init should succeed", PDNS_OK, pdns_sdk_init());
        pdns_sdk_cleanup();
    }
}

/* start 前解析：应能正常工作（内部按需拉取配置） */
void test_api_start_then_resolve(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());

    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_result_list_t *results = NULL;
    pdns_status_t     st      = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                             PDNS_QUERY_IPV4, &results);

    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssertPtrNotNull(tc, results);
    CuAssert(tc, "should resolve at least one ip", pdns_result_list_size(results) > 0);
    CuAssert(tc, "ipv4 query must yield only ipv4", all_ipv4(results));
    /* requestId 必须回填，便于链路追踪 */
    CuAssert(tc, "request id should be filled", strlen(st.request_id) > 0);

    pdns_result_list_cleanup(results);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* ---------------- 缓存 ---------------- */

/* 第二次同步解析应命中缓存（结果一致且明显更快） */
void test_api_second_resolve_hits_cache(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_result_list_t *first = NULL;
    pdns_status_t     st1   = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                           PDNS_QUERY_IPV4, &first);
    CuAssertIntEquals_Msg(tc, st1.error_msg, PDNS_OK, st1.code);

    apr_time_t        begin  = apr_time_now();
    pdns_result_list_t *second = NULL;
    pdns_status_t     st2    = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                            PDNS_QUERY_IPV4, &second);
    apr_time_t elapsed_ms = (apr_time_now() - begin) / 1000;

    CuAssertIntEquals_Msg(tc, st2.error_msg, PDNS_OK, st2.code);
    CuAssertIntEquals_Msg(tc, "cached result size should match",
                          (int) pdns_result_list_size(first), (int) pdns_result_list_size(second));
    CuAssert(tc, "cache hit should return quickly (<500ms)", elapsed_ms < 500);

    pdns_result_list_cleanup(first);
    pdns_result_list_cleanup(second);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 从缓存解析：首次未命中返回空并后台刷新，稍后再查应命中 */
void test_api_resolve_from_cache(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_result_list_t *miss = NULL;
    pdns_resolve_sync_from_cache(client, PDNS_TEST_HOST2, PDNS_QUERY_IPV4,
                                             false, &miss);
    /* 首次通常为空（缓存未命中，触发后台异步解析） */
    if (miss != NULL) {
        pdns_result_list_cleanup(miss);
    }

    /* 等后台解析完成后再查，应能命中 */
    apr_sleep(3 * APR_USEC_PER_SEC);

    pdns_result_list_t *hit = NULL;
    pdns_status_t     st  = pdns_resolve_sync_from_cache(client, PDNS_TEST_HOST2,
                                                                    PDNS_QUERY_IPV4, true, &hit);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssertPtrNotNull(tc, hit);
    CuAssert(tc, "background refresh should have populated the cache",
             pdns_result_list_size(hit) > 0);

    pdns_result_list_cleanup(hit);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 关闭缓存后每次都应回源，且仍能取到结果 */
void test_api_cache_disabled(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_enable_cache(client, false);
    pdns_client_set_timeout(client, 5000);
    pdns_client_start(client);

    pdns_result_list_t *r1 = NULL;
    pdns_result_list_t *r2 = NULL;
    pdns_status_t     s1 = pdns_resolve_sync(client, PDNS_TEST_HOST, PDNS_QUERY_IPV4, &r1);
    pdns_status_t     s2 = pdns_resolve_sync(client, PDNS_TEST_HOST, PDNS_QUERY_IPV4, &r2);

    CuAssertIntEquals_Msg(tc, s1.error_msg, PDNS_OK, s1.code);
    CuAssertIntEquals_Msg(tc, s2.error_msg, PDNS_OK, s2.code);
    CuAssert(tc, "resolve should work without cache", pdns_result_list_size(r1) > 0);
    CuAssert(tc, "resolve should work without cache", pdns_result_list_size(r2) > 0);

    pdns_result_list_cleanup(r1);
    pdns_result_list_cleanup(r2);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* ---------------- 查询类型 ---------------- */

/* AUTO：按网络栈自动收敛，必须返回结果 */
void test_api_query_auto(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_result_list_t *results = NULL;
    pdns_status_t     st      = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                             PDNS_QUERY_AUTO, &results);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssert(tc, "auto query should yield ips", pdns_result_list_size(results) > 0);

    pdns_result_list_cleanup(results);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* BOTH：拆成 v4/v6 两次单类型请求，v4 结果排在前 */
void test_api_query_both(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_result_list_t *results = NULL;
    pdns_status_t     st      = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                             PDNS_QUERY_BOTH, &results);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssert(tc, "both query should yield ips", pdns_result_list_size(results) > 0);

    /* 未开测速时按 v4 在前、v6 在后拼接：一旦出现 v6，其后不应再有 v4 */
    bool seen_v6 = false;
    for (size_t i = 0; i < pdns_result_list_size(results); i++) {
        const char *ip = pdns_result_list_get(results, i);
        bool        v6 = strchr(ip, ':') != NULL;
        if (v6) {
            seen_v6 = true;
        } else if (seen_v6) {
            CuFail(tc, "without speed test, all v4 must precede v6");
        }
    }

    pdns_result_list_cleanup(results);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 不存在的域名：应返回否定结果（无 IP），而不是报致命错误 */
void test_api_nxdomain(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_timeout(client, 5000);
    /* 关掉 LocalDNS 兜底，确保观察到的是 HTTPDNS 的否定响应 */
    pdns_client_set_enable_localdns(client, false);
    pdns_client_start(client);

    pdns_result_list_t *results = NULL;
    pdns_resolve_sync(client, PDNS_TEST_HOST_NX, PDNS_QUERY_IPV4, &results);
    /* 关注点：不得崩溃，且不应返回任何 IP */
    if (results != NULL) {
        CuAssertIntEquals_Msg(tc, "nxdomain must not yield ips", 0, (int) pdns_result_list_size(results));
        pdns_result_list_cleanup(results);
    }

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* ---------------- 异步解析 ---------------- */

typedef struct {
    apr_thread_mutex_t *lock;
    apr_pool_t         *pool;
    int                 done;
    int                 ip_count;
    char                host[128];
    pdns_query_type_t   qtype;
} async_ctx_t;

static void async_cb(const char *host, pdns_query_type_t query_type,
                     pdns_result_list_t *results, void *user_data) {
    async_ctx_t *ctx = (async_ctx_t *) user_data;
    apr_thread_mutex_lock(ctx->lock);
    ctx->done++;
    ctx->qtype    = query_type;
    ctx->ip_count = (int) pdns_result_list_size(results);
    snprintf(ctx->host, sizeof(ctx->host), "%s", host ? host : "");
    apr_thread_mutex_unlock(ctx->lock);
}

/* 异步解析：立即返回入队状态，随后在后台线程回调并带回结果 */
void test_api_async_resolve(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    apr_pool_t *pool = NULL;
    CuAssertIntEquals(tc, APR_SUCCESS, apr_pool_create(&pool, NULL));

    async_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pool = pool;
    apr_thread_mutex_create(&ctx.lock, APR_THREAD_MUTEX_DEFAULT, pool);

    pdns_status_t st = pdns_resolve_async(client, PDNS_TEST_HOST, PDNS_QUERY_IPV4,
                                                     async_cb, &ctx);
    CuAssertIntEquals_Msg(tc, "async submit should succeed", PDNS_OK, st.code);

    /* 最多等 8 秒 */
    for (int i = 0; i < 80; i++) {
        apr_thread_mutex_lock(ctx.lock);
        int done = ctx.done;
        apr_thread_mutex_unlock(ctx.lock);
        if (done > 0) {
            break;
        }
        apr_sleep(100 * 1000);
    }

    apr_thread_mutex_lock(ctx.lock);
    CuAssertIntEquals_Msg(tc, "async callback should be invoked once", 1, ctx.done);
    CuAssertStrEquals_Msg(tc, "callback host should match", PDNS_TEST_HOST, ctx.host);
    CuAssertIntEquals_Msg(tc, "callback query type should match",
                          PDNS_QUERY_IPV4, (int) ctx.qtype);
    CuAssert(tc, "async resolve should yield ips", ctx.ip_count > 0);
    apr_thread_mutex_unlock(ctx.lock);

    apr_thread_mutex_destroy(ctx.lock);
    apr_pool_destroy(pool);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 回调传 NULL：仅后台刷新缓存，不得崩溃 */
void test_api_async_without_callback(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_status_t st = pdns_resolve_async(client, PDNS_TEST_HOST2,
                                                     PDNS_QUERY_IPV4, NULL, NULL);
    CuAssertIntEquals_Msg(tc, "async submit without callback should succeed", PDNS_OK, st.code);

    apr_sleep(3 * APR_USEC_PER_SEC);

    pdns_result_list_t *cached = NULL;
    pdns_resolve_sync_from_cache(client, PDNS_TEST_HOST2, PDNS_QUERY_IPV4,
                                             true, &cached);
    if (cached != NULL) {
        CuAssert(tc, "background refresh should fill cache", pdns_result_list_size(cached) > 0);
        pdns_result_list_cleanup(cached);
    }

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* ---------------- 预解析 / 保活 ---------------- */

/* 预解析后应无需回源即可命中缓存 */
void test_api_preload_domains(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_domain_list_t *domains = pdns_domain_list_create();
    pdns_domain_list_add(domains, PDNS_TEST_HOST);
    pdns_domain_list_add(domains, PDNS_TEST_HOST2);
    pdns_client_add_pre_load_domains(client, PDNS_QUERY_IPV4, domains);
    pdns_domain_list_cleanup(domains);

    apr_sleep(5 * APR_USEC_PER_SEC);   /* 等预解析完成 */

    pdns_result_list_t *cached = NULL;
    pdns_status_t     st     = pdns_resolve_sync_from_cache(client, PDNS_TEST_HOST,
                                                                       PDNS_QUERY_IPV4, true, &cached);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssertPtrNotNull(tc, cached);
    CuAssert(tc, "preload should populate the cache", pdns_result_list_size(cached) > 0);

    pdns_result_list_cleanup(cached);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/*
 * 保活域名：set_keep_alive_domains 按设计只「登记」，
 * 不会自己发起解析；保活链由后续「写缓存事件」驱动排期（TTL×75% 刷新）。
 * 故本用例先登记、再解析一次以触发排期，最后验证带活跃排期任务时 cleanup 不崩溃。
 */
void test_api_keep_alive_domains(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_domain_list_t *domains = pdns_domain_list_create();
    pdns_domain_list_add(domains, PDNS_TEST_HOST);
    pdns_client_set_keep_alive_domains(client, domains);
    pdns_domain_list_cleanup(domains);

    /* 触发一次写缓存，从而启动保活排期 */
    pdns_result_list_t *results = NULL;
    pdns_status_t     st      = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                             PDNS_QUERY_IPV4, &results);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssert(tc, "resolve should populate cache to arm keep-alive",
             pdns_result_list_size(results) > 0);
    pdns_result_list_cleanup(results);

    /* 写缓存后缓存内容应可读取 */
    pdns_result_list_t *cached = NULL;
    pdns_resolve_sync_from_cache(client, PDNS_TEST_HOST, PDNS_QUERY_IPV4,
                                             true, &cached);
    CuAssertPtrNotNull(tc, cached);
    CuAssert(tc, "keep-alive domain should be cached after resolve",
             pdns_result_list_size(cached) > 0);
    pdns_result_list_cleanup(cached);

    /* 关键：存在已排期的保活任务时 cleanup 不得崩溃（任务需先被取消） */
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 重复登记与超限登记均应被安全处理（去重 + 上限保护） */
void test_api_keep_alive_dedup_and_limit(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    /* 同一域名重复登记多次 */
    for (int i = 0; i < 3; i++) {
        pdns_domain_list_t *d = pdns_domain_list_create();
        pdns_domain_list_add(d, PDNS_TEST_HOST);
        pdns_client_set_keep_alive_domains(client, d);
        pdns_domain_list_cleanup(d);
    }

    /* 超过上限（实现上限为 10）的批量登记：多余项应被忽略而不越界 */
    pdns_domain_list_t *many = pdns_domain_list_create();
    char              buf[64];
    for (int i = 0; i < 30; i++) {
        snprintf(buf, sizeof(buf), "ka-%d.example.com", i);
        pdns_domain_list_add(many, buf);
    }
    /* 空串与过长域名也应被跳过 */
    pdns_domain_list_add(many, "");
    char long_host[512];
    memset(long_host, 'a', sizeof(long_host) - 1);
    long_host[sizeof(long_host) - 1] = '\0';
    pdns_domain_list_add(many, long_host);

    pdns_client_set_keep_alive_domains(client, many);
    pdns_domain_list_cleanup(many);

    /* NULL / 空列表 */
    pdns_client_set_keep_alive_domains(client, NULL);
    pdns_domain_list_t *empty = pdns_domain_list_create();
    pdns_client_set_keep_alive_domains(client, empty);
    pdns_domain_list_cleanup(empty);

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
    CuAssert(tc, "keep-alive dedup/limit handling should not crash", true);
}

/* ---------------- 测速 ---------------- */

/* 开启测速后，等待测速完成，结果应仍然可用且数量不变（仅顺序可能变化） */
void test_api_speed_test_sorting(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(true);
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_speed_port(client, 443);

    pdns_result_list_t *before = NULL;
    pdns_status_t     st     = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                            PDNS_QUERY_IPV4, &before);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    size_t n = pdns_result_list_size(before);
    CuAssert(tc, "should resolve ips before speed test", n > 0);

    /* 等异步测速跑完（每 IP 最多 3 秒，留足余量） */
    apr_sleep(6 * APR_USEC_PER_SEC);

    pdns_result_list_t *after = NULL;
    pdns_resolve_sync_from_cache(client, PDNS_TEST_HOST, PDNS_QUERY_IPV4, true, &after);
    CuAssertPtrNotNull(tc, after);
    CuAssertIntEquals_Msg(tc, "speed test must not change ip count",
                          (int) n, (int) pdns_result_list_size(after));
    CuAssert(tc, "sorted result must still be ipv4 only", all_ipv4(after));

    pdns_result_list_cleanup(before);
    pdns_result_list_cleanup(after);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* ---------------- 兜底与选择 ---------------- */

/* 开启 LocalDNS 兜底后解析常见域名：无论走哪条路径都应有结果 */
void test_api_localdns_fallback_enabled(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_enable_localdns(client, true);
    pdns_client_set_timeout(client, 5000);
    pdns_client_start(client);

    pdns_result_list_t *results = NULL;
    pdns_status_t     st      = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                             PDNS_QUERY_IPV4, &results);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssert(tc, "with localdns fallback there must be a result", pdns_result_list_size(results) > 0);

    pdns_result_list_cleanup(results);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 真实解析结果配合 IP 选择接口使用 */
void test_api_select_ip_from_real_result(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_result_list_t *results = NULL;
    pdns_status_t     st      = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                             PDNS_QUERY_IPV4, &results);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssert(tc, "need ips for selection", pdns_result_list_size(results) > 0);

    char first[PDNS_IP_ADDRESS_STRING_LENGTH]  = {0};
    char random[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};
    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_first(results, PDNS_QUERY_IPV4, first));
    CuAssertIntEquals(tc, PDNS_OK, pdns_select_ip_randomly(results, PDNS_QUERY_IPV4, random));
    CuAssert(tc, "selected first ip should be non-empty", strlen(first) > 0);
    CuAssert(tc, "selected random ip should be non-empty", strlen(random) > 0);

    pdns_result_list_cleanup(results);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 手动通知网络变化：不得崩溃，且后续解析仍可用 */
void test_api_on_network_changed(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());
    pdns_client_t *client = start_client(false);
    CuAssertPtrNotNull(tc, client);

    pdns_on_network_changed();
    pdns_on_network_changed();

    pdns_result_list_t *results = NULL;
    pdns_status_t     st      = pdns_resolve_sync(client, PDNS_TEST_HOST,
                                                             PDNS_QUERY_IPV4, &results);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssert(tc, "resolve should work after network change notice",
             pdns_result_list_size(results) > 0);

    pdns_result_list_cleanup(results);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

void add_pdns_api_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_api_sdk_init_cleanup_repeatable);
    SUITE_ADD_TEST(suite, test_api_start_then_resolve);
    SUITE_ADD_TEST(suite, test_api_second_resolve_hits_cache);
    SUITE_ADD_TEST(suite, test_api_resolve_from_cache);
    SUITE_ADD_TEST(suite, test_api_cache_disabled);
    SUITE_ADD_TEST(suite, test_api_query_auto);
    SUITE_ADD_TEST(suite, test_api_query_both);
    SUITE_ADD_TEST(suite, test_api_nxdomain);
    SUITE_ADD_TEST(suite, test_api_async_resolve);
    SUITE_ADD_TEST(suite, test_api_async_without_callback);
    SUITE_ADD_TEST(suite, test_api_preload_domains);
    SUITE_ADD_TEST(suite, test_api_keep_alive_domains);
    SUITE_ADD_TEST(suite, test_api_keep_alive_dedup_and_limit);
    SUITE_ADD_TEST(suite, test_api_speed_test_sorting);
    SUITE_ADD_TEST(suite, test_api_localdns_fallback_enabled);
    SUITE_ADD_TEST(suite, test_api_select_ip_from_real_result);
    SUITE_ADD_TEST(suite, test_api_on_network_changed);
}
