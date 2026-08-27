/*
 * 线程安全测试（需要外网）
 *
 * 验证 pdns_client_t 可被多线程共享：并发解析、并发读缓存、并发改配置、
 * 并发预解析与网络变化通知都不得崩溃或产生数据竞争导致的错误结果。
 * 这类问题在生产中表现为随机崩溃，单测是最有效的拦截手段。
 */
#include "test_suite_list.h"

#include <apr_thread_proc.h>
#include <apr_thread_mutex.h>
#include <apr_pools.h>
#include <apr_time.h>

#define THREAD_COUNT      8
#define LOOP_PER_THREAD   5

typedef struct {
    pdns_client_t      *client;
    apr_thread_mutex_t *lock;
    int                *ok_count;
    int                *fail_count;
    int                 index;
} worker_arg_t;

static const char *g_hosts[] = {
    "www.taobao.com",
    "www.aliyun.com",
    "www.tmall.com",
    "g.alicdn.com"
};
#define HOST_COUNT ((int) (sizeof(g_hosts) / sizeof(g_hosts[0])))

/* 并发同步解析 */
static void *APR_THREAD_FUNC sync_resolve_worker(apr_thread_t *thd, void *data) {
    worker_arg_t *arg = (worker_arg_t *) data;

    for (int i = 0; i < LOOP_PER_THREAD; i++) {
        const char       *host    = g_hosts[(arg->index + i) % HOST_COUNT];
        pdns_result_list_t *results = NULL;
        pdns_status_t     st      = pdns_resolve_sync(arg->client, host,
                                                                 PDNS_QUERY_IPV4, &results);
        apr_thread_mutex_lock(arg->lock);
        if (st.code == PDNS_OK && pdns_result_list_size(results) > 0) {
            (*arg->ok_count)++;
        } else {
            (*arg->fail_count)++;
        }
        apr_thread_mutex_unlock(arg->lock);
        pdns_result_list_cleanup(results);
    }
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

/* 并发混合操作：解析 + 读缓存 + 改配置 + 预解析 + 通知网络变化 */
static void *APR_THREAD_FUNC mixed_worker(apr_thread_t *thd, void *data) {
    worker_arg_t *arg = (worker_arg_t *) data;

    for (int i = 0; i < LOOP_PER_THREAD; i++) {
        const char *host = g_hosts[(arg->index + i) % HOST_COUNT];

        switch ((arg->index + i) % 5) {
            case 0: {
                pdns_result_list_t *r = NULL;
                pdns_resolve_sync(arg->client, host, PDNS_QUERY_IPV4, &r);
                pdns_result_list_cleanup(r);
                break;
            }
            case 1: {
                pdns_result_list_t *r = NULL;
                pdns_resolve_sync_from_cache(arg->client, host, PDNS_QUERY_IPV4,
                                                         true, &r);
                pdns_result_list_cleanup(r);
                break;
            }
            case 2:
                /* 运行期改配置：与解析路径并发 */
                pdns_client_set_timeout(arg->client, 3000 + (i * 100));
                pdns_client_set_max_cache_size(arg->client, 50 + i);
                pdns_client_set_enable_speed_test(arg->client, (i % 2) == 0);
                break;
            case 3: {
                pdns_domain_list_t *domains = pdns_domain_list_create();
                pdns_domain_list_add(domains, host);
                pdns_client_add_pre_load_domains(arg->client, PDNS_QUERY_IPV4, domains);
                pdns_domain_list_cleanup(domains);
                break;
            }
            default:
                pdns_on_network_changed();
                break;
        }
    }
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

/* 并发异步解析（回调在 SDK 线程执行，需保证回调计数正确） */
typedef struct {
    apr_thread_mutex_t *lock;
    int                 cb_count;
} async_shared_t;

static async_shared_t g_async_shared;

static void concurrent_async_cb(const char *host, pdns_query_type_t query_type,
                                pdns_result_list_t *results, void *user_data) {
    (void) host;
    (void) query_type;
    (void) results;
    (void) user_data;
    apr_thread_mutex_lock(g_async_shared.lock);
    g_async_shared.cb_count++;
    apr_thread_mutex_unlock(g_async_shared.lock);
}

/* 用给定 worker 跑满 THREAD_COUNT 个线程并等待结束 */
static void run_workers(CuTest *tc, pdns_client_t *client,
                        apr_thread_start_t fn, int *ok, int *fail) {
    apr_pool_t         *pool = NULL;
    apr_thread_mutex_t *lock = NULL;

    CuAssertIntEquals(tc, APR_SUCCESS, apr_pool_create(&pool, NULL));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      apr_thread_mutex_create(&lock, APR_THREAD_MUTEX_DEFAULT, pool));

    apr_thread_t *threads[THREAD_COUNT];
    worker_arg_t  args[THREAD_COUNT];

    for (int i = 0; i < THREAD_COUNT; i++) {
        args[i].client     = client;
        args[i].lock       = lock;
        args[i].ok_count   = ok;
        args[i].fail_count = fail;
        args[i].index      = i;
        CuAssertIntEquals_Msg(tc, "thread create should succeed", APR_SUCCESS,
                              apr_thread_create(&threads[i], NULL, fn, &args[i], pool));
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        apr_status_t rv = APR_SUCCESS;
        apr_thread_join(&rv, threads[i]);
    }

    apr_thread_mutex_destroy(lock);
    apr_pool_destroy(pool);
}

/* 多线程共享同一 client 做同步解析 */
void test_thread_safe_concurrent_sync_resolve(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());

    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_timeout(client, 5000);
    pdns_client_set_enable_cache(client, true);
    pdns_client_start(client);

    int ok = 0, fail = 0;
    run_workers(tc, client, sync_resolve_worker, &ok, &fail);

    CuAssertIntEquals_Msg(tc, "all concurrent resolves should be accounted",
                          THREAD_COUNT * LOOP_PER_THREAD, ok + fail);
    /* 允许个别网络抖动，但绝大多数应成功 */
    CuAssert(tc, "most concurrent resolves should succeed", ok > (ok + fail) / 2);

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 多线程混合操作：解析 / 读缓存 / 改配置 / 预解析 / 网络变化 */
void test_thread_safe_mixed_operations(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());

    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_timeout(client, 5000);
    pdns_client_start(client);

    int ok = 0, fail = 0;
    run_workers(tc, client, mixed_worker, &ok, &fail);

    /* 断言点是「不崩溃、不死锁」——能走到这里即通过 */
    CuAssert(tc, "mixed concurrent operations should not crash or deadlock", true);

    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 并发提交异步解析：所有任务都应被回调（不丢任务、不重复回调） */
void test_thread_safe_concurrent_async(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());

    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_timeout(client, 5000);
    pdns_client_start(client);

    apr_pool_t *pool = NULL;
    CuAssertIntEquals(tc, APR_SUCCESS, apr_pool_create(&pool, NULL));
    g_async_shared.cb_count = 0;
    CuAssertIntEquals(tc, APR_SUCCESS,
                      apr_thread_mutex_create(&g_async_shared.lock,
                                              APR_THREAD_MUTEX_DEFAULT, pool));

    const int submitted = HOST_COUNT * 2;
    for (int i = 0; i < submitted; i++) {
        pdns_status_t st = pdns_resolve_async(client, g_hosts[i % HOST_COUNT],
                                                         (i % 2) ? PDNS_QUERY_IPV4
                                                                 : PDNS_QUERY_IPV6,
                                                         concurrent_async_cb, NULL);
        CuAssertIntEquals_Msg(tc, "async submit should succeed", PDNS_OK, st.code);
    }

    /* 最多等 15 秒收齐回调 */
    for (int i = 0; i < 150; i++) {
        apr_thread_mutex_lock(g_async_shared.lock);
        int done = g_async_shared.cb_count;
        apr_thread_mutex_unlock(g_async_shared.lock);
        if (done >= submitted) {
            break;
        }
        apr_sleep(100 * 1000);
    }

    apr_thread_mutex_lock(g_async_shared.lock);
    CuAssertIntEquals_Msg(tc, "every async task must be called back exactly once",
                          submitted, g_async_shared.cb_count);
    apr_thread_mutex_unlock(g_async_shared.lock);

    apr_thread_mutex_destroy(g_async_shared.lock);
    g_async_shared.lock = NULL;
    apr_pool_destroy(pool);
    pdns_client_cleanup(client);
    pdns_sdk_cleanup();
}

/* 多 client 实例并发：各自独立的缓存/调度器互不干扰 */
void test_thread_safe_multi_client(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());

    pdns_client_t *c1 = pdns_test_client_create();
    pdns_client_t *c2 = pdns_test_client_create();
    CuAssertPtrNotNull(tc, c1);
    CuAssertPtrNotNull(tc, c2);
    pdns_client_set_timeout(c1, 5000);
    pdns_client_set_timeout(c2, 5000);
    pdns_client_start(c1);
    pdns_client_start(c2);

    int ok1 = 0, fail1 = 0;
    int ok2 = 0, fail2 = 0;
    run_workers(tc, c1, sync_resolve_worker, &ok1, &fail1);
    run_workers(tc, c2, sync_resolve_worker, &ok2, &fail2);

    CuAssert(tc, "client1 should mostly succeed", ok1 > (ok1 + fail1) / 2);
    CuAssert(tc, "client2 should mostly succeed", ok2 > (ok2 + fail2) / 2);

    /* 先释放 c1，再用 c2 解析：验证 client 之间无共享状态被误释放
     * （全局 detector 的回调必须按 owner 精确摘除） */
    pdns_client_cleanup(c1);

    pdns_result_list_t *r = NULL;
    pdns_status_t     st = pdns_resolve_sync(c2, PDNS_TEST_HOST, PDNS_QUERY_IPV4, &r);
    CuAssertIntEquals_Msg(tc, st.error_msg, PDNS_OK, st.code);
    CuAssert(tc, "surviving client must still work after sibling cleanup",
             pdns_result_list_size(r) > 0);
    pdns_result_list_cleanup(r);

    pdns_client_cleanup(c2);
    pdns_sdk_cleanup();
}

/* 解析进行中执行 cleanup：不得崩溃（任务取消与资源回收顺序正确） */
void test_thread_safe_cleanup_during_resolve(CuTest *tc) {
    CuAssertIntEquals(tc, PDNS_OK, pdns_sdk_init());

    pdns_client_t *client =
        pdns_test_client_create();
    CuAssertPtrNotNull(tc, client);
    pdns_client_set_timeout(client, 5000);
    pdns_client_set_enable_speed_test(client, true);
    pdns_client_start(client);

    /* 提交一批异步任务与预解析后立即 cleanup */
    for (int i = 0; i < HOST_COUNT; i++) {
        pdns_resolve_async(client, g_hosts[i], PDNS_QUERY_IPV4, NULL, NULL);
    }
    pdns_domain_list_t *domains = pdns_domain_list_create();
    for (int i = 0; i < HOST_COUNT; i++) {
        pdns_domain_list_add(domains, g_hosts[i]);
    }
    pdns_client_add_pre_load_domains(client, PDNS_QUERY_IPV4, domains);
    pdns_client_set_keep_alive_domains(client, domains);
    pdns_domain_list_cleanup(domains);

    pdns_client_cleanup(client);   /* 关键：在飞任务未完成时释放 */
    pdns_sdk_cleanup();

    CuAssert(tc, "cleanup with in-flight tasks should not crash", true);
}

void add_pdns_thread_safe_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_thread_safe_concurrent_sync_resolve);
    SUITE_ADD_TEST(suite, test_thread_safe_mixed_operations);
    SUITE_ADD_TEST(suite, test_thread_safe_concurrent_async);
    SUITE_ADD_TEST(suite, test_thread_safe_multi_client);
    SUITE_ADD_TEST(suite, test_thread_safe_cleanup_during_resolve);
}
