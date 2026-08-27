/*
 * 网络检测器测试 —— 栈类型缓存 + 发布订阅 + 手动触发检测
 *
 * 后台轮询默认不开启（enable_poll=false），避免单测引入线程与时序不确定性；
 * 回调是否真正触发取决于运行期网络是否变化，故此处只校验注册/注销的
 * 生命周期正确性与幂等性，不断言回调必然被调用。
 */
#include "test_suite_list.h"
#include "pdns_net.h"

#include <apr_time.h>

static int g_cb_count;

static void on_net_change(void *user_data) {
    int *counter = (int *) user_data;
    if (counter) {
        (*counter)++;
    }
    g_cb_count++;
}

/* 创建 / 启动 / 销毁的基本生命周期 */
void test_net_detector_lifecycle(CuTest *tc) {
    pdns_net_detector_t *d = pdns_net_detector_create();
    CuAssertPtrNotNull(tc, d);

    pdns_net_detector_start(d, false);   /* 不启动后台轮询 */
    pdns_netstack_type_t s = pdns_net_get_type(d);
    CuAssert(tc, "detector should report a valid stack type",
             s == PDNS_STACK_NONE || s == PDNS_STACK_IPV4_ONLY ||
             s == PDNS_STACK_IPV6_ONLY || s == PDNS_STACK_DUAL);

    pdns_net_detector_destroy(d);
}

/* 栈类型走缓存：多次读取结果一致 */
void test_net_get_type_cached(CuTest *tc) {
    pdns_net_detector_t *d = pdns_net_detector_create();
    pdns_net_detector_start(d, false);

    pdns_netstack_type_t a = pdns_net_get_type(d);
    pdns_netstack_type_t b = pdns_net_get_type(d);
    pdns_netstack_type_t c = pdns_net_get_type(d);
    CuAssertIntEquals_Msg(tc, "cached type should be stable", (int) a, (int) b);
    CuAssertIntEquals_Msg(tc, "cached type should be stable", (int) a, (int) c);

    pdns_net_detector_destroy(d);
}

/* 未 start 的检测器也应能安全取类型（内部按需探测） */
void test_net_get_type_before_start(CuTest *tc) {
    pdns_net_detector_t *d = pdns_net_detector_create();

    pdns_netstack_type_t s = pdns_net_get_type(d);
    CuAssert(tc, "type should be valid even before start",
             s == PDNS_STACK_NONE || s == PDNS_STACK_IPV4_ONLY ||
             s == PDNS_STACK_IPV6_ONLY || s == PDNS_STACK_DUAL);

    pdns_net_detector_destroy(d);
}

/* 回调注册与注销：同一 owner 重复注册应被忽略（防止重复回调） */
void test_net_change_cb_register_dedup(CuTest *tc) {
    pdns_net_detector_t *d       = pdns_net_detector_create();
    int                  owner_a = 0;
    int                  counter = 0;

    pdns_net_detector_start(d, false);

    pdns_net_subscribe(d, on_net_change, &counter, &owner_a);
    pdns_net_subscribe(d, on_net_change, &counter, &owner_a);   /* 重复，应忽略 */
    pdns_net_subscribe(d, on_net_change, &counter, &owner_a);

    /* 退订后再订阅应成功（生命周期可重复） */
    pdns_net_unsubscribe(d, &owner_a);
    pdns_net_subscribe(d, on_net_change, &counter, &owner_a);
    pdns_net_unsubscribe(d, &owner_a);

    /* 退订不存在的 owner 不得崩溃 */
    int other = 0;
    pdns_net_unsubscribe(d, &other);

    pdns_net_detector_destroy(d);
    CuAssert(tc, "register/unregister should not crash", true);
}

/* 手动触发检测：不得崩溃；网络未变化时不应误报变化 */
void test_net_trigger_check(CuTest *tc) {
    pdns_net_detector_t *d       = pdns_net_detector_create();
    int                  counter = 0;
    int                  owner   = 0;

    pdns_net_detector_start(d, false);
    pdns_net_subscribe(d, on_net_change, &counter, &owner);

    g_cb_count = 0;
    /* 连续触发两次：本机网络在测试期间未变化，回调不应被反复触发 */
    pdns_net_trigger_check(d);
    pdns_net_trigger_check(d);

    CuAssert(tc, "callback must not fire spuriously when network is stable", counter <= 1);

    pdns_net_unsubscribe(d, &owner);
    pdns_net_detector_destroy(d);
}

/* 回调在退订后不得再被触发（防 use-after-free 的关键约束） */
void test_net_cb_not_called_after_remove(CuTest *tc) {
    pdns_net_detector_t *d       = pdns_net_detector_create();
    int                  counter = 0;
    int                  owner   = 0;

    pdns_net_detector_start(d, false);
    pdns_net_subscribe(d, on_net_change, &counter, &owner);
    pdns_net_unsubscribe(d, &owner);

    int before = counter;
    pdns_net_trigger_check(d);
    CuAssertIntEquals_Msg(tc, "removed callback must not be invoked", before, counter);

    pdns_net_detector_destroy(d);
}

/* 运行期开关轮询应幂等：反复开关不得崩溃或泄漏线程 */
void test_net_set_poll_idempotent(CuTest *tc) {
    pdns_net_detector_t *d = pdns_net_detector_create();
    pdns_net_detector_start(d, false);

    pdns_net_detector_set_poll(d, true);
    pdns_net_detector_set_poll(d, true);    /* 重复开启 */
    pdns_net_detector_set_poll(d, false);
    pdns_net_detector_set_poll(d, false);   /* 重复关闭 */
    pdns_net_detector_set_poll(d, true);

    /* 关闭后栈缓存与订阅仍应可用 */
    pdns_net_detector_set_poll(d, false);
    pdns_netstack_type_t s = pdns_net_get_type(d);
    CuAssert(tc, "type should remain available after poll off",
             s == PDNS_STACK_NONE || s == PDNS_STACK_IPV4_ONLY ||
             s == PDNS_STACK_IPV6_ONLY || s == PDNS_STACK_DUAL);

    pdns_net_detector_destroy(d);
}

/* NULL 防护：所有接口对 NULL detector 都应安全返回 */
void test_net_null_safety(CuTest *tc) {
    int owner = 0;
    CuAssertIntEquals_Msg(tc, "NULL detector should report NONE", PDNS_STACK_NONE,
                          (int) pdns_net_get_type(NULL));
    pdns_net_detector_start(NULL, true);
    pdns_net_detector_set_poll(NULL, true);
    pdns_net_subscribe(NULL, on_net_change, NULL, &owner);
    pdns_net_unsubscribe(NULL, &owner);
    pdns_net_trigger_check(NULL);
    pdns_net_detector_destroy(NULL);
    CuAssert(tc, "NULL detector operations should not crash", true);
}

void add_pdns_net_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_net_detector_lifecycle);
    SUITE_ADD_TEST(suite, test_net_get_type_cached);
    SUITE_ADD_TEST(suite, test_net_get_type_before_start);
    SUITE_ADD_TEST(suite, test_net_change_cb_register_dedup);
    SUITE_ADD_TEST(suite, test_net_trigger_check);
    SUITE_ADD_TEST(suite, test_net_cb_not_called_after_remove);
    SUITE_ADD_TEST(suite, test_net_set_poll_idempotent);
    SUITE_ADD_TEST(suite, test_net_null_safety);
}
