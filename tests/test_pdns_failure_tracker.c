/*
 * 失败计数器测试 —— 请求维度计数 / 降级判定 / 成功清零 / 过期清理
 *
 * 计数规则：key = domain:type:requestId，
 * 计数达到 fallback_threshold 即触发降级，成功或结束时清零。
 */
#include "test_suite_list.h"
#include "pdns_failure_tracker.h"

#define TK_DOMAIN "www.taobao.com"
#define TK_TYPE   "1"
#define TK_RID    "rid-0001"

/* 未记录过任何失败：不降级 */
void test_tracker_no_failure_no_fallback(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();
    CuAssertPtrNotNull(tc, t);

    CuAssert(tc, "no record -> no fallback",
             !pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, TK_RID, 2));
    CuAssertIntEquals(tc, 0, pdns_failure_tracker_size(t));

    pdns_failure_tracker_destroy(t);
}

/* 失败计数累加到阈值才降级（阈值 2：1 次不降，2 次降） */
void test_tracker_fallback_at_threshold(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();

    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    CuAssertIntEquals(tc, 1, pdns_failure_tracker_size(t));
    CuAssert(tc, "1 failure < threshold 2 -> no fallback",
             !pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, TK_RID, 2));

    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    CuAssertIntEquals_Msg(tc, "same key must not create a second entry", 1,
                          pdns_failure_tracker_size(t));
    CuAssert(tc, "2 failures >= threshold 2 -> fallback",
             pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, TK_RID, 2));

    pdns_failure_tracker_destroy(t);
}

/* threshold=0 表示不给主用机会，直接降级 */
void test_tracker_zero_threshold_always_fallback(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();

    CuAssert(tc, "threshold 0 -> fallback immediately",
             pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, TK_RID, 0));

    pdns_failure_tracker_destroy(t);
}

/* 计数按 domain:type:requestId 隔离：换任一维度都是独立计数 */
void test_tracker_key_isolation(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();

    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    CuAssert(tc, "target request should fallback",
             pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, TK_RID, 2));

    /* 换 requestId：另一次解析不受影响 */
    CuAssert(tc, "another request id is independent",
             !pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, "rid-0002", 2));
    /* 换 type：同域名不同记录类型独立 */
    CuAssert(tc, "another type is independent",
             !pdns_failure_tracker_should_fallback(t, TK_DOMAIN, "28", TK_RID, 2));
    /* 换 domain */
    CuAssert(tc, "another domain is independent",
             !pdns_failure_tracker_should_fallback(t, "www.aliyun.com", TK_TYPE, TK_RID, 2));

    pdns_failure_tracker_destroy(t);
}

/* 成功 / 重置都清零计数 */
void test_tracker_success_and_reset_clear(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();

    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_record_success(t, TK_DOMAIN, TK_TYPE, TK_RID);
    CuAssertIntEquals(tc, 0, pdns_failure_tracker_size(t));
    CuAssert(tc, "success should clear the counter",
             !pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, TK_RID, 2));

    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_reset(t, TK_DOMAIN, TK_TYPE, TK_RID);
    CuAssertIntEquals(tc, 0, pdns_failure_tracker_size(t));

    /* 重复 reset 幂等 */
    pdns_failure_tracker_reset(t, TK_DOMAIN, TK_TYPE, TK_RID);
    CuAssertIntEquals(tc, 0, pdns_failure_tracker_size(t));

    pdns_failure_tracker_destroy(t);
}

/* domain / request_id 为空：不记录也不降级（无法定位记录） */
void test_tracker_empty_key_ignored(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();

    pdns_failure_tracker_record_failure(t, NULL, TK_TYPE, TK_RID);
    pdns_failure_tracker_record_failure(t, "", TK_TYPE, TK_RID);
    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, NULL);
    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, "");
    CuAssertIntEquals_Msg(tc, "invalid keys must not be recorded", 0,
                          pdns_failure_tracker_size(t));

    CuAssert(tc, "NULL domain -> no fallback even with threshold 0",
             !pdns_failure_tracker_should_fallback(t, NULL, TK_TYPE, TK_RID, 0));
    CuAssert(tc, "NULL request id -> no fallback even with threshold 0",
             !pdns_failure_tracker_should_fallback(t, TK_DOMAIN, TK_TYPE, NULL, 0));

    pdns_failure_tracker_destroy(t);
}

/* 清理只淘汰过期条目；刚写入的条目必须保留 */
void test_tracker_cleanup_keeps_fresh(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();

    pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_cleanup_expired(t);
    CuAssertIntEquals_Msg(tc, "fresh entry must survive cleanup", 1,
                          pdns_failure_tracker_size(t));

    pdns_failure_tracker_destroy(t);
}

/* 条目数上限：超限后淘汰最旧条目，总数不越界 */
void test_tracker_capacity_bound(CuTest *tc) {
    pdns_failure_tracker_t *t = pdns_failure_tracker_create();

    char rid[32];
    for (int i = 0; i < PDNS_FAILURE_MAX_ENTRIES + 20; i++) {
        snprintf(rid, sizeof(rid), "rid-%d", i);
        pdns_failure_tracker_record_failure(t, TK_DOMAIN, TK_TYPE, rid);
    }
    CuAssert(tc, "entry count must stay bounded",
             pdns_failure_tracker_size(t) <= PDNS_FAILURE_MAX_ENTRIES);

    pdns_failure_tracker_destroy(t);
}

/* NULL 防护 */
void test_tracker_null_safety(CuTest *tc) {
    pdns_failure_tracker_record_failure(NULL, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_record_success(NULL, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_reset(NULL, TK_DOMAIN, TK_TYPE, TK_RID);
    pdns_failure_tracker_cleanup_expired(NULL);
    pdns_failure_tracker_destroy(NULL);
    CuAssert(tc, "NULL tracker -> no fallback",
             !pdns_failure_tracker_should_fallback(NULL, TK_DOMAIN, TK_TYPE, TK_RID, 0));
    CuAssertIntEquals(tc, 0, pdns_failure_tracker_size(NULL));
}

void add_pdns_failure_tracker_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_tracker_no_failure_no_fallback);
    SUITE_ADD_TEST(suite, test_tracker_fallback_at_threshold);
    SUITE_ADD_TEST(suite, test_tracker_zero_threshold_always_fallback);
    SUITE_ADD_TEST(suite, test_tracker_key_isolation);
    SUITE_ADD_TEST(suite, test_tracker_success_and_reset_clear);
    SUITE_ADD_TEST(suite, test_tracker_empty_key_ignored);
    SUITE_ADD_TEST(suite, test_tracker_cleanup_keeps_fresh);
    SUITE_ADD_TEST(suite, test_tracker_capacity_bound);
    SUITE_ADD_TEST(suite, test_tracker_null_safety);
}
