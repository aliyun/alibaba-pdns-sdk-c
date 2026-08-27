/*
 * 日志模块测试 —— 全局开关 / 级别过滤 / 回调注入
 *
 * 日志是集成方排障的唯一入口：开关失效会污染宿主输出，
 * 级别过滤失效会造成日志量失控，回调失效则集成方无法接管日志。
 */
#include "test_suite_list.h"
#include "pdns_log.h"

/* ---------------- 回调捕获 ---------------- */

#define CAPTURE_MAX 32

static int              g_hits;
static pdns_log_level_t g_levels[CAPTURE_MAX];
static char             g_msgs[CAPTURE_MAX][512];

static void capture_logger(pdns_log_level_t level, const char *msg) {
    if (g_hits < CAPTURE_MAX) {
        g_levels[g_hits] = level;
        snprintf(g_msgs[g_hits], sizeof(g_msgs[0]), "%s", msg ? msg : "");
    }
    g_hits++;
}

/* 每个用例开始时重置捕获状态并接管日志 */
static void capture_begin(void) {
    g_hits = 0;
    memset(g_levels, 0, sizeof(g_levels));
    memset(g_msgs, 0, sizeof(g_msgs));
    pdns_log_init();
    pdns_log_set_logger(capture_logger);
    pdns_log_set_enable(true);
    pdns_log_set_level(PDNS_LOG_LEVEL_DEBUG);
}

/* 用例结束后恢复默认，避免影响其它用例与后续联网用例的输出 */
static void capture_end(void) {
    pdns_log_set_logger(NULL);
    pdns_log_set_enable(false);
    pdns_log_set_level(PDNS_LOG_LEVEL_DEBUG);
}

/* 级别枚举顺序约定：数值越小级别越高（用于阈值过滤） */
void test_log_level_enum_order(CuTest *tc) {
    CuAssert(tc, "ERROR must be the highest level", PDNS_LOG_LEVEL_ERROR < PDNS_LOG_LEVEL_WARN);
    CuAssert(tc, "WARN above INFO", PDNS_LOG_LEVEL_WARN < PDNS_LOG_LEVEL_INFO);
    CuAssert(tc, "INFO above DEBUG", PDNS_LOG_LEVEL_INFO < PDNS_LOG_LEVEL_DEBUG);
}

/* 开关关闭时不得产生任何日志 */
void test_log_disabled_produces_nothing(CuTest *tc) {
    capture_begin();
    pdns_log_set_enable(false);
    CuAssert(tc, "log should report disabled", !pdns_log_is_enabled());

    PDNS_LOGE("error while disabled");
    PDNS_LOGI("info while disabled");
    CuAssertIntEquals_Msg(tc, "disabled log must not invoke logger", 0, g_hits);

    capture_end();
}

/* 开关开启后，注入的回调应收到日志，且内容包含格式化结果 */
void test_log_callback_receives_message(CuTest *tc) {
    capture_begin();
    CuAssert(tc, "log should report enabled", pdns_log_is_enabled());

    PDNS_LOGI("hello %s %d", "pdns", 42);
    CuAssert(tc, "logger should be invoked", g_hits >= 1);
    CuAssert(tc, "formatted args should appear in message",
             strstr(g_msgs[0], "hello pdns 42") != NULL);

    capture_end();
}

/* 日志文本应带 "pdns" 标识，便于集成方在混合日志中筛选 */
void test_log_message_contains_tag(CuTest *tc) {
    capture_begin();
    PDNS_LOGI("tagged message");
    CuAssert(tc, "logger should be invoked", g_hits >= 1);
    CuAssert(tc, "message should carry pdns tag", strstr(g_msgs[0], "pdns") != NULL);
    capture_end();
}

/* 级别过滤：阈值设为 WARN 时，只输出 ERROR / WARN */
void test_log_level_filter_warn(CuTest *tc) {
    capture_begin();
    pdns_log_set_level(PDNS_LOG_LEVEL_WARN);

    PDNS_LOGE("e");
    PDNS_LOGW("w");
    PDNS_LOGI("i");
    PDNS_LOGD("d");

    CuAssertIntEquals_Msg(tc, "only ERROR and WARN should pass", 2, g_hits);
    CuAssertIntEquals(tc, PDNS_LOG_LEVEL_ERROR, (int) g_levels[0]);
    CuAssertIntEquals(tc, PDNS_LOG_LEVEL_WARN, (int) g_levels[1]);

    capture_end();
}

/* 级别过滤：阈值设为 ERROR 时只输出 ERROR */
void test_log_level_filter_error_only(CuTest *tc) {
    capture_begin();
    pdns_log_set_level(PDNS_LOG_LEVEL_ERROR);

    PDNS_LOGE("e");
    PDNS_LOGW("w");
    PDNS_LOGI("i");
    PDNS_LOGD("d");

    CuAssertIntEquals_Msg(tc, "only ERROR should pass", 1, g_hits);
    CuAssertIntEquals(tc, PDNS_LOG_LEVEL_ERROR, (int) g_levels[0]);

    capture_end();
}

/* 级别过滤：阈值设为 DEBUG 时全部输出 */
void test_log_level_filter_debug_passes_all(CuTest *tc) {
    capture_begin();
    pdns_log_set_level(PDNS_LOG_LEVEL_DEBUG);

    PDNS_LOGE("e");
    PDNS_LOGW("w");
    PDNS_LOGI("i");
    PDNS_LOGD("d");

    CuAssertIntEquals_Msg(tc, "all four levels should pass", 4, g_hits);

    capture_end();
}

/* 回调设为 NULL 应恢复默认输出，不得崩溃 */
void test_log_reset_logger(CuTest *tc) {
    capture_begin();
    pdns_log_set_logger(NULL);

    int before = g_hits;
    PDNS_LOGI("goes to default sink");
    CuAssertIntEquals_Msg(tc, "custom logger must not be called after reset", before, g_hits);

    capture_end();
}

/* 超长日志内容不得越界崩溃 */
void test_log_long_message(CuTest *tc) {
    capture_begin();

    char big[4096];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    PDNS_LOGI("%s", big);

    CuAssert(tc, "long message should still be delivered", g_hits >= 1);
    capture_end();
}

/* 级别过滤切换应即时生效 */
void test_log_level_switch_takes_effect(CuTest *tc) {
    capture_begin();

    pdns_log_set_level(PDNS_LOG_LEVEL_ERROR);
    PDNS_LOGI("filtered");
    CuAssertIntEquals(tc, 0, g_hits);

    pdns_log_set_level(PDNS_LOG_LEVEL_INFO);
    PDNS_LOGI("passed");
    CuAssertIntEquals_Msg(tc, "level change should take effect immediately", 1, g_hits);

    capture_end();
}

void add_pdns_log_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_log_level_enum_order);
    SUITE_ADD_TEST(suite, test_log_disabled_produces_nothing);
    SUITE_ADD_TEST(suite, test_log_callback_receives_message);
    SUITE_ADD_TEST(suite, test_log_message_contains_tag);
    SUITE_ADD_TEST(suite, test_log_level_filter_warn);
    SUITE_ADD_TEST(suite, test_log_level_filter_error_only);
    SUITE_ADD_TEST(suite, test_log_level_filter_debug_passes_all);
    SUITE_ADD_TEST(suite, test_log_reset_logger);
    SUITE_ADD_TEST(suite, test_log_long_message);
    SUITE_ADD_TEST(suite, test_log_level_switch_takes_effect);
}
