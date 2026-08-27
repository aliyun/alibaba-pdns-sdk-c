/*
 * 工具模块测试 —— requestId / sessionId 生成
 *
 * requestId 用于全链路日志追踪，sessionId 随请求 &did= 上报，
 * 两者若重复或格式错误会直接影响服务端日志聚合，需保证唯一性与格式。
 */
#include "test_suite_list.h"
#include "pdns_util.h"

/* requestId 格式：{platform}_{16位hex}_{16位hex}，且长度受 PDNS_REQUEST_ID_LEN 约束 */
void test_request_id_format(CuTest *tc) {
    char id[PDNS_REQUEST_ID_LEN] = {0};

    pdns_util_init();
    pdns_gen_request_id(id, sizeof(id));

    size_t len = strlen(id);
    CuAssert(tc, "request id should not be empty", len > 0);
    CuAssert(tc, "request id should fit in buffer", len < PDNS_REQUEST_ID_LEN);

    /* 必须包含两个 '_' 分隔符（platform_devicePrefix_counter） */
    int underscores = 0;
    for (size_t i = 0; i < len; i++) {
        if (id[i] == '_') {
            underscores++;
        }
    }
    CuAssertIntEquals_Msg(tc, "request id should have 2 underscores", 2, underscores);

    pdns_util_cleanup();
}

/* 同进程内连续生成的 requestId 必须互不相同（计数器自增） */
void test_request_id_unique(CuTest *tc) {
    enum { N = 200 };
    char ids[N][PDNS_REQUEST_ID_LEN];

    pdns_util_init();
    for (int i = 0; i < N; i++) {
        memset(ids[i], 0, PDNS_REQUEST_ID_LEN);
        pdns_gen_request_id(ids[i], PDNS_REQUEST_ID_LEN);
    }
    for (int i = 0; i < N; i++) {
        for (int j = i + 1; j < N; j++) {
            CuAssert(tc, "request ids must be unique", strcmp(ids[i], ids[j]) != 0);
        }
    }
    pdns_util_cleanup();
}

/* 同一进程内设备前缀应保持稳定（同一台机器的多次请求可被聚合） */
void test_request_id_device_prefix_stable(CuTest *tc) {
    char id1[PDNS_REQUEST_ID_LEN] = {0};
    char id2[PDNS_REQUEST_ID_LEN] = {0};

    pdns_util_init();
    pdns_gen_request_id(id1, sizeof(id1));
    pdns_gen_request_id(id2, sizeof(id2));
    pdns_util_cleanup();

    /* 截取到第二个 '_' 之前的部分（platform_devicePrefix），两次应一致 */
    const char *p1 = strrchr(id1, '_');
    const char *p2 = strrchr(id2, '_');
    CuAssertPtrNotNull(tc, p1);
    CuAssertPtrNotNull(tc, p2);

    size_t prefix_len1 = (size_t) (p1 - id1);
    size_t prefix_len2 = (size_t) (p2 - id2);
    CuAssertIntEquals_Msg(tc, "device prefix length should be stable",
                          (int) prefix_len1, (int) prefix_len2);
    CuAssert(tc, "device prefix should be stable within a process",
             strncmp(id1, id2, prefix_len1) == 0);
}

/* 缓冲过小时必须截断而不越界（末尾仍为 NUL） */
void test_request_id_small_buffer(CuTest *tc) {
    char small[8];
    memset(small, 'X', sizeof(small));

    pdns_util_init();
    pdns_gen_request_id(small, sizeof(small));
    pdns_util_cleanup();

    CuAssert(tc, "small buffer must be NUL-terminated", small[sizeof(small) - 1] == '\0');
    CuAssert(tc, "small buffer must be truncated", strlen(small) < sizeof(small));
}

/* sessionId：12 位 A-Za-z0-9 */
void test_session_id_format(CuTest *tc) {
    char sid[16] = {0};

    pdns_gen_session_id(sid, sizeof(sid));

    CuAssertIntEquals_Msg(tc, "session id should be 12 chars", 12, (int) strlen(sid));
    for (int i = 0; i < 12; i++) {
        char c        = sid[i];
        bool is_alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        CuAssert(tc, "session id must be alphanumeric", is_alnum);
    }
}

/* 多次生成的 sessionId 应几乎不重复（随机串；允许极小概率碰撞，故只要求整体不全同） */
void test_session_id_randomness(CuTest *tc) {
    enum { N = 50 };
    char sids[N][16];
    int  distinct = 0;

    for (int i = 0; i < N; i++) {
        memset(sids[i], 0, sizeof(sids[i]));
        pdns_gen_session_id(sids[i], sizeof(sids[i]));
    }
    for (int i = 0; i < N; i++) {
        bool dup = false;
        for (int j = 0; j < i; j++) {
            if (strcmp(sids[i], sids[j]) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            distinct++;
        }
    }
    /* 12 位 62 进制随机串，50 次生成理应全不相同；放宽到 >=45 以容忍极端情况 */
    CuAssert(tc, "session ids should be (almost) all distinct", distinct >= 45);
}

void add_pdns_util_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_request_id_format);
    SUITE_ADD_TEST(suite, test_request_id_unique);
    SUITE_ADD_TEST(suite, test_request_id_device_prefix_stable);
    SUITE_ADD_TEST(suite, test_request_id_small_buffer);
    SUITE_ADD_TEST(suite, test_session_id_format);
    SUITE_ADD_TEST(suite, test_session_id_randomness);
}
