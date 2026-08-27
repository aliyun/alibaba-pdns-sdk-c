/*
 * IDN 转换测试 —— UTF-8 域名转 punycode（xn-- 形式）
 *
 * 中文等非 ASCII 域名必须转为 ASCII 才能进入 HTTPDNS 请求 URL 与签名原文，
 * 转换错误会导致解析失败或签名不匹配。策略为「尽力而为」：失败时回退原始域名。
 */
#include "test_suite_list.h"
#include "pdns_idn.h"

/* 纯 ASCII 域名应原样输出并返回 true */
void test_idn_pure_ascii_passthrough(CuTest *tc) {
    char out[256] = {0};

    CuAssert(tc, "ascii host should succeed", pdns_idn_to_ascii("www.taobao.com", out, sizeof(out)));
    CuAssertStrEquals(tc, "www.taobao.com", out);

    memset(out, 0, sizeof(out));
    CuAssert(tc, "ascii host with digits/hyphen should succeed",
             pdns_idn_to_ascii("cdn-01.example-site.com", out, sizeof(out)));
    CuAssertStrEquals(tc, "cdn-01.example-site.com", out);
}

/* 已是 punycode 形式的域名不应被二次编码 */
void test_idn_already_punycode(CuTest *tc) {
    char out[256] = {0};
    CuAssert(tc, "punycode host should succeed",
             pdns_idn_to_ascii("xn--fiqs8s.example.com", out, sizeof(out)));
    CuAssertStrEquals(tc, "xn--fiqs8s.example.com", out);
}

/* IDNA 标准向量：中文域名 "中国" → xn--fiqs8s */
void test_idn_chinese_label(CuTest *tc) {
    char out[256] = {0};
    CuAssert(tc, "chinese host should convert", pdns_idn_to_ascii("中国.cn", out, sizeof(out)));
    CuAssertStrEquals(tc, "xn--fiqs8s.cn", out);
}

/* 多个非 ASCII label 各自独立编码："例子.测试" → xn--fsqu00a.xn--0zwm56d */
void test_idn_multiple_non_ascii_labels(CuTest *tc) {
    char out[256] = {0};
    CuAssert(tc, "multi-label idn should convert", pdns_idn_to_ascii("例子.测试", out, sizeof(out)));
    CuAssertStrEquals(tc, "xn--fsqu00a.xn--0zwm56d", out);
}

/* ASCII 与非 ASCII label 混合：仅非 ASCII label 被编码 */
void test_idn_mixed_labels(CuTest *tc) {
    char out[256] = {0};
    CuAssert(tc, "mixed host should convert", pdns_idn_to_ascii("www.中国.cn", out, sizeof(out)));
    CuAssertStrEquals(tc, "www.xn--fiqs8s.cn", out);
}

/* 输出缓冲不足时：返回 false，且 out 必须安全（NUL 结尾，不越界） */
void test_idn_insufficient_buffer(CuTest *tc) {
    char tiny[4];
    memset(tiny, 'X', sizeof(tiny));

    bool ok = pdns_idn_to_ascii("中国.cn", tiny, sizeof(tiny));
    CuAssert(tc, "insufficient buffer should return false", !ok);
    CuAssert(tc, "output must stay NUL-terminated", tiny[sizeof(tiny) - 1] == '\0' ||
                                                    strlen(tiny) < sizeof(tiny));
}

/* 非法 UTF-8 序列：尽力而为——返回 false 但 out 回退为原始 host，不得崩溃 */
void test_idn_invalid_utf8_fallback(CuTest *tc) {
    char       out[256]  = {0};
    /* 0xFF 不是合法 UTF-8 起始字节 */
    const char bad_host[] = {'a', (char) 0xFF, '.', 'c', 'o', 'm', '\0'};

    bool ok = pdns_idn_to_ascii(bad_host, out, sizeof(out));
    (void) ok;   /* 允许 false */
    CuAssert(tc, "output must be NUL-terminated on fallback", strlen(out) < sizeof(out));
}

/* 空入参与 NULL 防护 */
void test_idn_edge_cases(CuTest *tc) {
    char out[64];

    memset(out, 'X', sizeof(out));
    pdns_idn_to_ascii("", out, sizeof(out));
    CuAssertStrEquals_Msg(tc, "empty host should yield empty string", "", out);

    /* NULL 入参不得崩溃 */
    pdns_idn_to_ascii(NULL, out, sizeof(out));
    pdns_idn_to_ascii("a.com", NULL, 0);
    pdns_idn_to_ascii("a.com", out, 0);
}

/* 结果稳定：同一域名多次转换结果一致（签名依赖该稳定性） */
void test_idn_deterministic(CuTest *tc) {
    char o1[256] = {0};
    char o2[256] = {0};
    pdns_idn_to_ascii("测试.中国", o1, sizeof(o1));
    pdns_idn_to_ascii("测试.中国", o2, sizeof(o2));
    CuAssertStrEquals_Msg(tc, "idn conversion must be deterministic", o1, o2);
}

void add_pdns_idn_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_idn_pure_ascii_passthrough);
    SUITE_ADD_TEST(suite, test_idn_already_punycode);
    SUITE_ADD_TEST(suite, test_idn_chinese_label);
    SUITE_ADD_TEST(suite, test_idn_multiple_non_ascii_labels);
    SUITE_ADD_TEST(suite, test_idn_mixed_labels);
    SUITE_ADD_TEST(suite, test_idn_insufficient_buffer);
    SUITE_ADD_TEST(suite, test_idn_invalid_utf8_fallback);
    SUITE_ADD_TEST(suite, test_idn_edge_cases);
    SUITE_ADD_TEST(suite, test_idn_deterministic);
}
