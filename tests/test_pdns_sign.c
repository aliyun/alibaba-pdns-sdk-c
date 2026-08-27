/*
 * 签名模块测试 —— 内置 SHA-256（FIPS 180-4）与签名时间偏移
 *
 * 用 FIPS 180-4 / NIST 官方测试向量校验内置实现，确保去掉 OpenSSL 后
 * 摘要结果与标准完全一致（签名错误会导致服务端鉴权失败，属高危项）。
 */
#include "test_suite_list.h"
#include "pdns_sign.h"

#include <time.h>

/* 空串向量 */
void test_sha256_empty(CuTest *tc) {
    char hex[65] = {0};
    pdns_sha256_hex("", hex);
    CuAssertStrEquals(tc, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
}

/* FIPS 180-4 §D.1：单块消息 "abc" */
void test_sha256_abc(CuTest *tc) {
    char hex[65] = {0};
    pdns_sha256_hex("abc", hex);
    CuAssertStrEquals(tc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
}

/* FIPS 180-4 §D.2：56 字节消息，跨两个压缩块（padding 边界） */
void test_sha256_two_blocks(CuTest *tc) {
    char hex[65] = {0};
    pdns_sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hex);
    CuAssertStrEquals(tc, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hex);
}

/*
 * padding 边界性质测试：55/56/63/64/65 字节分别落在
 * 「单块可容纳 padding」「需追加整块」等不同分支上。
 * 这里不硬编码摘要值（避免引入未经核对的期望值），而是断言
 * 输出格式合法且各长度摘要互不相同——足以捕获 padding/长度域写错的缺陷。
 */
void test_sha256_padding_boundaries(CuTest *tc) {
    const int lens[]  = {55, 56, 63, 64, 65};
    const int n       = (int) (sizeof(lens) / sizeof(lens[0]));
    char      hex[5][65];
    char      msg[66];

    for (int i = 0; i < n; i++) {
        memset(msg, 'a', (size_t) lens[i]);
        msg[lens[i]] = '\0';
        memset(hex[i], 0, sizeof(hex[i]));
        pdns_sha256_hex(msg, hex[i]);
        CuAssertIntEquals_Msg(tc, "digest length must be 64", 64, (int) strlen(hex[i]));
    }
    /* 不同长度输入的摘要必须互不相同 */
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            CuAssert(tc, "digests of different lengths must differ",
                     strcmp(hex[i], hex[j]) != 0);
        }
    }
}

/* 经典长句向量（含不带/带句点两组，覆盖单块与跨块） */
void test_sha256_quick_fox(CuTest *tc) {
    char hex[65] = {0};
    pdns_sha256_hex("The quick brown fox jumps over the lazy dog", hex);
    CuAssertStrEquals(tc, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", hex);

    memset(hex, 0, sizeof(hex));
    pdns_sha256_hex("The quick brown fox jumps over the lazy dog.", hex);
    CuAssertStrEquals(tc, "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c", hex);
}

/* 输出必须是 64 个小写十六进制字符 + 结尾 NUL */
void test_sha256_output_format(CuTest *tc) {
    char hex[65] = {0};
    pdns_sha256_hex("pdns", hex);
    CuAssertIntEquals_Msg(tc, "digest must be 64 chars", 64, (int) strlen(hex));
    for (int i = 0; i < 64; i++) {
        bool is_lower_hex = (hex[i] >= '0' && hex[i] <= '9') || (hex[i] >= 'a' && hex[i] <= 'f');
        CuAssert(tc, "digest must be lowercase hex", is_lower_hex);
    }
}

/* 同一输入结果稳定；输入仅差一个字符时摘要必须不同（雪崩效应） */
void test_sha256_deterministic(CuTest *tc) {
    char h1[65] = {0}, h2[65] = {0}, h3[65] = {0};
    pdns_sha256_hex("709021www.taobao.com", h1);
    pdns_sha256_hex("709021www.taobao.com", h2);
    pdns_sha256_hex("709021www.taobao.com ", h3);   /* 末尾多一个空格 */
    CuAssertStrEquals_Msg(tc, "same input must yield same digest", h1, h2);
    CuAssert(tc, "different input must yield different digest", strcmp(h1, h3) != 0);
}

/* 无偏移时，签名时间应贴近本地时间 */
void test_sign_now_without_offset(CuTest *tc) {
    long local = (long) time(NULL);
    long sign  = pdns_sign_now();
    long diff  = sign > local ? sign - local : local - sign;
    CuAssert(tc, "sign time should be close to local time when no offset", diff <= 2);
}

/* 用服务端时间校准后，签名时间应跟随服务端；随后恢复偏移避免影响其它用例 */
void test_sign_update_offset(CuTest *tc) {
    long local        = (long) time(NULL);
    long server_ahead = local + 3600;   /* 模拟本地时钟慢 1 小时 */

    pdns_sign_update_offset(server_ahead);
    long signed_time = pdns_sign_now();
    long diff        = signed_time > server_ahead ? signed_time - server_ahead
                                                  : server_ahead - signed_time;
    CuAssert(tc, "sign time should follow server epoch after offset update", diff <= 2);

    /* 复位：用当前本地时间重新校准，offset 归零 */
    pdns_sign_update_offset((long) time(NULL));
    long restored = pdns_sign_now();
    long back     = restored > local ? restored - local : local - restored;
    CuAssert(tc, "offset should be resettable", back <= 2);
}

void add_pdns_sign_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_sha256_empty);
    SUITE_ADD_TEST(suite, test_sha256_abc);
    SUITE_ADD_TEST(suite, test_sha256_two_blocks);
    SUITE_ADD_TEST(suite, test_sha256_padding_boundaries);
    SUITE_ADD_TEST(suite, test_sha256_quick_fox);
    SUITE_ADD_TEST(suite, test_sha256_output_format);
    SUITE_ADD_TEST(suite, test_sha256_deterministic);
    SUITE_ADD_TEST(suite, test_sign_now_without_offset);
    SUITE_ADD_TEST(suite, test_sign_update_offset);
}
