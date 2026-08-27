/*
 * RC4 + Base64URL 测试 —— 黑白名单 /conf 配置解密链路
 *
 * 用标准 RC4 测试向量校验手写实现；并覆盖 Base64URL 变体字符、
 * 缺省 padding、往返一致性等实际下发数据会遇到的情形。
 */
#include "test_suite_list.h"
#include "pdns_rc4.h"

/* 把二进制转小写 hex，便于与标准向量比对 */
static void to_hex(const unsigned char *data, size_t len, char *out) {
    static const char *tbl = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = tbl[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = tbl[data[i] & 0xF];
    }
    out[len * 2] = '\0';
}

/* 标准 RC4 向量：key="Key", plaintext="Plaintext" → BBF316E8D940AF0AD3 */
void test_rc4_standard_vector_key(CuTest *tc) {
    const char   *plain = "Plaintext";
    size_t        len   = strlen(plain);
    unsigned char out[16];
    char          hex[40];

    pdns_rc4_crypt("Key", (const unsigned char *) plain, len, out);
    to_hex(out, len, hex);
    CuAssertStrEquals(tc, "bbf316e8d940af0ad3", hex);
}

/* 标准 RC4 向量：key="Wiki", plaintext="pedia" → 1021BF0420 */
void test_rc4_standard_vector_wiki(CuTest *tc) {
    const char   *plain = "pedia";
    size_t        len   = strlen(plain);
    unsigned char out[16];
    char          hex[40];

    pdns_rc4_crypt("Wiki", (const unsigned char *) plain, len, out);
    to_hex(out, len, hex);
    CuAssertStrEquals(tc, "1021bf0420", hex);
}

/* 标准 RC4 向量：key="Secret", plaintext="Attack at dawn" */
void test_rc4_standard_vector_secret(CuTest *tc) {
    const char   *plain = "Attack at dawn";
    size_t        len   = strlen(plain);
    unsigned char out[32];
    char          hex[72];

    pdns_rc4_crypt("Secret", (const unsigned char *) plain, len, out);
    to_hex(out, len, hex);
    CuAssertStrEquals(tc, "45a01f645fc35b383552544b9bf5", hex);
}

/* RC4 是对称流密码：同一密钥加密两次应还原原文 */
void test_rc4_symmetric_roundtrip(CuTest *tc) {
    const char   *plain = "{\"v\":100,\"ttl\":60,\"acl\":{\"bz\":[],\"bd\":[],\"wz\":[],\"wd\":[]}}";
    size_t        len   = strlen(plain);
    unsigned char cipher[256];
    unsigned char restored[256];

    pdns_rc4_crypt("pdns-test-key", (const unsigned char *) plain, len, cipher);
    CuAssert(tc, "cipher must differ from plaintext",
             memcmp(cipher, plain, len) != 0);

    pdns_rc4_crypt("pdns-test-key", cipher, len, restored);
    restored[len] = '\0';
    CuAssertStrEquals_Msg(tc, "rc4 must be symmetric", plain, (const char *) restored);
}

/* 密钥长度超过明文、以及密钥需循环取用的情形都应正常工作 */
void test_rc4_key_cycling(CuTest *tc) {
    const char   *plain = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t        len   = strlen(plain);
    unsigned char cipher[64];
    unsigned char restored[64];

    /* 单字符密钥：KSA 中 key[i % 1] 需被循环使用 256 次 */
    pdns_rc4_crypt("k", (const unsigned char *) plain, len, cipher);
    pdns_rc4_crypt("k", cipher, len, restored);
    restored[len] = '\0';
    CuAssertStrEquals_Msg(tc, "single-char key roundtrip", plain, (const char *) restored);

    /* 超长密钥：KSA 只取前 256 字节参与，仍需可逆 */
    char long_key[400];
    memset(long_key, 'x', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';
    pdns_rc4_crypt(long_key, (const unsigned char *) plain, len, cipher);
    pdns_rc4_crypt(long_key, cipher, len, restored);
    restored[len] = '\0';
    CuAssertStrEquals_Msg(tc, "long key roundtrip", plain, (const char *) restored);
}

/* 原地加解密（in == out）不得产生错误结果 */
void test_rc4_in_place(CuTest *tc) {
    unsigned char buf[] = "in-place-data";
    size_t        len   = strlen((const char *) buf);

    pdns_rc4_crypt("key", buf, len, buf);
    pdns_rc4_crypt("key", buf, len, buf);
    CuAssertStrEquals(tc, "in-place-data", (const char *) buf);
}

/* 空密钥 / 空指针：直接返回，输出保持原样，不得崩溃 */
void test_rc4_invalid_args(CuTest *tc) {
    unsigned char buf[] = "unchanged";
    pdns_rc4_crypt("", buf, strlen((const char *) buf), buf);
    CuAssertStrEquals_Msg(tc, "empty key should be a no-op", "unchanged", (const char *) buf);

    pdns_rc4_crypt(NULL, buf, strlen((const char *) buf), buf);
    CuAssertStrEquals_Msg(tc, "NULL key should be a no-op", "unchanged", (const char *) buf);

    pdns_rc4_crypt("key", NULL, 8, buf);   /* 不得崩溃 */
    pdns_rc4_crypt("key", buf, 8, NULL);   /* 不得崩溃 */
}

/* 标准 Base64 解码（带 padding） */
void test_base64_decode_standard(CuTest *tc) {
    size_t         len  = 0;
    unsigned char *data = pdns_base64url_decode("SGVsbG8sIHBkbnMh", &len);
    CuAssertPtrNotNull(tc, data);
    CuAssertIntEquals(tc, 12, (int) len);
    CuAssert(tc, "decoded content mismatch", memcmp(data, "Hello, pdns!", 12) == 0);
    free(data);
}

/* 缺省 padding 也应能解码（服务端下发常见去掉 '='） */
void test_base64_decode_without_padding(CuTest *tc) {
    size_t         len  = 0;
    unsigned char *data = pdns_base64url_decode("SGVsbG8", &len);   /* "Hello" 无 padding */
    CuAssertPtrNotNull(tc, data);
    CuAssertIntEquals(tc, 5, (int) len);
    CuAssert(tc, "decoded content mismatch", memcmp(data, "Hello", 5) == 0);
    free(data);
}

/* URL-safe 变体：'-' 等价 '+'，'_' 等价 '/'，两者结果必须一致 */
void test_base64url_variant_chars(CuTest *tc) {
    size_t         std_len = 0, url_len = 0;
    /* 0xFB 0xFF 0xBF 编码为标准 "+/+/"，URL-safe 为 "-_-_" */
    unsigned char *std_data = pdns_base64url_decode("+/+/", &std_len);
    unsigned char *url_data = pdns_base64url_decode("-_-_", &url_len);

    CuAssertPtrNotNull(tc, std_data);
    CuAssertPtrNotNull(tc, url_data);
    CuAssertIntEquals_Msg(tc, "url-safe decode length must match standard",
                          (int) std_len, (int) url_len);
    CuAssert(tc, "url-safe decode must equal standard decode",
             memcmp(std_data, url_data, std_len) == 0);
    free(std_data);
    free(url_data);
}

/* 空输入与 NULL：返回 NULL 或零长度，不得崩溃 */
void test_base64_decode_edge_cases(CuTest *tc) {
    size_t         len  = 123;
    unsigned char *data = pdns_base64url_decode(NULL, &len);
    CuAssertPtrEquals_Msg(tc, "NULL input should return NULL", NULL, data);
    CuAssertIntEquals_Msg(tc, "out_len must be reset to 0", 0, (int) len);

    len  = 123;
    data = pdns_base64url_decode("", &len);
    CuAssertIntEquals_Msg(tc, "empty input decodes to 0 byte", 0, (int) len);
    free(data);

    /* 含空白与非法字符时容错跳过，仍能解出有效数据 */
    len  = 0;
    data = pdns_base64url_decode("SGVs bG8\n", &len);
    CuAssertPtrNotNull(tc, data);
    CuAssertIntEquals(tc, 5, (int) len);
    CuAssert(tc, "should skip whitespace", memcmp(data, "Hello", 5) == 0);
    free(data);
}

/* 组合链路：Base64URL 解码 + RC4 解密 → 明文 JSON（模拟 /conf 响应） */
void test_rc4_decrypt_base64url_pipeline(CuTest *tc) {
    const char *key   = "conf-key";
    const char *plain = "{\"v\":7,\"ttl\":60}";
    size_t      len   = strlen(plain);

    /* 先构造密文：RC4 加密后做标准 Base64 编码（自行编码，避免依赖外部工具） */
    unsigned char        cipher[128];
    static const char   *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char                 encoded[256];
    size_t               o = 0;

    pdns_rc4_crypt(key, (const unsigned char *) plain, len, cipher);
    for (size_t i = 0; i < len; i += 3) {
        unsigned int v    = (unsigned int) cipher[i] << 16;
        size_t       rest = len - i;
        if (rest > 1) v |= (unsigned int) cipher[i + 1] << 8;
        if (rest > 2) v |= (unsigned int) cipher[i + 2];
        encoded[o++] = b64[(v >> 18) & 0x3F];
        encoded[o++] = b64[(v >> 12) & 0x3F];
        if (rest > 1) encoded[o++] = b64[(v >> 6) & 0x3F];
        if (rest > 2) encoded[o++] = b64[v & 0x3F];
    }
    encoded[o] = '\0';

    char *decrypted = pdns_rc4_decrypt_base64url(key, encoded);
    CuAssertPtrNotNull(tc, decrypted);
    CuAssertStrEquals_Msg(tc, "decrypt pipeline must restore plaintext", plain, decrypted);
    free(decrypted);

    /* 错误密钥不应还原出原文 */
    char *wrong = pdns_rc4_decrypt_base64url("wrong-key", encoded);
    CuAssertPtrNotNull(tc, wrong);
    CuAssert(tc, "wrong key must not restore plaintext", strcmp(wrong, plain) != 0);
    free(wrong);

    /* NULL 密文返回 NULL */
    CuAssertPtrEquals_Msg(tc, "NULL ciphertext should return NULL", NULL,
                          pdns_rc4_decrypt_base64url(key, NULL));
}

void add_pdns_rc4_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_rc4_standard_vector_key);
    SUITE_ADD_TEST(suite, test_rc4_standard_vector_wiki);
    SUITE_ADD_TEST(suite, test_rc4_standard_vector_secret);
    SUITE_ADD_TEST(suite, test_rc4_symmetric_roundtrip);
    SUITE_ADD_TEST(suite, test_rc4_key_cycling);
    SUITE_ADD_TEST(suite, test_rc4_in_place);
    SUITE_ADD_TEST(suite, test_rc4_invalid_args);
    SUITE_ADD_TEST(suite, test_base64_decode_standard);
    SUITE_ADD_TEST(suite, test_base64_decode_without_padding);
    SUITE_ADD_TEST(suite, test_base64url_variant_chars);
    SUITE_ADD_TEST(suite, test_base64_decode_edge_cases);
    SUITE_ADD_TEST(suite, test_rc4_decrypt_base64url_pipeline);
}
