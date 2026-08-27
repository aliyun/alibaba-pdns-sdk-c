/*
 * RC4 + Base64URL 解密工具实现（手写标准 RC4）
 */
#include "pdns_rc4.h"

#include <stdlib.h>
#include <string.h>

void pdns_rc4_crypt(const char *key, const unsigned char *in, size_t len, unsigned char *out) {
    if (key == NULL || key[0] == '\0' || in == NULL || out == NULL) {
        return;
    }
    size_t klen = strlen(key);

    /* KSA：初始化 S 盒并按密钥打乱（密钥循环 key[i % klen]） */
    int sbox[256];
    for (int i = 0; i < 256; i++) {
        sbox[i] = i;
    }
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + sbox[i] + (unsigned char) key[i % klen]) % 256;
        int t   = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
    }

    /* PRGA：生成密钥流并与数据异或 */
    int i2 = 0, j2 = 0;
    for (size_t k = 0; k < len; k++) {
        i2 = (i2 + 1) % 256;
        j2 = (j2 + sbox[i2]) % 256;
        int t    = sbox[i2];
        sbox[i2] = sbox[j2];
        sbox[j2] = t;
        int ks = sbox[(sbox[i2] + sbox[j2]) % 256];
        out[k] = (unsigned char) (in[k] ^ ks);
    }
}

/* 单个 Base64 字符 → 6bit 值；同时接受标准与 URL-safe 字符，非法返回 -1 */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;   /* URL-safe: '-' 等价 '+' */
    if (c == '/' || c == '_') return 63;   /* URL-safe: '_' 等价 '/' */
    return -1;
}

unsigned char *pdns_base64url_decode(const char *in, size_t *out_len) {
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (in == NULL) {
        return NULL;
    }
    size_t n = strlen(in);
    /* 输出上界：每 4 个字符 → 3 字节，留余量 */
    unsigned char *out = (unsigned char *) malloc(n / 4 * 3 + 4);
    if (out == NULL) {
        return NULL;
    }
    int    buf  = 0;
    int    bits = 0;
    size_t o    = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            continue;   /* 跳过填充与空白 */
        }
        int v = b64_val(c);
        if (v < 0) {
            continue;   /* 跳过非法字符（容错） */
        }
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char) ((buf >> bits) & 0xFF);
        }
    }
    if (out_len != NULL) {
        *out_len = o;
    }
    return out;
}

char *pdns_rc4_decrypt_base64url(const char *key, const char *b64url) {
    if (b64url == NULL) {
        return NULL;
    }
    size_t         len  = 0;
    unsigned char *data = pdns_base64url_decode(b64url, &len);
    if (data == NULL || len == 0) {
        free(data);
        return NULL;
    }
    unsigned char *plain = (unsigned char *) malloc(len + 1);
    if (plain == NULL) {
        free(data);
        return NULL;
    }
    pdns_rc4_crypt(key, data, len, plain);
    plain[len] = '\0';
    free(data);
    return (char *) plain;
}
