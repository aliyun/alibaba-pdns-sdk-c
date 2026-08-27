/*
 * 签名模块实现 —— 内置 SHA-256（FIPS 180-4）
 *
 * 不依赖 OpenSSL：SHA-256 是本 SDK 对 OpenSSL 的唯一用途，内置后可彻底移除
 * OpenSSL 依赖——静态交付时约减少 4~5MB，并避免与宿主程序自带的
 * libcrypto 出现两份全局状态（版本不一致时可致崩溃）。
 * RC4 亦为内置实现（pdns_rc4.c），加密相关无第三方依赖。
 */
#include "pdns_sign.h"

#include <stdint.h>
#include <string.h>
#include <time.h>

/* 全局签名时间偏移（秒）；offset 为秒级精度，long 对齐读写视为原子 */
static volatile long g_time_offset = 0;

long pdns_sign_now(void) {
    return (long) time(NULL) + g_time_offset;
}

void pdns_sign_update_offset(long server_epoch) {
    if (server_epoch <= 0) {
        return;
    }
    g_time_offset = server_epoch - (long) time(NULL);
}

/* ============================ 内置 SHA-256（FIPS 180-4） ============================ */

/* 轮常量：前 64 个素数立方根小数部分的前 32 位（FIPS 180-4 §4.2.2） */
static const uint32_t PDNS_SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define PDNS_ROTR(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define PDNS_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define PDNS_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define PDNS_BSIG0(x)     (PDNS_ROTR(x, 2) ^ PDNS_ROTR(x, 13) ^ PDNS_ROTR(x, 22))
#define PDNS_BSIG1(x)     (PDNS_ROTR(x, 6) ^ PDNS_ROTR(x, 11) ^ PDNS_ROTR(x, 25))
#define PDNS_SSIG0(x)     (PDNS_ROTR(x, 7) ^ PDNS_ROTR(x, 18) ^ ((x) >> 3))
#define PDNS_SSIG1(x)     (PDNS_ROTR(x, 17) ^ PDNS_ROTR(x, 19) ^ ((x) >> 10))

/* 压缩单个 512-bit 块，就地更新 state */
static void pdns_sha256_compress(uint32_t state[8], const unsigned char block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int t;

    for (t = 0; t < 16; t++) {
        w[t] = ((uint32_t) block[t * 4] << 24) |
               ((uint32_t) block[t * 4 + 1] << 16) |
               ((uint32_t) block[t * 4 + 2] << 8) |
               ((uint32_t) block[t * 4 + 3]);
    }
    for (t = 16; t < 64; t++) {
        w[t] = PDNS_SSIG1(w[t - 2]) + w[t - 7] + PDNS_SSIG0(w[t - 15]) + w[t - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (t = 0; t < 64; t++) {
        uint32_t t1 = h + PDNS_BSIG1(e) + PDNS_CH(e, f, g) + PDNS_SHA256_K[t] + w[t];
        uint32_t t2 = PDNS_BSIG0(a) + PDNS_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/*
 * 计算 data[0..len) 的 SHA-256，输出 32 字节裸摘要。
 *
 * 尾块填充在栈缓冲内完成（最多两个块），全程不分配内存。
 */
static void pdns_sha256_raw(const unsigned char *data, size_t len, unsigned char out[32]) {
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    unsigned char tail[128];
    uint64_t bits = (uint64_t) len * 8;
    size_t off = 0;
    size_t rem;
    size_t block_len;
    int i;

    while (off + 64 <= len) {
        pdns_sha256_compress(state, data + off);
        off += 64;
    }

    rem = len - off;
    if (rem > 0) {
        memcpy(tail, data + off, rem);
    }
    tail[rem++] = 0x80;
    /* 长度字段占末尾 8 字节；不够放则再用一个块 */
    block_len = (rem <= 56) ? 64 : 128;
    memset(tail + rem, 0, block_len - rem);
    for (i = 0; i < 8; i++) {
        tail[block_len - 1 - i] = (unsigned char) (bits >> (8 * i));
    }

    pdns_sha256_compress(state, tail);
    if (block_len == 128) {
        pdns_sha256_compress(state, tail + 64);
    }

    for (i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char) (state[i] >> 24);
        out[i * 4 + 1] = (unsigned char) (state[i] >> 16);
        out[i * 4 + 2] = (unsigned char) (state[i] >> 8);
        out[i * 4 + 3] = (unsigned char) (state[i]);
    }
}

void pdns_sha256_hex(const char *input, char *out_hex65) {
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[32];
    int i;

    if (input == NULL || out_hex65 == NULL) {
        if (out_hex65) out_hex65[0] = '\0';
        return;
    }

    pdns_sha256_raw((const unsigned char *) input, strlen(input), digest);

    for (i = 0; i < 32; i++) {
        out_hex65[i * 2]     = hex[(digest[i] >> 4) & 0x0F];
        out_hex65[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out_hex65[64] = '\0';
}
