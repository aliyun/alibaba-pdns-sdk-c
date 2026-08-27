/*
 * IDN 转换模块实现 —— RFC 3492 Punycode 编码（自带实现，无第三方依赖）
 */
#include "pdns_idn.h"

#include <string.h>
#include <stdint.h>

/* ---------------- RFC 3492 Punycode 参数 ---------------- */
#define PUNY_BASE          36
#define PUNY_TMIN          1
#define PUNY_TMAX          26
#define PUNY_SKEW          38
#define PUNY_DAMP          700
#define PUNY_INITIAL_BIAS  72
#define PUNY_INITIAL_N     128
#define PUNY_DELIMITER     '-'
#define PUNY_MAXINT        0xFFFFFFFFu

/* 整串是否纯 ASCII（无 >=0x80 字节） */
static bool is_all_ascii(const char *s) {
    for (; *s != '\0'; ++s) {
        if ((unsigned char) *s >= 0x80) {
            return false;
        }
    }
    return true;
}

/* 数字 0..35 → punycode 字符：0..25 -> 'a'..'z'，26..35 -> '0'..'9' */
static char encode_digit(unsigned d) {
    return (char) (d < 26 ? (int) d + 'a' : (int) d - 26 + '0');
}

static unsigned puny_adapt(unsigned delta, unsigned numpoints, int firsttime) {
    unsigned k;
    delta = firsttime ? delta / PUNY_DAMP : delta >> 1;
    delta += delta / numpoints;
    for (k = 0; delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2; k += PUNY_BASE) {
        delta /= (PUNY_BASE - PUNY_TMIN);
    }
    return k + (PUNY_BASE - PUNY_TMIN + 1) * delta / (delta + PUNY_SKEW);
}

/* UTF-8 解码一个 label 到码点数组。成功返回码点数，失败返回 -1。 */
static int utf8_decode(const char *s, size_t len, uint32_t *cps, size_t cap) {
    size_t i = 0, n = 0;
    while (i < len) {
        unsigned char c = (unsigned char) s[i];
        uint32_t  cp;
        size_t    extra;
        if (c < 0x80) {
            cp = c; extra = 0;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F; extra = 1;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F; extra = 2;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07; extra = 3;
        } else {
            return -1;  /* 非法起始字节 */
        }
        if (i + extra + 1 > len) {
            return -1;  /* 后续字节不足 */
        }
        for (size_t k = 0; k < extra; ++k) {
            unsigned char cc = (unsigned char) s[i + 1 + k];
            if ((cc & 0xC0) != 0x80) {
                return -1;  /* 非法后续字节 */
            }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (n >= cap) {
            return -1;  /* 码点数超出容量 */
        }
        cps[n++] = cp;
        i += extra + 1;
    }
    return (int) n;
}

/* 对码点数组做 punycode 编码，输出到 out（不含 xn-- 前缀）。成功返回 true。 */
static bool punycode_encode(const uint32_t *input, size_t input_length,
                            char *out, size_t out_cap, size_t *out_len) {
    unsigned n     = PUNY_INITIAL_N;
    unsigned delta = 0;
    unsigned bias  = PUNY_INITIAL_BIAS;
    size_t   out_i = 0;
    size_t   h, b, j;

    /* 先输出全部基本码点（ASCII） */
    for (j = 0; j < input_length; ++j) {
        if (input[j] < 0x80) {
            if (out_i >= out_cap) return false;
            out[out_i++] = (char) input[j];
        }
    }
    h = b = out_i;
    if (b > 0) {
        if (out_i >= out_cap) return false;
        out[out_i++] = PUNY_DELIMITER;
    }

    while (h < input_length) {
        unsigned m = PUNY_MAXINT;
        for (j = 0; j < input_length; ++j) {
            if (input[j] >= n && input[j] < m) {
                m = input[j];
            }
        }
        if (m - n > (PUNY_MAXINT - delta) / (unsigned) (h + 1)) {
            return false;  /* overflow */
        }
        delta += (m - n) * (unsigned) (h + 1);
        n = m;
        for (j = 0; j < input_length; ++j) {
            if (input[j] < n) {
                if (++delta == 0) return false;  /* overflow */
            }
            if (input[j] == n) {
                unsigned q = delta;
                unsigned k;
                for (k = PUNY_BASE; ; k += PUNY_BASE) {
                    unsigned t = k <= bias ? PUNY_TMIN
                               : (k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias);
                    if (q < t) break;
                    if (out_i >= out_cap) return false;
                    out[out_i++] = encode_digit(t + (q - t) % (PUNY_BASE - t));
                    q = (q - t) / (PUNY_BASE - t);
                }
                if (out_i >= out_cap) return false;
                out[out_i++] = encode_digit(q);
                bias  = puny_adapt(delta, (unsigned) (h + 1), h == b);
                delta = 0;
                ++h;
            }
        }
        ++delta;
        ++n;
    }
    *out_len = out_i;
    return true;
}

bool pdns_idn_to_ascii(const char *host, char *out, size_t out_size) {
    if (host == NULL || out == NULL || out_size == 0) {
        if (out != NULL && out_size > 0) {
            out[0] = '\0';
        }
        return false;
    }

    /* 纯 ASCII：原样拷贝（最常见路径，快速返回） */
    if (is_all_ascii(host)) {
        size_t len = strlen(host);
        if (len + 1 > out_size) {
            out[0] = '\0';
            return false;
        }
        memcpy(out, host, len + 1);
        return true;
    }

    /* 含非 ASCII：按 '.' 分段，逐 label 转换 */
    size_t      out_i = 0;
    const char *p     = host;
    bool        ok    = true;
    while (true) {
        const char *dot       = strchr(p, '.');
        size_t      label_len = dot ? (size_t) (dot - p) : strlen(p);

        bool label_ascii = true;
        for (size_t k = 0; k < label_len; ++k) {
            if ((unsigned char) p[k] >= 0x80) {
                label_ascii = false;
                break;
            }
        }

        if (label_ascii) {
            if (out_i + label_len >= out_size) { ok = false; break; }
            memcpy(out + out_i, p, label_len);
            out_i += label_len;
        } else {
            uint32_t cps[256];
            int      ncp = utf8_decode(p, label_len, cps, sizeof(cps) / sizeof(cps[0]));
            if (ncp < 0) { ok = false; break; }
            if (out_i + 4 >= out_size) { ok = false; break; }
            memcpy(out + out_i, "xn--", 4);
            out_i += 4;
            size_t enc_len = 0;
            if (!punycode_encode(cps, (size_t) ncp, out + out_i, out_size - out_i - 1, &enc_len)) {
                ok = false;
                break;
            }
            out_i += enc_len;
        }

        if (!dot) {
            break;
        }
        if (out_i + 1 >= out_size) { ok = false; break; }
        out[out_i++] = '.';
        p = dot + 1;
    }

    if (!ok) {
        /* 尽力而为：转换失败回退原始 host，返回 false 供调用方记 warning */
        size_t len = strlen(host);
        if (len + 1 <= out_size) {
            memcpy(out, host, len + 1);
        } else {
            out[0] = '\0';
        }
        return false;
    }

    out[out_i] = '\0';
    return true;
}
