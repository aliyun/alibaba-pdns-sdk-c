/*
 * RC4 + Base64URL 解密工具（内部）—— 黑白名单 /conf 配置解密
 *
 * 实现要点：
 *   - RC4 标准 KSA + PRGA，密钥循环 key[i % keyLen]
 *   - Base64 使用 URL-safe 变体（'-'→'+'、'_'→'/'，'=' 填充可缺省）
 *   - 解密流程：Base64URL 解码 → RC4 解密 → UTF-8 明文
 */
#ifndef PDNS_RC4_H
#define PDNS_RC4_H

#include <stddef.h>

/*
 * RC4 对称加/解密（in、out 长度均为 len，可原地或分离缓冲）。
 * 密钥按 key[i % strlen(key)] 循环取用。key 为空则不处理。
 */
void pdns_rc4_crypt(const char *key, const unsigned char *in, size_t len, unsigned char *out);

/*
 * Base64URL 解码。返回 malloc 分配的字节缓冲（调用方 free），长度写入 *out_len。
 * 失败或空输入返回 NULL。
 */
unsigned char *pdns_base64url_decode(const char *in, size_t *out_len);

/*
 * 便捷组合：对 Base64URL 密文先解码再 RC4 解密，返回 malloc 的 NUL 结尾字符串
 * （UTF-8 明文，调用方 free）。失败返回 NULL。
 */
char *pdns_rc4_decrypt_base64url(const char *key, const char *b64url);

#endif /* PDNS_RC4_H */
