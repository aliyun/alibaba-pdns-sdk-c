/*
 * 签名模块（内部）—— SHA-256
 *
 * 用于生成 HTTPDNS 鉴权请求的签名。签名原文：
 *   account_id + access_key_secret + timestamp + domain + access_key_id
 * 取 SHA-256 后转小写十六进制字符串，放入 URL 的 key 参数。
 */
#ifndef PDNS_SIGN_H
#define PDNS_SIGN_H

/*
 * 计算 input 的 SHA-256，输出 64 个字符的小写十六进制字符串。
 * @param[in]  input      待签名字符串（以 \0 结尾）
 * @param[out] out_hex65  输出缓冲，长度至少 65 字节（64 hex + \0）
 */
void pdns_sha256_hex(const char *input, char *out_hex65);

/* ============================ 时间偏移（authTimeOffset） ============================ */

/*
 * 返回用于签名的当前时间戳（秒）= 本地时间 + 全局偏移。
 * 当本地时钟与服务端存在偏差时，偏移能保证签名时间有效。
 */
long pdns_sign_now(void);

/*
 * 用服务端时间（Unix 秒）更新全局时间偏移：offset = server_epoch - 本地时间。
 * 通常由解析响应的 HTTP Date 头触发。
 */
void pdns_sign_update_offset(long server_epoch);

#endif /* PDNS_SIGN_H */
