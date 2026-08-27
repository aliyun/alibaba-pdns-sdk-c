/*
 * IDN（国际化域名）转换模块 —— UTF-8 域名转 punycode(ASCII)
 *
 * 策略：用时转换 + 原始域名流转 + 尽力而为：
 *   - 仅在需要 ASCII 的使用点调用（HTTPDNS 请求 URL 的 name= / 签名 content、LocalDNS getaddrinfo）；
 *   - 缓存 key、黑白名单 ACL、回调/返回等仍使用原始域名（本模块不介入）。
 */
#ifndef PDNS_IDN_H
#define PDNS_IDN_H

#include <stdbool.h>
#include <stddef.h>

/*
 * 将 UTF-8 域名转换为 IDNA/ASCII（punycode，xn-- 形式）。
 *   - 纯 ASCII 域名：原样拷贝到 out，返回 true；
 *   - 含非 ASCII（如中文）：按 '.' 分段，对含非 ASCII 的 label 做 punycode 编码并加 "xn--" 前缀；
 *   - 转换失败（非法 UTF-8 / punycode 溢出 / 缓冲不足）：尽力而为——把【原始 host】拷贝到 out，
 *     返回 false（调用方据此记 warning，但仍可用 out 继续解析，交由后续失败/兜底链路处理，不中断）。
 *
 * @param host     输入域名（UTF-8，可含中文）
 * @param out      输出缓冲（ASCII 域名，含结尾 '\0'）
 * @param out_size out 缓冲大小
 * @return true=成功（含纯 ASCII 原样）；false=转换失败，out 已回退为原始 host
 */
bool pdns_idn_to_ascii(const char *host, char *out, size_t out_size);

#endif /* PDNS_IDN_H */
