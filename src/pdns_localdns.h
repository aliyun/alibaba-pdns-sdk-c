/*
 * LocalDNS 降级模块（内部）—— 系统解析器兜底
 *
 * 当 HTTPDNS 解析结果为空时，降级调用系统解析（getaddrinfo）。
 * 跨平台：POSIX（Linux/macOS）与 Windows（Winsock）统一封装。
 * TTL 硬编码为 PDNS_LOCALDNS_TTL 秒（系统解析无 TTL 信息）。
 */
#ifndef PDNS_LOCALDNS_H
#define PDNS_LOCALDNS_H

#include "pdns/pdns_api.h"
#include "pdns_list.h"

/* LocalDNS 结果缓存 TTL（秒） */
#define PDNS_LOCALDNS_TTL 60

/*
 * 使用系统解析器解析 host，将匹配 query_type 的 IP 字符串追加到 out_ips。
 * @return 成功解析到至少一个 IP 返回 PDNS_OK，否则返回非 0。
 */
int pdns_localdns_resolve(const char *host,
                          pdns_query_type_t query_type,
                          pdns_result_list_t *out_ips);

#endif /* PDNS_LOCALDNS_H */
