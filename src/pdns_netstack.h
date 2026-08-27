/*
 * 网络栈探测原语（内部）—— IPv4/IPv6 可达性判定 + 本机 IP 收集
 *
 *   - UDP connect 探测（IPv4 8.8.8.8 / IPv6 2000::，端口 0xFFFF）
 *   - UDP 探测得到 NONE 时回退到 DNS 探测（getaddrinfo 已知域名）
 *   - 位或组合出 IPV4_ONLY / IPV6_ONLY / DUAL / NONE
 * 本机 IP 收集：汇总非回环网卡地址到链表，供上层做"集合对比"式网络切换检测。
 * 跨平台：POSIX（Linux/macOS）与 Windows（Winsock）统一封装。
 */
#ifndef PDNS_NETSTACK_H
#define PDNS_NETSTACK_H

#include "pdns/pdns_api.h"
#include "pdns_list.h"

/* 网络栈类型（位掩码组合） */
typedef enum {
    PDNS_STACK_NONE      = 0,   /* 无法探测/无网络 */
    PDNS_STACK_IPV4_ONLY = 1,   /* 仅 IPv4 */
    PDNS_STACK_IPV6_ONLY = 2,   /* 仅 IPv6 */
    PDNS_STACK_DUAL      = 3     /* 双栈（IPv4 + IPv6） */
} pdns_netstack_type_t;

/*
 * 探测当前网络栈类型：UDP 探测优先，得到 NONE 时回退 DNS 探测。
 * @return PDNS_STACK_* 之一。
 */
pdns_netstack_type_t pdns_netstack_detect(void);

/* 网络栈类型语义名（日志可读）：IPv4_ONLY / IPv6_ONLY / DUAL / NONE */
const char *pdns_netstack_name(pdns_netstack_type_t stack);

/*
 * 收集本机非回环网卡的 IP 地址，逐个追加到 out 链表。
 * 用于网络切换检测（集合对比：地址集合变化即认为网络环境变化）。
 * 此处用内部通用链表而非解析结果列表：本机网卡地址不是解析结果，不存在来源语义。
 * @return 成功返回 0；失败返回非 0。
 */
int pdns_netstack_collect_local_ips(pdns_list_impl_t *out);

#endif /* PDNS_NETSTACK_H */
