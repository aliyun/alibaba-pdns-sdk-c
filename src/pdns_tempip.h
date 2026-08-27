/*
 * 服务 IP 优选拉取模块（内部）—— 最优解析 IP 获取
 *
 * 协议：
 *   - 向 GET /resolve?name=auto.sdk.alidns.com&type=SRV&uid=9999 拉取服务端下发的优选节点
 *     （该接口固定 uid=9999，无签名；服务节点由 provider 选出，走 IP 直连）
 *   - SRV 记录 data 字段形如 "prio weight port <target>"，取 target 按后缀分类：
 *       .ipv4.  → IPv4 节点（去后缀）
 *       .ipv6.  → IPv6 节点（去后缀，'-' 还原为 ':'）
 *       .domain.→ 域名（HOST）节点（去后缀）
 *   - 解析出的三类列表与默认 bootstrap 节点合并写回 provider（SRTT 状态继承）
 *
 * 仅公共 DNS 具备本能力：自建的节点由调用方在 init 时一次性传入，服务端不下发
 * 优选列表，故入参直接收紧为
 * pdns_public_provider_t，从类型上排除误用。
 * 线程安全：拉取应在后台线程执行（HTTP 阻塞）。
 */
#ifndef PDNS_TEMPIP_H
#define PDNS_TEMPIP_H

#include "pdns/pdns_api.h"
#include "pdns_public_provider.h"
#include "pdns_netstack.h"

/*
 * 拉取并合并一次服务端下发的优选服务 IP 列表。
 *
 * @param provider    公共 DNS 提供者（选节点 + 合并写回）。
 * @param stack       当前网络栈类型（用于挑选发起拉取的服务节点）。
 * @param enable_ipv6 是否允许 IPv6 直连。
 * @param using_https true=HTTPS，false=HTTP。
 * @param timeout_ms  请求超时（毫秒），<=0 用默认。
 * @param is_expire   本次拉取原因：true=serverTtl 过期刷新（合并时继承同 IP 的 SRTT）；
 *                    false=首次/网络切换（合并时新节点 SRTT 归零）。
 * @return pdns_status_t，code=PDNS_OK 表示成功拉取并合并。
 */
pdns_status_t pdns_tempip_fetch(pdns_public_provider_t *provider,
                                pdns_netstack_type_t stack,
                                bool enable_ipv6,
                                bool using_https,
                                int timeout_ms,
                                bool is_expire);

#endif /* PDNS_TEMPIP_H */
