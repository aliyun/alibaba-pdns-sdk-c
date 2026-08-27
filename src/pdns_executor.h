/*
 * 带重试的 HTTPDNS 请求执行器（内部）
 *
 * 职责：承载「多次尝试 + 每次向 manager 索取服务端 URL + 成功更新 SRTT / 失败惩罚
 * + 失败计数驱动主备降级 + 末次 HOST 域名兜底」的重试循环。
 * 业务层只需生成 requestId、填好请求模板并调用本执行器。
 */
#ifndef PDNS_EXECUTOR_H
#define PDNS_EXECUTOR_H

#include "pdns/pdns_api.h"
#include "pdns_resolver.h"
#include "pdns_server_manager.h"
#include "pdns_netstack.h"

/*
 * 执行一次带 failover 重试的 HTTPDNS 解析。
 *
 * 循环策略：
 *   - 总尝试次数 = manager 的 max_total_retry_count() + 1，多出的 1 次留给
 *     HOST 域名兜底（详见 pdns_server_manager.h 顶部的逐次展开）。
 *     max_total_retry_count() 为 0（无任何可用 provider）时直接失败，不发请求。
 *   - 每次尝试的服务端寻址与鉴权 path 全部向 manager / provider 索取：
 *     manager 内部完成「主用 → 备用」的降级决策，provider 内部完成
 *     「优选节点 → HOST 兜底」的选点。本模块不做任何选点判断。
 *   - 成功：更新该节点 SRTT + 清除失败计数，结束重试
 *   - 失败：惩罚该节点 SRTT + 累加失败计数（达到阈值后下一轮自动切备用）
 *
 * @param manager    provider 调度管理器（选 provider / 选节点 / 失败计数）。
 * @param stack      当前网络栈类型（用于节点过滤）。
 * @param enable_ipv6 是否允许 IPv6 直连。
 * @param req        请求模板，host / request_id / ecs / session_id 等由调用方填充；
 *                   base_url / url_path / resolve_host / server_ip / skip_cert_verify / source
 *                   由本函数按尝试逐次填充（调用方无需设置）。返回后 req->source
 *                   即末次实际使用的 provider 名（供调用方日志 / 统计）。
 * @param out        解析结果 IP 追加到此链表（调用方已创建）。
 * @param[out] out_ttl 首个匹配记录 TTL（已钳制，秒）；否定响应为否定 TTL。可为 NULL。
 * @param[out] out_is_negative 是否为否定响应（NXDOMAIN / NODATA）。可为 NULL。
 * @param[out] out_conf_version 末次成功请求的响应头 Cv（服务端 ACL 版本），<0 表未携带。可为 NULL。
 * @return 末次尝试的状态；成功时 code=PDNS_OK。
 */
pdns_status_t pdns_execute_resolve_with_retry(pdns_server_manager_t *manager,
                                              pdns_netstack_type_t stack,
                                              bool enable_ipv6,
                                              pdns_resolve_req_t *req,
                                              pdns_result_list_t *out,
                                              int *out_ttl,
                                              bool *out_is_negative,
                                              long *out_conf_version);

#endif /* PDNS_EXECUTOR_H */
