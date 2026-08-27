/*
 * DNS 服务节点健康检查（内部）
 *
 * 职责：对已熔断的节点发起一次探测请求，判断其是否恢复服务。
 * 职责划分：
 *   - 连续失败/成功计数与熔断判定 → pdns_server_manager
 *   - 节点存活状态与恢复动作     → pdns_base_provider
 *   - 探测请求本身               → 本模块
 *
 * 一处实现差异：C SDK 支持多 client 实例并存（各自独立的 provider 与鉴权），
 * 若引入全局单例会让多个 client 的探测域名互相覆盖。故本模块**不持有任何状态**，
 * 探测域名仍由 fusion provider 持有（pdns_fusion_provider_get_health_check_domain），
 * 每次调用从 provider 取。
 *
 * 熔断仅对自建生效（公共 DNS 节点不参与熔断），故本模块只处理
 * fusion provider。
 */
#ifndef PDNS_DNS_HEALTH_CHECKER_H
#define PDNS_DNS_HEALTH_CHECKER_H

#include "pdns_fusion_provider.h"
#include "pdns_netstack.h"

/* 单轮健康检查最多探测的节点数（三类节点各自上限为 PDNS_MAX_NODES_PER_TYPE） */
#define PDNS_HEALTH_CHECK_MAX_NODES (PDNS_MAX_NODES_PER_TYPE * 3)

/*
 * 探测单个节点是否已恢复。
 *
 * 探测请求复用正常解析的构造方式：provider 的鉴权 path + 自建 base_url 拼接规则，
 * 但**不写缓存、不参与解析结果**，仅看 HTTP 状态码是否为 200。
 *
 * @param[in]  fusion       自建 provider（提供节点端口、鉴权、证书开关、探测域名）
 * @param[in]  node         待探测的节点地址（IP 或私有域名，不带方括号）
 * @param[in]  query_type   探测用的查询类型（按被探测节点的地址族选择）
 * @param[in]  session_id   会话 ID，可为 NULL
 * @param[in]  timeout_ms   超时（毫秒），<=0 用默认
 * @param[in]  using_https  true=https，false=http
 * @return true 表示探测成功（HTTP 200）。
 */
bool pdns_health_check_probe_node(pdns_fusion_provider_t *fusion,
                                  const char *node,
                                  pdns_query_type_t query_type,
                                  const char *session_id,
                                  int timeout_ms,
                                  bool using_https);

/*
 * 执行一轮健康检查：
 * 收集当前已熔断的节点 → 逐个探测 → 把结果记回 provider（达阈值即恢复）。
 *
 * 以下任一条件不满足即整轮跳过：
 *   - fusion provider 未启用（未配置或鉴权不全）
 *   - health_check_domain 为空（等价于熔断功能关闭）
 * 无已熔断节点时也直接返回，不产生任何网络请求。
 *
 * @param[in]  fusion       自建 provider
 * @param[in]  stack        当前网络栈，决定探测哪些类型的节点
 * @param[in]  session_id   会话 ID，可为 NULL
 * @param[in]  timeout_ms   单次探测超时（毫秒）
 * @param[in]  using_https  true=https，false=http
 * @return 本轮恢复的节点数。
 * @note 同步串行执行，由调用方放到后台线程调用。
 */
int pdns_health_check_run(pdns_fusion_provider_t *fusion,
                          pdns_netstack_type_t stack,
                          const char *session_id,
                          int timeout_ms,
                          bool using_https);

#endif /* PDNS_DNS_HEALTH_CHECKER_H */
