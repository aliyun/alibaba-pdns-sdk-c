/*
 * DNS 服务提供者调度管理器（内部）
 *
 * 职责：持有 public / fusion 两个 provider，按「首次配置者为主用」组成 provider
 * group，并在一次解析的多次尝试之间做主备降级决策；节点池与 SRTT 逻辑
 * 已下移到 pdns_base_provider。
 *
 * ============ 主备顺序与 fallback_threshold ============
 *   仅 public 启用            → [public]           （单 provider，无降级）
 *   仅 fusion 启用            → [fusion]           （单 provider，无降级）
 *   两者都启用 & public 先配   → [public, fusion]    threshold = 4
 *   两者都启用 & fusion 先配   → [fusion, public]    threshold = 2
 * threshold 取值范围 [0, 4]，0 表示不给主用机会直接降级。
 *
 * ============ request_count 与总尝试次数的关系 ============
 * max_total_retry_count() 语义见下；上层执行器的总尝试次数为
 * max_total_retry_count() + 1，多出的这 1 次是 HOST 域名兜底。展开后：
 *
 *   单 public（max=3，共 4 次）：
 *       rc=0,1,2 → public IP 直连；rc=3 → public HOST 兜底
 *   public 主用 + fusion 备用（threshold=4，max=4+3=7，共 8 次）：
 *       rc=0..2 → public IP；rc=3 → public HOST；（此时已累计 4 次失败）
 *       rc=4..6 → fusion IP（换算后 0..2）；rc=7 → fusion HOST（换算后 3）
 *   fusion 主用 + public 备用（threshold=2，max=2+3=5，共 6 次）：
 *       rc=0,1 → fusion IP；（累计 2 次失败）
 *       rc=2..4 → public IP（换算后 0..2）；rc=5 → public HOST（换算后 3）
 *
 * 线程安全：provider group 与 threshold 由内部互斥量保护；两个 provider 各自内部加锁。
 */
#ifndef PDNS_DNS_SERVER_MANAGER_H
#define PDNS_DNS_SERVER_MANAGER_H

#include "pdns_server_provider.h"
#include "pdns_public_provider.h"
#include "pdns_fusion_provider.h"

/* 主用失败降级阈值上限（[0,4] 钳制） */
#define PDNS_FALLBACK_THRESHOLD_MAX 4

/* 双 provider 时的默认阈值 */
#define PDNS_FALLBACK_THRESHOLD_PUBLIC_PRIMARY 4
#define PDNS_FALLBACK_THRESHOLD_FUSION_PRIMARY 2

/* 首次配置的 provider 类型 */
typedef enum {
    PDNS_FIRST_CONFIGURED_NONE = 0,
    PDNS_FIRST_CONFIGURED_PUBLIC,
    PDNS_FIRST_CONFIGURED_FUSION
} pdns_first_configured_type_t;

typedef struct pdns_server_manager_s pdns_server_manager_t;

/* ---------------- 生命周期 ---------------- */

/*
 * 创建管理器：内部同时创建 public / fusion 两个 provider 实体，
 * 但二者均处于「未配置」状态，provider group 为空。
 */
pdns_server_manager_t *pdns_server_manager_create(void);

void pdns_server_manager_destroy(pdns_server_manager_t *m);

/* ---------------- 配置入口 ---------------- */

/*
 * 配置公共 DNS 鉴权并加入 provider group。
 * 鉴权三参数必填，缺一返回非 0 且不改动任何状态。
 */
int pdns_server_manager_init_public_dns(pdns_server_manager_t *m,
                                            const char *account_id,
                                            const char *access_key_id,
                                            const char *access_key_secret);

/*
 * 配置自建 DNS 并加入 provider group。
 * 校验规则见 pdns_fusion_provider_init_fusion_dns，任一不满足返回非 0。
 */
int pdns_server_manager_init_fusion_dns(pdns_server_manager_t *m,
                                            const char *const *server_ipv4_arr, int v4_count,
                                            const char *const *server_ipv6_arr, int v6_count,
                                            const char *const *server_host_arr, int host_count,
                                            int         port,
                                            const char *health_check_domain,
                                            const char *account_id,
                                            const char *access_key_id,
                                            const char *access_key_secret);

/* ---------------- provider 访问（供 conf / tempip 按 provider 各拉一次） ---------------- */

/* 两个 provider 实体恒存在；是否已配置须用 pdns_provider_is_dns_provider_enabled 判断 */
pdns_public_provider_t *pdns_server_manager_public(pdns_server_manager_t *m);
pdns_fusion_provider_t *pdns_server_manager_fusion(pdns_server_manager_t *m);

/* provider group 内已启用的 provider 数量（0 / 1 / 2） */
int pdns_server_manager_provider_count(pdns_server_manager_t *m);

/* 主用 provider（group 为空时返回 NULL）；备用无则返回 NULL */
pdns_server_provider_t *pdns_server_manager_primary(pdns_server_manager_t *m);
pdns_server_provider_t *pdns_server_manager_backup(pdns_server_manager_t *m);

pdns_first_configured_type_t
pdns_server_manager_first_configured_type(pdns_server_manager_t *m);

/* ---------------- fallback_threshold ---------------- */

int  pdns_server_manager_get_fallback_threshold(pdns_server_manager_t *m);

/* 入参钳制到 [0, PDNS_FALLBACK_THRESHOLD_MAX] */
void pdns_server_manager_set_fallback_threshold(pdns_server_manager_t *m,
                                                    int fallback_threshold);

/* ---------------- 核心调度 ---------------- */

/*
 * 整条解析链路的最大重试次数：
 *   0 个 provider                    → 0
 *   1 个                             → 有活跃节点时取该 provider 的重试预算，否则 0
 *   2 个 & 主用有活跃节点             → threshold + 备用重试预算（备用无活跃节点则为 0）
 *   2 个 & 主用无活跃节点             → 备用重试预算（备用无活跃节点则 0）
 * 上层执行器的总尝试次数 = 本值 + 1（多出的 1 次为 HOST 域名兜底）。
 */
int pdns_server_manager_max_total_retry_count(pdns_server_manager_t *m,
                                                   pdns_netstack_type_t stack,
                                                   bool enable_ipv6);

/*
 * 按重试序号取服务端 URL，含主备降级决策。
 *
 * @param request_count 本次尝试序号（从 0 起）
 * @param domain/type_str/request_id 用于失败计数定位，决定是否降级
 * @param[out] out           选点结果
 * @param[out] out_provider  实际选中的 provider（用于随后生成鉴权 path 与 SRTT 归属），可为 NULL
 * @return 0 成功；非 0 表示主备均无可用节点
 */
int pdns_server_manager_get_server_url_with_request_count(
        pdns_server_manager_t *m,
        int                        request_count,
        const char                *domain,
        const char                *type_str,
        const char                *request_id,
        pdns_netstack_type_t       stack,
        bool                       enable_ipv6,
        bool                       using_https,
        pdns_server_url_result_t  *out,
        pdns_server_provider_t **out_provider);

/* ---------------- 事件通知 ---------------- */

/* 请求成功：清除该请求的失败计数 */
void pdns_server_manager_on_request_success(pdns_server_manager_t *m,
                                                const char *domain,
                                                const char *type_str,
                                                const char *request_id);

/* 请求失败：累加该请求的失败计数，达到 threshold 后下一次尝试切备用 */
void pdns_server_manager_on_request_failure(pdns_server_manager_t *m,
                                                const char *domain,
                                                const char *type_str,
                                                const char *request_id);

/* 重试次数用尽：清除该请求的失败计数，避免残留影响后续同名请求 */
void pdns_server_manager_on_request_finish(pdns_server_manager_t *m,
                                               const char *domain,
                                               const char *type_str,
                                               const char *request_id);

/* 清理过期失败记录（由 client 的配置刷新定时器周期调用） */
void pdns_server_manager_cleanup_expired(pdns_server_manager_t *m);

/* ---------------- 熔断（节点级连续失败计数） ---------------- */

/*
 * 节点级请求结果记账，达阈即熔断。与上面的 on_request_xxx 是两个不同维度，不可混淆：
 *   - on_request_xxx：**请求**级（domain:type:requestId），决定本次解析是否从主用切到备用
 *   - 本组函数：  **节点**级（具体 IP），决定该节点是否被摘除出调度池
 *
 * 两个前置条件（任一不满足即不计数）：
 *   1. 仅自建节点参与熔断（公共 DNS 节点不参与）
 *   2. 自建的 health_check_domain 非空（为空等价熔断关闭，否则节点被摘除后无法探测恢复）
 *
 * @param[in] provider 本次选中的 provider（由 get_server_url 回传）
 * @param[in] node_ip  本次选中的节点标识；NULL（HOST 兜底无具体节点）时直接返回
 */
void pdns_server_manager_update_consecutive_success(pdns_server_manager_t *m,
                                                        pdns_server_provider_t *provider,
                                                        const char *node_ip);

void pdns_server_manager_update_consecutive_failure(pdns_server_manager_t *m,
                                                        pdns_server_provider_t *provider,
                                                        const char *node_ip);

/*
 * 执行一轮自建节点健康检查。
 * 由 client 的 60s 配置刷新定时器调用；无熔断节点时不发任何请求。
 * @return 本轮恢复的节点数。
 */
int pdns_server_manager_run_health_check(pdns_server_manager_t *m,
                                             pdns_netstack_type_t stack,
                                             const char *session_id,
                                             int timeout_ms,
                                             bool using_https);

/* ---------------- 网络切换 ---------------- */

/* 重置两个 provider 的全部节点 SRTT（网络切换时调用） */
void pdns_server_manager_reset_srtt(pdns_server_manager_t *m);

#endif /* PDNS_DNS_SERVER_MANAGER_H */
