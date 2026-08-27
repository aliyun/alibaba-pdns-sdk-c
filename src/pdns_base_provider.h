/*
 * DNS 服务提供者抽象基类（内部）
 *
 * 承载两个子类共享的全部能力：
 *   - 三类节点列表：V4 / V6 / Host
 *   - 选点策略：getServerIPWithRequestCount → getServerIPWithType → getScoreIpModel
 *   - SRTT 更新：srtt = lastSrtt*0.7 + rtt*0.3
 *   - 失败惩罚：目标节点 srtt+200ms，其余节点 srtt*0.98
 *   - serverTtl 过期判断
 *   - 鉴权参数持有与签名 path 生成（两个子类的签名算法一致，差异见各子类）
 *
 * 「等价 protected」约定：以下字段仅允许 pdns_base_provider.c 与两个子类的
 * .c 直接访问，其余模块一律通过 pdns_server_provider.h 的接口调用。
 * C 无真正的 protected，此约束靠注释与 review 保证。
 *
 * 线程安全：内部使用 APR 互斥量保护节点列表与鉴权字段。
 */
#ifndef PDNS_BASE_DNS_PROVIDER_H
#define PDNS_BASE_DNS_PROVIDER_H

#include "pdns_server_provider.h"

#include <apr_pools.h>
#include <apr_thread_mutex.h>

/* 单次解析在同一 provider 内的服务节点重试阈值：
 * request_count 达到该值即切 HOST 域名兜底（走系统 DNS 解析服务域名）。 */
#define PDNS_RETRY_COUNT 3

/* 各类型节点数量上限 */
#define PDNS_MAX_NODES_PER_TYPE 8

/* 节点默认 TTL */
#define PDNS_SERVER_DEFAULT_TTL 60

/* 熔断阈值：节点连续失败达到该次数即摘除 */
#define PDNS_MIN_CONSECUTIVE_FAILURES 3

/* 恢复阈值：健康探测连续成功达到该次数即恢复 */
#define PDNS_MIN_CONSECUTIVE_SUCCESS 1

struct pdns_base_provider_s;
typedef struct pdns_base_provider_s pdns_base_provider_t;

struct pdns_base_provider_s {
    /* 必须是第一个成员：向上转型为 pdns_server_provider_t* 的前提 */
    const pdns_server_provider_vtbl_t *vtbl;

    /* ===================== 以下等价 protected ===================== */
    apr_pool_t         *pool;
    apr_thread_mutex_t *lock;

    /* 鉴权参数（两个 provider 各自独立持有） */
    char *account_id;
    char *access_key_id;
    char *access_key_secret;

    /* 三类节点 */
    pdns_server_ip_model_t v4[PDNS_MAX_NODES_PER_TYPE];
    int                        v4_count;
    pdns_server_ip_model_t v6[PDNS_MAX_NODES_PER_TYPE];
    int                        v6_count;
    pdns_server_ip_model_t host[PDNS_MAX_NODES_PER_TYPE];
    int                        host_count;

    /* serverTtl 过期时刻（微秒，apr_time_now 基准），0 表示尚未成功下发过 */
    apr_time_t server_expire_at;
};

/* ---------------- 基类构造 / 析构（供子类调用，等价 [super init] / dealloc） ---------------- */

/* 初始化基类：建 pool 与锁、绑定 vtable。成功返回 0。 */
int pdns_base_provider_init(pdns_base_provider_t          *base,
                                const pdns_server_provider_vtbl_t *vtbl);

/* 释放基类持有的资源（pool 与锁）。 */
void pdns_base_provider_destroy(pdns_base_provider_t *base);

/* ---------------- 鉴权 ---------------- */

/*
 * 设置鉴权三参数。三者须全部非空，否则返回非 0 且不改动现有值
 * （鉴权不全时 Provider 不启用，不存在「部分鉴权」状态）。
 */
int pdns_base_provider_set_auth(pdns_base_provider_t *base,
                                   const char *account_id,
                                   const char *access_key_id,
                                   const char *access_key_secret);

/* 鉴权三参数是否全部非空 */
bool pdns_base_provider_is_account_auth_available(pdns_base_provider_t *base);

/* v4/v6/host 任一非空 */
bool pdns_base_provider_is_server_available(pdns_base_provider_t *base);

/*
 * 只读鉴权访问器。供 pdns_conf 拼 /conf 请求参数使用：C 侧只保留 pdns_conf 一份
 * 实现，由它向 provider 索取寻址与鉴权。
 * 返回的指针由 provider 的 pool 持有，调用方不得释放，也不应长期缓存。
 */
const char *pdns_base_provider_account_id(pdns_base_provider_t *base);
const char *pdns_base_provider_access_key_id(pdns_base_provider_t *base);
const char *pdns_base_provider_access_key_secret(pdns_base_provider_t *base);

/*
 * 接口指针向下转型回基类。
 * 合法性：基类首成员是 vtbl，接口对象也只有 vtbl，两者地址等价；
 * 而所有 provider 实体均以基类为首成员（各子类头文件已用编译期断言钉死）。
 */
static inline pdns_base_provider_t *
pdns_base_of(pdns_server_provider_t *p) {
    return (pdns_base_provider_t *) p;
}

/* 当前网络栈下是否有可调度节点 */
bool pdns_base_provider_has_active_servers(pdns_base_provider_t *base,
                                              pdns_netstack_type_t stack,
                                              bool enable_ipv6);

/* ---------------- 节点装载 ---------------- */

/*
 * 用给定地址数组重建三类节点列表，SRTT 归零。
 * 该能力上提到基类由两个子类共用。
 * v4/v6/host 为不含方括号的 IP 或域名字符串数组，可为 NULL/0。
 */
void pdns_base_provider_setup_servers(pdns_base_provider_t *base,
                                          const char *const *v4, int v4_count,
                                          const char *const *v6, int v6_count,
                                          const char *const *host, int host_count);

/*
 * 合并服务端下发的优选节点，仅公共 DNS 使用：
 *   新数组 = [服务端下发节点...] + [默认 bootstrap 节点...]（去重）
 *   - inherit_srtt=true（serverTtl 过期刷新）：同 IP 保留历史 SRTT
 *   - inherit_srtt=false（网络切换/首次）：全部 SRTT 归零
 * def_* 为该 provider 的默认 bootstrap 节点（自建无默认节点，传 NULL/0）。
 */
void pdns_base_provider_merge_server_list(pdns_base_provider_t *base,
                                              const char *const *v4, int v4_count,
                                              const char *const *v6, int v6_count,
                                              const char *const *host, int host_count,
                                              const char *const *def_v4, int def_v4_count,
                                              const char *const *def_v6, int def_v6_count,
                                              const char *const *def_host, int def_host_count,
                                              int ttl_sec, bool inherit_srtt);

/* ---------------- 选点 ---------------- */

/*
 * 取当前最优节点。
 * @param[out] out_is_host true 表示选中 HOST 域名兜底（此时返回 NULL 属正常）
 * @return 节点 IP（调用方不得释放）；HOST 兜底或无可用节点时返回 NULL。
 */
const char *pdns_base_provider_get_server_ip_with_request_count(
        pdns_base_provider_t *base, pdns_netstack_type_t stack,
        bool enable_ipv6, int request_count, bool *out_is_host);

/* 查询指定节点当前 SRTT（毫秒）；未命中或 NULL 入参返回 0。用于日志展示选点时刻的 SRTT。 */
float pdns_base_provider_get_node_srtt(pdns_base_provider_t *base, const char *node_ip);

/* ---------------- SRTT ---------------- */

/* 请求成功后用本次 RTT（毫秒）更新该节点 SRTT */
void pdns_base_provider_update_srtt(pdns_base_provider_t *base,
                                        const char *server_ip, long rtt_ms);

/* 请求失败后对该节点 +200ms、其余节点 ×0.98 */
void pdns_base_provider_punish(pdns_base_provider_t *base, const char *server_ip);

/* 重置所有节点 SRTT（网络切换时调用） */
void pdns_base_provider_reset_srtt(pdns_base_provider_t *base);

/* ---------------- serverTtl ---------------- */

/* serverTtl 是否过期；尚未成功下发过（expire==0）返回 false */
bool pdns_base_provider_is_server_ip_expired(pdns_base_provider_t *base);

/* 仅刷新 serverTtl 过期时刻（拉取失败时的重试节流） */
void pdns_base_provider_touch_server_expire(pdns_base_provider_t *base, int ttl_sec);

/* ---------------- 熔断与健康检查 ---------------- */

/*
 * 「已熔断节点集合」在 C 侧的表达方式（实现差异，行为等价）：
 *
 * C 侧节点是固定数组（v4/v6/host + count），改用 model->is_alive 标记原地区分：
 *   is_alive == true  等价于「在 aliveList 中」
 *   is_alive == false 等价于「在 healthCheckList 中」
 * 这样做有一个必须避免的实际风险：pdns_server_url_result_t.node_ip 是指向数组内
 * model->ip 的指针，若熔断时真的搬移数组元素，正在飞的请求持有的 node_ip 会指向
 * 错位的节点，导致 SRTT / 惩罚记到别的节点上。原地标记则无此问题。
 *
 * 「恢复后优先被再次选中以验证」的意图，C 侧等价手段是把 srtt 归零——
 * get_score_ip 对 srtt==0（未测量）的节点优先返回。
 */

/*
 * 记一次节点请求失败：failure_count++、success_count 清零、记 last_failed_time；
 * 达到 PDNS_MIN_CONSECUTIVE_FAILURES 即置 is_alive=false（熔断）。
 * @return true 表示本次调用刚触发熔断（供调用方打日志），已熔断者重复调用返回 false。
 */
bool pdns_base_provider_record_node_failure(pdns_base_provider_t *base,
                                                const char *node_ip);

/* 记一次节点请求成功：failure_count 清零、success_count++（不改 is_alive） */
void pdns_base_provider_record_node_success(pdns_base_provider_t *base,
                                                const char *node_ip);

/*
 * 收集当前已熔断、且在给定网络栈下需要探测的节点 IP（按栈分流：
 * IPV4_ONLY 探 v4+host；IPV6_ONLY 探 v6+host；双栈全探）。
 * IP 以值拷贝方式写出，调用方无需关心节点数组的后续变动。
 * @return 写入 out_ips 的个数。
 */
int pdns_base_provider_collect_broken_nodes(
        pdns_base_provider_t *base, pdns_netstack_type_t stack,
        char out_ips[][PDNS_IP_ADDRESS_STRING_LENGTH], int max_out);

/*
 * 记一次健康探测结果。
 * 成功：success_count++、failure_count 清零；达到 PDNS_MIN_CONSECUTIVE_SUCCESS 即恢复
 *       （is_alive=true、两计数清零、srtt 归零以便优先被选中验证）。
 * 失败：success_count 清零（保持熔断，等下一轮探测）。
 * @return true 表示节点本次恢复。
 */
bool pdns_base_provider_record_probe_result(pdns_base_provider_t *base,
                                                const char *node_ip, bool success);

/* 是否存在已熔断节点（供定时器快速跳过） */
bool pdns_base_provider_has_broken_nodes(pdns_base_provider_t *base);

/*
 * 取首个存活的 HOST 节点地址（供自建 HOST 兜底选取私有域名）。
 * 公共 DNS 的 HOST 兜底用固定服务域名，不需要本函数。
 * @return 节点地址（调用方不得释放）；无存活 host 节点时返回 NULL。
 */
const char *pdns_base_provider_alive_host_node(pdns_base_provider_t *base);

/* ---------------- 鉴权 path（两个子类共用的签名实现） ---------------- */

/*
 * 生成带 SHA-256 签名的 URL path。
 * 签名原文：account_id + access_key_secret + ts + ascii_host + access_key_id
 * 两个子类的签名算法完全一致，差异只在「鉴权不全时是否允许降级」，而该差异已在
 * 配置入口拦截（鉴权不全的 provider 不会被启用），故此处只有一份实现。
 * @return 0 成功；非 0 表示鉴权不全或缓冲不足。
 */
int pdns_base_provider_build_auth_url_path(pdns_base_provider_t *base,
                                               const char *ascii_host,
                                               const char *type_str,
                                               const char *session_id,
                                               const char *ecs,
                                               bool        enable_short,
                                               char *out, size_t out_len);

#endif /* PDNS_BASE_DNS_PROVIDER_H */
