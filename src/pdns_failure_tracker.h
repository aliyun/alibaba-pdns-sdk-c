/*
 * DNS 失败计数器（内部）
 *
 * 按「请求维度」记录单次解析过程中的连续失败次数，供 pdns_server_manager
 * 判断是否从主用 provider 降级到备用 provider。
 *
 * key = domain:type:request_id
 *   之所以带 request_id：降级决策必须限定在「同一次解析」内，否则某个域名的
 *   历史失败会让后续无关请求一上来就直接走备用。请求成功或重试次数用尽即清除。
 *
 * 本 SDK 一切状态挂在 client 下（与 cache / acl 一致），故本模块为普通对象，
 * 由 manager 持有。
 *
 * 清理策略：不新起独立线程——由
 * client 已有的配置刷新定时器调用 pdns_failure_tracker_cleanup_expired()，
 * 另在写入路径做 30s 节流的惰性清理兜底（定时器未启动时也不会无限增长）。
 *
 * 线程安全：内部 APR 互斥量保护整张表。
 */
#ifndef PDNS_DNS_FAILURE_TRACKER_H
#define PDNS_DNS_FAILURE_TRACKER_H

#include <stdbool.h>

/* 请求记录存活时长（秒） */
#define PDNS_FAILURE_REQUEST_EXPIRE_SEC 60

/* 清理周期（秒） */
#define PDNS_FAILURE_CLEANUP_INTERVAL_SEC 30

/*
 * 记录条数上限。正常情况下在表内的只有「当前在飞且已失败过」的请求，
 * 数量受 max_concurrent_resolve 约束，远不到此值；此上限只为防御异常场景下
 * 无界增长（超限时丢弃最旧记录，最坏后果是该请求少一次降级判断）。
 */
#define PDNS_FAILURE_MAX_ENTRIES 256

typedef struct pdns_failure_tracker_s pdns_failure_tracker_t;

pdns_failure_tracker_t *pdns_failure_tracker_create(void);

void pdns_failure_tracker_destroy(pdns_failure_tracker_t *t);

/* 记录一次失败，累加该 domain:type:request_id 的失败计数 */
void pdns_failure_tracker_record_failure(pdns_failure_tracker_t *t,
                                             const char *domain,
                                             const char *type_str,
                                             const char *request_id);

/* 记录成功：等价于清除该请求的失败计数 */
void pdns_failure_tracker_record_success(pdns_failure_tracker_t *t,
                                             const char *domain,
                                             const char *type_str,
                                             const char *request_id);

/* 清除该请求的失败计数（请求成功或重试次数用尽时调用） */
void pdns_failure_tracker_reset(pdns_failure_tracker_t *t,
                                    const char *domain,
                                    const char *type_str,
                                    const char *request_id);

/*
 * 该请求是否应降级到备用 provider。
 *   - domain / request_id 为空：返回 false（无法定位记录，不降级）
 *   - fallback_threshold == 0：返回 true（配置为「立即降级」）
 *   - 否则：失败计数 >= fallback_threshold 时返回 true
 */
bool pdns_failure_tracker_should_fallback(pdns_failure_tracker_t *t,
                                              const char *domain,
                                              const char *type_str,
                                              const char *request_id,
                                              int fallback_threshold);

/* 清除所有超过 PDNS_FAILURE_REQUEST_EXPIRE_SEC 未更新的记录（由定时器调用） */
void pdns_failure_tracker_cleanup_expired(pdns_failure_tracker_t *t);

/* 当前记录条数（测试与日志用） */
int pdns_failure_tracker_size(pdns_failure_tracker_t *t);

#endif /* PDNS_DNS_FAILURE_TRACKER_H */
