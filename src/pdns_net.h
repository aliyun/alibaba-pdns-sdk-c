/*
 * 网络检测器（内部）—— 网络栈类型缓存 + 切换检测 + 发布订阅回调
 *
 *   - 类型检测：缓存网络栈类型，UNKNOWN 时限时重试（网络切换后栈需时间稳定）
 *   - 切换检测：后台线程定期用"本机 IP 集合对比"判断网络是否变化（集合对比，不受顺序影响）
 *   - 发布订阅：任意模块可注册"网络变化"回调（server_manager 重置 SRTT、重新预解析等），
 *              检测到变化时先内置重探网络栈，再依次触发所有订阅回调
 * 线程安全：内部 APR 互斥量保护。
 */
#ifndef PDNS_NET_H
#define PDNS_NET_H

#include "pdns_netstack.h"

typedef struct pdns_net_detector_s pdns_net_detector_t;

/* 网络变化回调：由订阅者注入，user_data 为订阅时传入的透传指针 */
typedef void (*pdns_net_change_cb_fn)(void *user_data);

/* 创建检测器（不自动启动后台线程，需调用 start） */
pdns_net_detector_t *pdns_net_detector_create(void);

/* 启动：首次探测网络栈 + 初始化本机 IP 快照；enable_poll 为 true 时启动后台轮询线程 */
void pdns_net_detector_start(pdns_net_detector_t *detector, bool enable_poll);

/* 停止后台线程并释放资源 */
void pdns_net_detector_destroy(pdns_net_detector_t *detector);

/*
 * 运行期开关后台轮询（幂等）：开则启动轮询线程，关则停线程。
 * 关闭后仍保留已探测的网络栈缓存与回调订阅，不影响手动 trigger_check。
 */
void pdns_net_detector_set_poll(pdns_net_detector_t *detector, bool enable_poll);

/*
 * 取网络栈类型：命中缓存直接返回；缓存为 NONE 时重探并回写缓存。
 */
pdns_netstack_type_t pdns_net_get_type(pdns_net_detector_t *detector);

/*
 * 订阅网络变化通知（发布订阅）。同一 owner 重复订阅会被忽略。
 * @param owner 订阅者标识，用于去重与退订。
 */
void pdns_net_subscribe(pdns_net_detector_t *detector,
                        pdns_net_change_cb_fn fn,
                        void *user_data,
                        void *owner);

/* 按 owner 退订网络变化通知 */
void pdns_net_unsubscribe(pdns_net_detector_t *detector, void *owner);

/* 手动触发一次网络变化检测（供集成方监听系统网络事件时调用） */
void pdns_net_trigger_check(pdns_net_detector_t *detector);

#endif /* PDNS_NET_H */
