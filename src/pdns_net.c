/*
 * 网络检测器实现 —— 类型缓存 + 集合对比切换检测 + 发布订阅回调 + 后台轮询
 */
#include "pdns_net.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <string.h>

#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_proc.h>

/* 轮询间隔（毫秒）与分段步长（便于停止标志及时生效） */
#define PDNS_NET_POLL_INTERVAL_MS 1000
#define PDNS_NET_POLL_STEP_MS     200

/* 最大订阅回调数（订阅者极少：server_manager / 预解析 等） */
#define PDNS_NET_MAX_CB 8

typedef struct {
    pdns_net_change_cb_fn fn;
    void                 *user_data;
    void                 *owner;
} pdns_net_cb_t;

struct pdns_net_detector_s {
    apr_pool_t         *pool;
    apr_thread_mutex_t *lock;
    volatile pdns_netstack_type_t type;   /* 网络栈类型缓存 */
    pdns_list_impl_t   *local_ips;         /* 上次本机 IP 快照 */
    pdns_net_cb_t       cbs[PDNS_NET_MAX_CB];
    int                 cb_count;
    apr_thread_t       *thread;
    volatile int        stop;
};

/* ---------------- 内部辅助 ---------------- */

static bool list_contains(const pdns_list_impl_t *list, const char *s) {
    size_t n = pdns_list_impl_size(list);
    for (size_t i = 0; i < n; i++) {
        const char *e = pdns_list_impl_get(list, i);
        if (e && strcmp(e, s) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * 集合对比判断网络是否变化：收集当前本机 IP，与上次快照比对
 * （数量不同，或出现快照中没有的新 IP 即视为变化）。变化则更新快照。
 */
static bool detect_change(pdns_net_detector_t *detector) {
    pdns_list_impl_t *new_ips = pdns_list_impl_create();
    if (pdns_netstack_collect_local_ips(new_ips) != 0) {
        pdns_list_impl_destroy(new_ips);
        return false;
    }

    apr_thread_mutex_lock(detector->lock);
    bool   changed = false;
    size_t nn = pdns_list_impl_size(new_ips);
    size_t no = pdns_list_impl_size(detector->local_ips);
    if (nn != no) {
        changed = true;
    } else {
        for (size_t i = 0; i < nn; i++) {
            const char *ip = pdns_list_impl_get(new_ips, i);
            if (ip && !list_contains(detector->local_ips, ip)) {
                changed = true;
                break;
            }
        }
    }
    if (changed) {
        pdns_list_impl_destroy(detector->local_ips);
        detector->local_ips = new_ips;
    }
    apr_thread_mutex_unlock(detector->lock);

    if (!changed) {
        pdns_list_impl_destroy(new_ips);
    }
    return changed;
}

/* 执行一次检测：变化时先内置重探网络栈，再依次触发所有订阅回调 */
static void do_check(pdns_net_detector_t *detector) {
    if (!detect_change(detector)) {
        return;
    }

    /* 内置任务：重探网络栈并更新缓存 */
    pdns_netstack_type_t t = pdns_netstack_detect();

    /* 复制回调快照，避免在锁内执行回调导致重入 */
    pdns_net_cb_t snapshot[PDNS_NET_MAX_CB];
    int           cnt;
    apr_thread_mutex_lock(detector->lock);
    detector->type = t;
    cnt = detector->cb_count;
    memcpy(snapshot, detector->cbs, sizeof(pdns_net_cb_t) * cnt);
    apr_thread_mutex_unlock(detector->lock);

    PDNS_LOGI("network changed: netstack=%d, notify %d subscriber(s)", t, cnt);
    for (int i = 0; i < cnt; i++) {
        if (snapshot[i].fn) {
            snapshot[i].fn(snapshot[i].user_data);
        }
    }
}

/* 后台轮询线程 */
static void *APR_THREAD_FUNC pdns_net_poll_worker(apr_thread_t *thd, void *param) {
    (void) thd;
    pdns_net_detector_t *detector = (pdns_net_detector_t *) param;
    while (!detector->stop) {
        int slept = 0;
        while (slept < PDNS_NET_POLL_INTERVAL_MS && !detector->stop) {
            apr_sleep((apr_interval_time_t) PDNS_NET_POLL_STEP_MS * 1000);
            slept += PDNS_NET_POLL_STEP_MS;
        }
        if (detector->stop) {
            break;
        }
        do_check(detector);
    }
    return NULL;
}

/* ---------------- 对外（模块内）入口 ---------------- */

pdns_net_detector_t *pdns_net_detector_create(void) {
    pdns_net_detector_t *detector =
        (pdns_net_detector_t *) calloc(1, sizeof(pdns_net_detector_t));
    if (detector == NULL) {
        return NULL;
    }
    if (apr_pool_create(&detector->pool, NULL) != APR_SUCCESS) {
        free(detector);
        return NULL;
    }
    apr_thread_mutex_create(&detector->lock, APR_THREAD_MUTEX_DEFAULT, detector->pool);
    detector->type      = PDNS_STACK_NONE;
    detector->local_ips = pdns_list_impl_create();
    detector->cb_count  = 0;
    detector->thread    = NULL;
    detector->stop      = 0;
    return detector;
}

void pdns_net_detector_start(pdns_net_detector_t *detector, bool enable_poll) {
    if (detector == NULL) {
        return;
    }
    /* 首次探测网络栈 + 初始化本机 IP 快照 */
    detector->type = pdns_netstack_detect();
    pdns_netstack_collect_local_ips(detector->local_ips);
    PDNS_LOGI("net detector start: netstack=%d(%s), poll=%s",
              detector->type, pdns_netstack_name(detector->type),
              enable_poll ? "on" : "off");

    if (enable_poll && detector->thread == NULL) {
        detector->stop = 0;
        apr_thread_create(&detector->thread, NULL, pdns_net_poll_worker, detector, detector->pool);
    }
}

void pdns_net_detector_set_poll(pdns_net_detector_t *detector, bool enable_poll) {
    if (detector == NULL) {
        return;
    }
    if (enable_poll) {
        /* 开：线程未跑时启动（已在跑则幂等） */
        if (detector->thread == NULL) {
            detector->stop = 0;
            apr_thread_create(&detector->thread, NULL, pdns_net_poll_worker,
                              detector, detector->pool);
            PDNS_LOGI("net detector poll: on");
        }
        return;
    }
    /* 关：停轮询线程（保留已探测的网络栈缓存与回调订阅） */
    if (detector->thread) {
        apr_status_t rv;
        detector->stop = 1;
        apr_thread_join(&rv, detector->thread);
        detector->thread = NULL;
        PDNS_LOGI("net detector poll: off");
    }
}

void pdns_net_detector_destroy(pdns_net_detector_t *detector) {
    if (detector == NULL) {
        return;
    }
    if (detector->thread) {
        apr_status_t rv;
        detector->stop = 1;
        apr_thread_join(&rv, detector->thread);
        detector->thread = NULL;
    }
    pdns_list_impl_destroy(detector->local_ips);
    if (detector->lock) {
        apr_thread_mutex_destroy(detector->lock);
    }
    if (detector->pool) {
        apr_pool_destroy(detector->pool);
    }
    free(detector);
}

pdns_netstack_type_t pdns_net_get_type(pdns_net_detector_t *detector) {
    if (detector == NULL) {
        return PDNS_STACK_NONE;
    }
    apr_thread_mutex_lock(detector->lock);
    pdns_netstack_type_t t = detector->type;
    apr_thread_mutex_unlock(detector->lock);
    if (t != PDNS_STACK_NONE) {
        return t;
    }
    /* 缓存为 NONE：重探并回写（相当于 UNKNOWN 持续重试） */
    t = pdns_netstack_detect();
    if (t != PDNS_STACK_NONE) {
        apr_thread_mutex_lock(detector->lock);
        detector->type = t;
        apr_thread_mutex_unlock(detector->lock);
    }
    return t;
}

void pdns_net_subscribe(pdns_net_detector_t *detector,
                        pdns_net_change_cb_fn fn,
                        void *user_data,
                        void *owner) {
    if (detector == NULL || fn == NULL) {
        return;
    }
    apr_thread_mutex_lock(detector->lock);
    /* 同一 owner 去重 */
    for (int i = 0; i < detector->cb_count; i++) {
        if (detector->cbs[i].owner == owner) {
            apr_thread_mutex_unlock(detector->lock);
            return;
        }
    }
    if (detector->cb_count < PDNS_NET_MAX_CB) {
        detector->cbs[detector->cb_count].fn        = fn;
        detector->cbs[detector->cb_count].user_data = user_data;
        detector->cbs[detector->cb_count].owner     = owner;
        detector->cb_count++;
    }
    apr_thread_mutex_unlock(detector->lock);
}

void pdns_net_unsubscribe(pdns_net_detector_t *detector, void *owner) {
    if (detector == NULL) {
        return;
    }
    apr_thread_mutex_lock(detector->lock);
    for (int i = 0; i < detector->cb_count; i++) {
        if (detector->cbs[i].owner == owner) {
            /* 用末尾元素覆盖，收缩数组 */
            detector->cbs[i] = detector->cbs[detector->cb_count - 1];
            detector->cb_count--;
            break;
        }
    }
    apr_thread_mutex_unlock(detector->lock);
}

void pdns_net_trigger_check(pdns_net_detector_t *detector) {
    if (detector == NULL) {
        return;
    }
    do_check(detector);
}
