/*
 * DNS 失败计数器实现
 *
 * 存储用单链表 + APR 互斥量（与 pdns_cache 同一套风格）。
 * 之所以不用 apr_hash：条目会被频繁增删，而 apr_hash 的 key 必须由外部保证生命周期，
 * 用 pool 分配 key 会随增删单调增长（APR pool 不支持单条释放），反而制造泄漏。
 * 表内条目数受在飞请求数约束（个位数量级），线性查找开销可忽略。
 */
#include "pdns_failure_tracker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_time.h>

/* key 缓冲：domain(253) + ':' + type(8) + ':' + request_id(64) 余量充足 */
#define PDNS_FAILURE_KEY_MAX_LEN 352

typedef struct failure_entry_s {
    char                    key[PDNS_FAILURE_KEY_MAX_LEN];
    int                     failure_count;
    apr_time_t              last_update;   /* 微秒，apr_time_now 基准 */
    struct failure_entry_s *next;
} failure_entry_t;

struct pdns_failure_tracker_s {
    apr_pool_t         *pool;
    apr_thread_mutex_t *lock;
    failure_entry_t    *head;
    int                 size;
    apr_time_t          last_cleanup;   /* 惰性清理节流基准 */
};

/* ---------------- 内部辅助 ---------------- */

/* 组装 key（domain + ":" + type + ":" + requestId）。
 * 返回 false 表示 domain / request_id 为空，调用方直接放弃本次操作（空值早退）。 */
static bool make_key(char *buf, size_t n, const char *domain,
                     const char *type_str, const char *request_id) {
    if (domain == NULL || domain[0] == '\0' ||
        request_id == NULL || request_id[0] == '\0') {
        return false;
    }
    snprintf(buf, n, "%s:%s:%s", domain, type_str ? type_str : "", request_id);
    return true;
}

/* 已持锁：按 key 查条目 */
static failure_entry_t *find_locked(pdns_failure_tracker_t *t, const char *key) {
    for (failure_entry_t *e = t->head; e != NULL; e = e->next) {
        if (strcmp(e->key, key) == 0) {
            return e;
        }
    }
    return NULL;
}

/* 已持锁：摘除并释放 key 对应条目 */
static void remove_locked(pdns_failure_tracker_t *t, const char *key) {
    failure_entry_t **pp = &t->head;
    while (*pp != NULL) {
        failure_entry_t *e = *pp;
        if (strcmp(e->key, key) == 0) {
            *pp = e->next;
            free(e);
            t->size--;
            return;
        }
        pp = &e->next;
    }
}

/* 已持锁：清除过期条目 */
static void cleanup_locked(pdns_failure_tracker_t *t) {
    apr_time_t now       = apr_time_now();
    apr_time_t threshold = now - apr_time_from_sec(PDNS_FAILURE_REQUEST_EXPIRE_SEC);

    failure_entry_t **pp = &t->head;
    while (*pp != NULL) {
        failure_entry_t *e = *pp;
        if (e->last_update < threshold) {
            *pp = e->next;
            free(e);
            t->size--;
        } else {
            pp = &e->next;
        }
    }
    t->last_cleanup = now;
}

/* 已持锁：丢弃最旧（last_update 最小）的一条，用于超出上限时腾位 */
static void evict_oldest_locked(pdns_failure_tracker_t *t) {
    failure_entry_t **pp      = &t->head;
    failure_entry_t **oldest  = NULL;
    apr_time_t        min_upd = 0;
    for (failure_entry_t **cur = pp; *cur != NULL; cur = &(*cur)->next) {
        if (oldest == NULL || (*cur)->last_update < min_upd) {
            oldest  = cur;
            min_upd = (*cur)->last_update;
        }
    }
    if (oldest != NULL) {
        failure_entry_t *e = *oldest;
        *oldest = e->next;
        free(e);
        t->size--;
    }
}

/* ---------------- 生命周期 ---------------- */

pdns_failure_tracker_t *pdns_failure_tracker_create(void) {
    pdns_failure_tracker_t *t =
        (pdns_failure_tracker_t *) calloc(1, sizeof(pdns_failure_tracker_t));
    if (t == NULL) {
        return NULL;
    }
    if (apr_pool_create(&t->pool, NULL) != APR_SUCCESS) {
        free(t);
        return NULL;
    }
    if (apr_thread_mutex_create(&t->lock, APR_THREAD_MUTEX_DEFAULT, t->pool)
        != APR_SUCCESS) {
        apr_pool_destroy(t->pool);
        free(t);
        return NULL;
    }
    t->last_cleanup = apr_time_now();
    return t;
}

void pdns_failure_tracker_destroy(pdns_failure_tracker_t *t) {
    if (t == NULL) {
        return;
    }
    failure_entry_t *e = t->head;
    while (e != NULL) {
        failure_entry_t *next = e->next;
        free(e);
        e = next;
    }
    if (t->pool != NULL) {
        apr_pool_destroy(t->pool);   /* 互斥量随 pool 销毁 */
    }
    free(t);
}

/* ---------------- 请求维度 API ---------------- */

void pdns_failure_tracker_record_failure(pdns_failure_tracker_t *t,
                                             const char *domain,
                                             const char *type_str,
                                             const char *request_id) {
    char key[PDNS_FAILURE_KEY_MAX_LEN];
    if (t == NULL || !make_key(key, sizeof(key), domain, type_str, request_id)) {
        return;
    }

    apr_thread_mutex_lock(t->lock);

    /* 惰性清理兜底：定时器未启动（未调 pdns_client_start）时也不会无界增长 */
    if (apr_time_now() - t->last_cleanup >=
        apr_time_from_sec(PDNS_FAILURE_CLEANUP_INTERVAL_SEC)) {
        cleanup_locked(t);
    }

    failure_entry_t *e = find_locked(t, key);
    if (e != NULL) {
        e->failure_count++;
        e->last_update = apr_time_now();
        apr_thread_mutex_unlock(t->lock);
        return;
    }

    if (t->size >= PDNS_FAILURE_MAX_ENTRIES) {
        evict_oldest_locked(t);
    }
    e = (failure_entry_t *) calloc(1, sizeof(failure_entry_t));
    if (e == NULL) {
        apr_thread_mutex_unlock(t->lock);
        return;
    }
    strncpy(e->key, key, sizeof(e->key) - 1);
    e->failure_count = 1;
    e->last_update   = apr_time_now();
    e->next          = t->head;
    t->head          = e;
    t->size++;

    apr_thread_mutex_unlock(t->lock);
}

void pdns_failure_tracker_record_success(pdns_failure_tracker_t *t,
                                             const char *domain,
                                             const char *type_str,
                                             const char *request_id) {
    pdns_failure_tracker_reset(t, domain, type_str, request_id);
}

void pdns_failure_tracker_reset(pdns_failure_tracker_t *t,
                                    const char *domain,
                                    const char *type_str,
                                    const char *request_id) {
    char key[PDNS_FAILURE_KEY_MAX_LEN];
    if (t == NULL || !make_key(key, sizeof(key), domain, type_str, request_id)) {
        return;
    }
    apr_thread_mutex_lock(t->lock);
    remove_locked(t, key);
    apr_thread_mutex_unlock(t->lock);
}

bool pdns_failure_tracker_should_fallback(pdns_failure_tracker_t *t,
                                              const char *domain,
                                              const char *type_str,
                                              const char *request_id,
                                              int fallback_threshold) {
    char key[PDNS_FAILURE_KEY_MAX_LEN];
    if (t == NULL || !make_key(key, sizeof(key), domain, type_str, request_id)) {
        return false;
    }
    /* threshold=0 表示「不给主用机会，直接降级」 */
    if (fallback_threshold == 0) {
        return true;
    }
    apr_thread_mutex_lock(t->lock);
    failure_entry_t *e = find_locked(t, key);
    bool should = (e != NULL) && (e->failure_count >= fallback_threshold);
    apr_thread_mutex_unlock(t->lock);
    return should;
}

void pdns_failure_tracker_cleanup_expired(pdns_failure_tracker_t *t) {
    if (t == NULL) {
        return;
    }
    apr_thread_mutex_lock(t->lock);
    cleanup_locked(t);
    apr_thread_mutex_unlock(t->lock);
}

int pdns_failure_tracker_size(pdns_failure_tracker_t *t) {
    if (t == NULL) {
        return 0;
    }
    apr_thread_mutex_lock(t->lock);
    int n = t->size;
    apr_thread_mutex_unlock(t->lock);
    return n;
}
