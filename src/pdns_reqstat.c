/*
 * 请求级统计头状态实现 —— c / ne / se
 */
#include "pdns_reqstat.h"

#include <stdio.h>
#include <string.h>

#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_thread_mutex.h>

/* 单条统计：按 (ip, host, qtype) 归属 */
typedef struct {
    int rtt_ms;  /* 上次成功 RTT（毫秒），供下次 c 头 */
    int ne;      /* 累计网络错误数 */
    int se;      /* 累计服务器错误数 */
} reqstat_val_t;

static apr_pool_t         *g_pool = NULL;
static apr_thread_mutex_t *g_lock = NULL;
static apr_hash_t         *g_map  = NULL;

void pdns_reqstat_init(void) {
    if (g_pool != NULL) {
        return;
    }
    if (apr_pool_create(&g_pool, NULL) != APR_SUCCESS) {
        return;
    }
    apr_thread_mutex_create(&g_lock, APR_THREAD_MUTEX_DEFAULT, g_pool);
    g_map = apr_hash_make(g_pool);
}

void pdns_reqstat_cleanup(void) {
    if (g_lock != NULL) {
        apr_thread_mutex_destroy(g_lock);
        g_lock = NULL;
    }
    if (g_pool != NULL) {
        apr_pool_destroy(g_pool);
        g_pool = NULL;
    }
    g_map = NULL;
}

/* key = ip_host_qtype */
static void make_key(char *buf, size_t n, const char *ip, const char *host, const char *qtype) {
    snprintf(buf, n, "%s_%s_%s", ip ? ip : "", host ? host : "", qtype ? qtype : "");
}

/* 取或建条目（须持锁）。 */
static reqstat_val_t *get_or_create(const char *key) {
    reqstat_val_t *v = (reqstat_val_t *) apr_hash_get(g_map, key, APR_HASH_KEY_STRING);
    if (v == NULL) {
        v = (reqstat_val_t *) apr_pcalloc(g_pool, sizeof(*v));
        char *k = apr_pstrdup(g_pool, key);
        apr_hash_set(g_map, k, APR_HASH_KEY_STRING, v);
    }
    return v;
}

void pdns_reqstat_take(const char *ip, const char *host, const char *qtype,
                       int *out_rtt_ms, int *out_ne, int *out_se) {
    if (out_rtt_ms) *out_rtt_ms = 0;
    if (out_ne)     *out_ne = 0;
    if (out_se)     *out_se = 0;
    if (g_map == NULL || ip == NULL || host == NULL) {
        return;
    }
    char key[320];
    make_key(key, sizeof(key), ip, host, qtype);

    apr_thread_mutex_lock(g_lock);
    reqstat_val_t *v = (reqstat_val_t *) apr_hash_get(g_map, key, APR_HASH_KEY_STRING);
    if (v != NULL) {
        if (out_rtt_ms) *out_rtt_ms = v->rtt_ms;
        if (out_ne)     *out_ne = v->ne;
        if (out_se)     *out_se = v->se;
        /* 消费：读后清零 */
        v->rtt_ms = 0;
        v->ne     = 0;
        v->se     = 0;
    }
    apr_thread_mutex_unlock(g_lock);
}

void pdns_reqstat_on_success(const char *ip, const char *host, const char *qtype,
                             long rtt_ms, long max_rtt_ms) {
    if (g_map == NULL || ip == NULL || host == NULL) {
        return;
    }
    if (rtt_ms < 0) {
        rtt_ms = 0;
    }
    if (max_rtt_ms > 0 && rtt_ms > max_rtt_ms) {
        rtt_ms = max_rtt_ms;
    }
    char key[320];
    make_key(key, sizeof(key), ip, host, qtype);

    apr_thread_mutex_lock(g_lock);
    reqstat_val_t *v = get_or_create(key);
    v->rtt_ms = (int) rtt_ms;
    v->ne     = 0;   /* 成功清网络错误 */
    apr_thread_mutex_unlock(g_lock);
}

void pdns_reqstat_on_net_error(const char *ip, const char *host, const char *qtype) {
    if (g_map == NULL || ip == NULL || host == NULL) {
        return;
    }
    char key[320];
    make_key(key, sizeof(key), ip, host, qtype);

    apr_thread_mutex_lock(g_lock);
    reqstat_val_t *v = get_or_create(key);
    v->ne += 1;
    apr_thread_mutex_unlock(g_lock);
}

void pdns_reqstat_on_server_error(const char *ip, const char *host, const char *qtype) {
    if (g_map == NULL || ip == NULL || host == NULL) {
        return;
    }
    char key[320];
    make_key(key, sizeof(key), ip, host, qtype);

    apr_thread_mutex_lock(g_lock);
    reqstat_val_t *v = get_or_create(key);
    v->se += 1;
    apr_thread_mutex_unlock(g_lock);
}
