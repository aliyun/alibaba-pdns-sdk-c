/*
 * curl 会话连接池实现
 */
#include "pdns_session.h"

#include <stdbool.h>
#include <apr_pools.h>
#include <apr_thread_mutex.h>

/* 进程级 handle 栈 */
static apr_pool_t         *g_pool = NULL;
static apr_thread_mutex_t *g_lock = NULL;
static CURL               *g_stack[PDNS_SESSION_POOL_SIZE];
static int                 g_top = 0;   /* 栈内可用 handle 数 */

void pdns_session_init(void) {
    if (g_lock != NULL) {
        return;
    }
    if (apr_pool_create(&g_pool, NULL) == APR_SUCCESS) {
        apr_thread_mutex_create(&g_lock, APR_THREAD_MUTEX_DEFAULT, g_pool);
    }
    g_top = 0;
}

void pdns_session_cleanup(void) {
    if (g_lock != NULL) {
        apr_thread_mutex_lock(g_lock);
    }
    for (int i = 0; i < g_top; i++) {
        curl_easy_cleanup(g_stack[i]);
        g_stack[i] = NULL;
    }
    g_top = 0;
    if (g_lock != NULL) {
        apr_thread_mutex_unlock(g_lock);
        apr_thread_mutex_destroy(g_lock);
        g_lock = NULL;
    }
    if (g_pool != NULL) {
        apr_pool_destroy(g_pool);
        g_pool = NULL;
    }
}

CURL *pdns_session_acquire(void) {
    CURL *handle = NULL;
    if (g_lock != NULL) {
        apr_thread_mutex_lock(g_lock);
    }
    if (g_top > 0) {
        handle = g_stack[--g_top];
    }
    if (g_lock != NULL) {
        apr_thread_mutex_unlock(g_lock);
    }
    if (handle != NULL) {
        curl_easy_reset(handle);   /* 复用前清空上次配置 */
        return handle;
    }
    /* 池空则新建 */
    return curl_easy_init();
}

void pdns_session_release(CURL *handle) {
    if (handle == NULL) {
        return;
    }
    bool pushed = false;
    if (g_lock != NULL) {
        apr_thread_mutex_lock(g_lock);
    }
    if (g_top < PDNS_SESSION_POOL_SIZE) {
        g_stack[g_top++] = handle;
        pushed = true;
    }
    if (g_lock != NULL) {
        apr_thread_mutex_unlock(g_lock);
    }
    if (!pushed) {
        /* 栈满，直接销毁 */
        curl_easy_cleanup(handle);
    }
}
