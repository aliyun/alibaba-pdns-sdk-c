/*
 * 日志模块实现
 */
#include "pdns_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_time.h>
#include <apr_portable.h>

#ifndef PDNS_LOG_USE_COLOR
#define PDNS_LOG_USE_COLOR 1   /* 默认 stderr 输出按级别上色，可通过编译宏关闭 */
#endif

/* 全局开关、回调、输出锁（进程级） */
static bool                g_log_enable = false;
static pdns_log_level_t     g_log_level  = PDNS_LOG_LEVEL_DEBUG;  /* 默认输出全部级别 */
static pdns_logger_fn      g_logger     = NULL;
static apr_pool_t         *g_log_pool   = NULL;
static apr_thread_mutex_t *g_log_lock   = NULL;

/* 级别文字 */
static const char *level_tag(pdns_log_level_t level) {
    switch (level) {
        case PDNS_LOG_LEVEL_ERROR: return "E";
        case PDNS_LOG_LEVEL_WARN:  return "W";
        case PDNS_LOG_LEVEL_INFO:  return "I";
        case PDNS_LOG_LEVEL_DEBUG: return "D";
        default:                   return "?";
    }
}

#if PDNS_LOG_USE_COLOR
/* 级别颜色（ANSI）：仅用于默认 stderr 输出，注入回调不上色 */
static const char *level_color(pdns_log_level_t level) {
    switch (level) {
        case PDNS_LOG_LEVEL_ERROR: return "\x1b[31m"; /* 红 */
        case PDNS_LOG_LEVEL_WARN:  return "\x1b[33m"; /* 黄 */
        case PDNS_LOG_LEVEL_INFO:  return "\x1b[32m"; /* 绿 */
        case PDNS_LOG_LEVEL_DEBUG: return "\x1b[36m"; /* 青 */
        default:                   return "\x1b[0m";
    }
}
#endif

/* ---------------- 对外（模块内）入口 ---------------- */

void pdns_log_init(void) {
    if (g_log_lock != NULL) {
        return;
    }
    if (apr_pool_create(&g_log_pool, NULL) == APR_SUCCESS) {
        apr_thread_mutex_create(&g_log_lock, APR_THREAD_MUTEX_DEFAULT, g_log_pool);
    }
}

void pdns_log_cleanup(void) {
    if (g_log_lock != NULL) {
        apr_thread_mutex_destroy(g_log_lock);
        g_log_lock = NULL;
    }
    if (g_log_pool != NULL) {
        apr_pool_destroy(g_log_pool);
        g_log_pool = NULL;
    }
}

void pdns_log_set_enable(bool enable) {
    g_log_enable = enable;
}

void pdns_log_set_level(pdns_log_level_t level) {
    g_log_level = level;
}

void pdns_log_set_logger(pdns_logger_fn logger) {
    g_logger = logger;
}

bool pdns_log_is_enabled(void) {
    return g_log_enable;
}

void pdns_log_write(pdns_log_level_t level, const char *file, int line_no,
                    const char *func, const char *fmt, ...) {
    if (!g_log_enable || level > g_log_level || fmt == NULL) {
        return;
    }

    /* 先格式化用户内容 */
    char    body[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    /* 本地时间戳到毫秒：[YYYY-MM-DD HH:MM:SS.mmm] */
    char            ts[32];
    apr_time_t      now = apr_time_now();
    apr_time_exp_t  lt;
    if (apr_time_exp_lt(&lt, now) == APR_SUCCESS) {
        snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                 lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
                 lt.tm_hour, lt.tm_min, lt.tm_sec,
                 (int)(lt.tm_usec / 1000));
    } else {
        ts[0] = '\0';
    }

    /* 线程 ID（便于并发定位） */
    unsigned long tid = (unsigned long)(uintptr_t) apr_os_thread_current();

    /* 文件名取 basename，去掉目录前缀，日志更短 */
    const char *base = file ? strrchr(file, '/') : NULL;
    base = base ? base + 1 : (file ? file : "?");
    const char *fn = func ? func : "?";

    /* 完整日志行：[时间][pdns][级别][tid][文件:行 函数] 内容 */
    char line[1400];

    /* 输出加锁，避免多线程交错 */
    if (g_log_lock != NULL) {
        apr_thread_mutex_lock(g_log_lock);
    }
    if (g_logger != NULL) {
        /* 注入回调：传无颜色的纯文本，避免污染集成方日志系统 */
        snprintf(line, sizeof(line), "[%s][pdns][%s][tid=%lu][%s:%d %s] %s",
                 ts, level_tag(level), tid, base, line_no, fn, body);
        g_logger(level, line);
    } else {
#if PDNS_LOG_USE_COLOR
        /* 默认输出：整行按级别上色（颜色码置行首，reset 置行尾） */
        snprintf(line, sizeof(line), "%s[%s][pdns][%s][tid=%lu][%s:%d %s] %s\x1b[0m",
                 level_color(level), ts, level_tag(level), tid, base, line_no, fn, body);
#else
        snprintf(line, sizeof(line), "[%s][pdns][%s][tid=%lu][%s:%d %s] %s",
                 ts, level_tag(level), tid, base, line_no, fn, body);
#endif
        /* 按级别分流：ERROR/WARN 走 stderr（问题信息，IDE 标红合理、便于 2> 收集）；
         * INFO/DEBUG 走 stdout（避免被 IDE 整片标红，分级 ANSI 颜色可正常显示）。 */
        FILE *out = (level <= PDNS_LOG_LEVEL_WARN) ? stderr : stdout;
        fprintf(out, "%s\n", line);
    }
    if (g_log_lock != NULL) {
        apr_thread_mutex_unlock(g_log_lock);
    }
}
