/*
 * 日志模块（内部）—— 分级日志 + 全局开关 + 回调转接
 *
 * 级别 error/warn/info/debug，统一 "pdns" 前缀，
 * 默认输出到 stderr，可通过 pdns_log_set_logger 注入回调。
 * 线程安全：输出由全局互斥量保护（pdns_log_init 创建），避免多线程交错。
 */
#ifndef PDNS_LOG_H
#define PDNS_LOG_H

#include "pdns/pdns_api.h"

/* 初始化/销毁日志全局锁（由 pdns_sdk_init / pdns_sdk_cleanup 调用） */
void pdns_log_init(void);
void pdns_log_cleanup(void);

/* 日志开关是否开启 */
bool pdns_log_is_enabled(void);

/* 写一条日志（内部会判断开关与级别；fmt 为 printf 风格格式串）。
 * file/line/func 由便捷宏自动传入，用于定位问题。 */
void pdns_log_write(pdns_log_level_t level, const char *file, int line,
                    const char *func, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 5, 6)))
#endif
    ;

/* 便捷宏：自动带上文件/行号/函数名 */
#define PDNS_LOGE(...) pdns_log_write(PDNS_LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define PDNS_LOGW(...) pdns_log_write(PDNS_LOG_LEVEL_WARN,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define PDNS_LOGI(...) pdns_log_write(PDNS_LOG_LEVEL_INFO,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define PDNS_LOGD(...) pdns_log_write(PDNS_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)

#endif /* PDNS_LOG_H */
