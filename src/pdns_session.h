/*
 * curl 会话连接池（内部）—— 复用 CURL handle 以复用 TCP 连接
 *
 * 进程级维护一个 CURL* 栈，acquire 时优先复用
 * （reset 后返回），release 时归还入栈；栈满则销毁。减少频繁
 * curl_easy_init/cleanup 的开销，提升 TCP/TLS 连接复用率。
 * 线程安全：APR 互斥量保护。
 */
#ifndef PDNS_SESSION_H
#define PDNS_SESSION_H

#include <curl/curl.h>

/* 连接池容量 */
#define PDNS_SESSION_POOL_SIZE 32

/* 初始化/销毁连接池（由 pdns_sdk_init / pdns_sdk_cleanup 调用） */
void pdns_session_init(void);
void pdns_session_cleanup(void);

/* 取一个可用 CURL handle（已 reset）；失败返回 NULL */
CURL *pdns_session_acquire(void);

/* 归还 CURL handle（栈满则销毁） */
void pdns_session_release(CURL *handle);

#endif /* PDNS_SESSION_H */
