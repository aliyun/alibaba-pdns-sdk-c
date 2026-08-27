/*
 * 通用工具（内部）—— 请求级追踪 ID 生成等
 */
#ifndef PDNS_UTIL_H
#define PDNS_UTIL_H

#include <stddef.h>

/* 初始化/销毁工具模块（生成设备前缀 + 初始化计数器与锁），由 pdns_sdk_init / pdns_sdk_cleanup 调用 */
void pdns_util_init(void);
void pdns_util_cleanup(void);

/*
 * 生成请求级唯一追踪 ID，写入 out。
 * 格式：{platform}_{16位设备前缀hex}_{16位计数器hex}。
 * 建议 out_len >= PDNS_REQUEST_ID_LEN。
 */
void pdns_gen_request_id(char *out, size_t out_len);

/*
 * 生成会话 ID：12 位 A-Za-z0-9 随机串。
 * 每个 client 创建时生成一次，随请求 &did= 上报，供服务端日志聚合分析。
 * 要求 out_len >= 13。
 */
void pdns_gen_session_id(char *out, size_t out_len);

#endif /* PDNS_UTIL_H */
