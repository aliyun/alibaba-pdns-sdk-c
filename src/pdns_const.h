/*
 * SDK 内部公共常量（内部）
 *
 * 集中 SDK 版本号与平台标识（随请求上报 &sv= / &pf= / p=），
 * 避免分散定义导致改版本时漏改。
 */
#ifndef PDNS_CONST_H
#define PDNS_CONST_H

#include "pdns/pdns_api.h"

/* SDK 版本号（随请求上报 &sv= / v=）。
 * 唯一定义在对外头 pdns_api.h 的 PDNS_VERSION，此处仅别名，
 * 避免两处硬编码导致改版本时漏改。 */
#define PDNS_SDK_VERSION PDNS_VERSION

/* 平台标识（随请求上报 &pf= / p=，采用 c 前缀命名风格） */
#if defined(_WIN32)
#define PDNS_PLATFORM "cwindows"
#elif defined(__APPLE__)
#define PDNS_PLATFORM "cmac"
#else
#define PDNS_PLATFORM "clinux"
#endif

#endif /* PDNS_CONST_H */
