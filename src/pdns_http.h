/*
 * HTTP 传输抽象层（内部）—— 统一的 GET 请求封装
 *
 * 职责：封装 libcurl 细节，供 resolver（/resolve）、黑白名单（/config）、
 *       预解析/保活等场景复用。特性：
 *   - 从连接池（pdns_session）获取/归还 CURL handle，复用 TCP/TLS 连接
 *   - IP 直连（CURLOPT_RESOLVE），SNI/证书仍按 resolve_host 校验，IPv6 自动加方括号
 *   - 响应体缓冲、HTTP 状态码、请求 RTT 采集
 *   - 抽取响应 Date 头校正签名时间偏移（authTimeOffset）
 */
#ifndef PDNS_HTTP_H
#define PDNS_HTTP_H

#include <stdbool.h>
#include <stddef.h>

/* 超时参数（毫秒）：总超时与连接超时分离设置——
 * 连接超时必须短于总超时，确保 TCP 建连失败后仍留有余量响应超时，
 * 避免节点不可达时拖满整个总超时（加速服务节点切换）。
 *   PDNS_DEFAULT_TIMEOUT_MS      总超时默认值（timeout_ms <=0 时采用）
 *   PDNS_MAX_CONNECT_TIMEOUT_MS  连接超时上限（实际取 min(总超时, 本值)） */
#define PDNS_DEFAULT_TIMEOUT_MS      3000
#define PDNS_MAX_CONNECT_TIMEOUT_MS  2500

/* HTTP 请求参数 */
typedef struct {
    const char *url;           /* 完整 URL（含 query） */
    const char *resolve_host;  /* 直连时用于 SNI/证书校验的域名（如 dns.alidns.com） */
    const char *server_ip;     /* 直连目标 IP（可为 IPv6，无需方括号）；为空则不启用直连 */
    bool        using_https;   /* true=443/https，false=80/http */
    int         timeout_ms;    /* 超时（毫秒），<=0 用默认 PDNS_DEFAULT_TIMEOUT_MS */
    const char *request_id;    /* 请求追踪 ID（日志用），可为 NULL */
    /* 请求级统计头值（c/ne/se），为 NULL/空则不设置该头 */
    const char *hdr_c;         /* c：上次该 IP 的 RTT（毫秒，十进制字符串） */
    const char *hdr_ne;        /* ne：累计网络错误数 */
    const char *hdr_se;        /* se：服务器错误标记/计数 */
    /*
     * 跳过服务端证书校验。默认 false（校验），仅自建 DNS 在调用方显式关闭
     * enable_certificate_validation 时置 true（自签证书的私有化部署）。
     * 有意采用「跳过」这一否定式命名：本结构体一律 memset 归零后填充，
     * 零值必须落在安全的一侧（校验开启）。
     */
    bool        skip_cert_verify;
    bool        use_http2;      /* 启用 HTTP/2（TLS ALPN 协商，不支持时回落 HTTP/1.1） */
} pdns_http_request_t;

/* HTTP 响应结果 */
typedef struct {
    long   http_code;  /* HTTP 状态码 */
    int    curl_code;  /* CURLcode（0=CURLE_OK） */
    char  *body;       /* 响应体（malloc，需 pdns_http_response_free 释放） */
    size_t body_len;   /* 响应体长度 */
    long   rtt_ms;     /* 本次请求总耗时（毫秒） */
    long   conf_version; /* 响应头 Cv（服务端当前 ACL 版本），<0 表示响应未携带该头 */
} pdns_http_response_t;

/*
 * 发起一次 HTTP GET。
 * @return 0 表示 curl 成功执行（仍需检查 http_code）；非 0 表示传输失败。
 */
int pdns_http_get(const pdns_http_request_t *req, pdns_http_response_t *resp);

/* 释放响应体资源 */
void pdns_http_response_free(pdns_http_response_t *resp);

#endif /* PDNS_HTTP_H */
