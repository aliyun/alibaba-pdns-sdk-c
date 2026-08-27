/*
 * HTTP 传输抽象层实现 —— libcurl + 连接池 + Date 头时间校正
 */
#include "pdns_http.h"
#include "pdns_session.h"
#include "pdns_sign.h"
#include "pdns_log.h"
#include "pdns_const.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

#include <curl/curl.h>

/* ---------------- 响应缓冲 ---------------- */

typedef struct {
    char  *data;
    size_t size;
} resp_buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp) {
    size_t real = size * nmemb;
    resp_buf_t *buf = (resp_buf_t *) userp;
    char *np = (char *) realloc(buf->data, buf->size + real + 1);
    if (np == NULL) {
        return 0;
    }
    buf->data = np;
    memcpy(buf->data + buf->size, ptr, real);
    buf->size += real;
    buf->data[buf->size] = '\0';
    return real;
}

/* 大小写不敏感前缀匹配（跨平台，避免 strncasecmp 头文件差异） */
static bool starts_with_ci(const char *s, const char *prefix) {
    for (; *prefix != '\0'; s++, prefix++) {
        if (tolower((unsigned char) *s) != tolower((unsigned char) *prefix)) {
            return false;
        }
    }
    return true;
}

/* 响应头回调：
 *   - 抽取 Date 头校正签名时间偏移（authTimeOffset）
 *   - 抽取 Cv 头（服务端当前 ACL 版本）写入 resp->conf_version */
static size_t header_cb(char *buffer, size_t size, size_t nitems, void *userp) {
    pdns_http_response_t *resp = (pdns_http_response_t *) userp;
    size_t len = size * nitems;
    if (len > 6 && starts_with_ci(buffer, "Date:")) {
        char   datestr[128];
        size_t off = 5;
        while (off < len && (buffer[off] == ' ' || buffer[off] == '\t')) {
            off++;
        }
        size_t n = 0;
        while (off < len && n < sizeof(datestr) - 1 &&
               buffer[off] != '\r' && buffer[off] != '\n') {
            datestr[n++] = buffer[off++];
        }
        datestr[n] = '\0';
        time_t server_time = curl_getdate(datestr, NULL);
        if (server_time != -1) {
            pdns_sign_update_offset((long) server_time);
        }
    } else if (resp != NULL && len > 3 && starts_with_ci(buffer, "Cv:")) {
        char   cvstr[32];
        size_t off = 3;
        while (off < len && (buffer[off] == ' ' || buffer[off] == '\t')) {
            off++;
        }
        size_t n = 0;
        while (off < len && n < sizeof(cvstr) - 1 &&
               buffer[off] != '\r' && buffer[off] != '\n') {
            cvstr[n++] = buffer[off++];
        }
        cvstr[n] = '\0';
        if (n > 0) {
            resp->conf_version = atol(cvstr);
        }
    }
    return len;
}

/* ---------------- 对外（模块内）入口 ---------------- */

int pdns_http_get(const pdns_http_request_t *req, pdns_http_response_t *resp) {
    if (req == NULL || req->url == NULL || resp == NULL) {
        return 1;
    }
    memset(resp, 0, sizeof(*resp));
    resp->conf_version = -1;   /* -1 表示响应未携带 Cv 头 */

    /* curl 选项设置宏：统一设置入口，避免逐行重复句柄变量。仅在本函数内有效。
     * 纯语法糖——所有选项的语义依据 libcurl 官方文档显式声明（见下方逐项注释），
     * 不依赖版本默认值。 */
#define PDNS_SETOPT(opt, val) curl_easy_setopt(curl, opt, val)

    CURL *curl = pdns_session_acquire();
    if (curl == NULL) {
        return 1;
    }

    resp_buf_t         buf          = {0};
    struct curl_slist *resolve_list = NULL;
    int                port         = req->using_https ? 443 : 80;

    /* IP 直连：resolve_host:port:server_ip，IPv6 需方括号包裹 */
    if (req->server_ip && req->server_ip[0] && req->resolve_host && req->resolve_host[0]) {
        char resolve_entry[160];
        if (strchr(req->server_ip, ':') != NULL) {
            snprintf(resolve_entry, sizeof(resolve_entry), "%s:%d:[%s]",
                     req->resolve_host, port, req->server_ip);
        } else {
            snprintf(resolve_entry, sizeof(resolve_entry), "%s:%d:%s",
                     req->resolve_host, port, req->server_ip);
        }
        resolve_list = curl_slist_append(NULL, resolve_entry);
        PDNS_SETOPT(CURLOPT_RESOLVE, resolve_list);
    }

    PDNS_SETOPT(CURLOPT_URL, req->url);
    /* 自定义 UA：标识 SDK 身份与版本（版本宏随 pdns_api.h 升级自动跟随），
     * 服务端可据此做客户端统计与问题定位。 */
    PDNS_SETOPT(CURLOPT_USERAGENT, "pdns-c-sdk/" PDNS_SDK_VERSION);
    /* 显式忽略环境代理：libcurl 在 UNIX 下默认读取 http_proxy/HTTPS_PROXY
     * 环境变量，宿主机器若有全局代理配置，DNS 请求会被劫持走代理（变慢、
     * 失败、甚至把解析域名泄漏给代理服务器）。置空串禁用；代理类型显式
     * 声明为 HTTP（libcurl 默认值，防御性重申，不依赖版本默认）。 */
    PDNS_SETOPT(CURLOPT_PROXY, "");
    PDNS_SETOPT(CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    /*
     * 多线程必设（libcurl 官方要求）。未设置时有两处危害：
     *   1. 每次 curl_easy_perform 会把【进程级】的 SIGPIPE 临时改成 SIG_IGN 再恢复，
     *      而「恢复用的旧值」保存在各自线程的栈上。并发请求时，后完成的线程会用它
     *      读到的 SIG_IGN 覆盖先完成线程的恢复，导致宿主 App 自己装的 SIGPIPE
     *      handler 被永久丢弃。已实测：8 线程 × 30 次并发即稳定复现（本 SDK 的线程池
     *      worker / detector 轮询 / 测速线程本就会并发发请求）。
     *   2. 未启用 AsynchDNS 的 libcurl 构建会用 SIGALRM + siglongjmp 实现「名字解析
     *      超时」，在非主线程 siglongjmp 属未定义行为。触发路径是 server_ip 为空的
     *      HOST 域名兜底（见上方），此时走系统 DNS 解析 dns.alidns.com。
     * 注：本选项会被 pdns_session_acquire 的 curl_easy_reset 清除，故须每次请求设置。
     *
     * 副作用：关闭 signal 后 DNS 超时改由异步解析器控制。已实测本机 AsynchDNS=yes
     * 时超时正常（设 40ms 实测 29ms 返回）；即使某些构建未启用 AsynchDNS，也仅影响
     * HOST 兜底这一条低频路径（主路径走 IP 直连，不做 DNS 查询）。
     */
    PDNS_SETOPT(CURLOPT_NOSIGNAL, 1L);
    /*
     * 以下三项均为「显式重申 libcurl 默认值」：
     * 默认值随 libcurl 版本演进过（NOPROGRESS 在 7.x 早期默认为 0，TCP_NODELAY
     * 在 7.50 之前默认为 0），交付到宿主机器上的 libcurl 版本不可控，故显式声明，
     * 不依赖默认值。NETRC 显式忽略，避免读取 ~/.netrc 引入意料外的凭证行为。
     */
    PDNS_SETOPT(CURLOPT_NOPROGRESS, 1L);
    PDNS_SETOPT(CURLOPT_TCP_NODELAY, 1L);
    PDNS_SETOPT(CURLOPT_NETRC, (long) CURL_NETRC_IGNORED);
    long timeout_total = (long) (req->timeout_ms > 0 ? req->timeout_ms
                                                     : PDNS_DEFAULT_TIMEOUT_MS);
    PDNS_SETOPT(CURLOPT_TIMEOUT_MS, timeout_total);
    /* 连接超时独立于总超时：TCP 建连快慢不应拖垮整体超时预算。
     * 上限 PDNS_MAX_CONNECT_TIMEOUT_MS，且不超过总超时（调用方可把总超时调到
     * 2500ms 以下，此时以总超时为准，保证连接超时恒不晚于总超时）。 */
    long timeout_connect = timeout_total < PDNS_MAX_CONNECT_TIMEOUT_MS
                           ? timeout_total : PDNS_MAX_CONNECT_TIMEOUT_MS;
    PDNS_SETOPT(CURLOPT_CONNECTTIMEOUT_MS, timeout_connect);
    PDNS_SETOPT(CURLOPT_WRITEFUNCTION, write_cb);
    PDNS_SETOPT(CURLOPT_WRITEDATA, &buf);
    PDNS_SETOPT(CURLOPT_HEADERFUNCTION, header_cb);
    PDNS_SETOPT(CURLOPT_HEADERDATA, resp);
    PDNS_SETOPT(CURLOPT_FOLLOWLOCATION, 0L);
    /*
     * 证书校验：默认开启（与 libcurl 默认一致，但这里必须显式设回——
     * handle 来自连接池，上一次可能是自建请求关过校验；curl_easy_reset 虽会
     * 恢复默认值，但不依赖它更稳妥）。
     * 仅自建 DNS 在调用方显式关闭校验时才置 0，公共 DNS 无此开关。
     */
    if (req->skip_cert_verify) {
        PDNS_SETOPT(CURLOPT_SSL_VERIFYPEER, 0L);
        PDNS_SETOPT(CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        PDNS_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
        PDNS_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    }
#if defined(_WIN32)
    PDNS_SETOPT(CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    /* HTTP/2：默认开（client 默认 true）。开启后通过 TLS ALPN 协商优先走
     * h2，服务端或 libcurl 不支持时自动回落 HTTP/1.1，不影响请求成功率。
     * 编译期保护：CURL_HTTP_VERSION_2 宏随 HTTP/2 支持（7.43.0）引入，
     * 旧版 libcurl 头文件（如 CentOS 7 自带 7.29.0）无此宏，整个分支不参与
     * 编译，老环境构建零影响且默认走 HTTP/1.1。 */
    if (req->use_http2) {
#ifdef CURL_HTTP_VERSION_2
        PDNS_SETOPT(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
#endif
    }

    /* 请求级统计头 c/ne/se：仅在有值时追加 */
    struct curl_slist *headers = NULL;
    char               hbuf[64];
    if (req->hdr_c && req->hdr_c[0]) {
        snprintf(hbuf, sizeof(hbuf), "c: %s", req->hdr_c);
        headers = curl_slist_append(headers, hbuf);
    }
    if (req->hdr_ne && req->hdr_ne[0]) {
        snprintf(hbuf, sizeof(hbuf), "ne: %s", req->hdr_ne);
        headers = curl_slist_append(headers, hbuf);
    }
    if (req->hdr_se && req->hdr_se[0]) {
        snprintf(hbuf, sizeof(hbuf), "se: %s", req->hdr_se);
        headers = curl_slist_append(headers, hbuf);
    }
    if (headers != NULL) {
        PDNS_SETOPT(CURLOPT_HTTPHEADER, headers);
    }

    PDNS_LOGD("http get: rid=%s url=%s server=%s c=%s ne=%s se=%s",
              req->request_id ? req->request_id : "-", req->url,
              req->server_ip ? req->server_ip : "-",
              req->hdr_c ? req->hdr_c : "-",
              req->hdr_ne ? req->hdr_ne : "-",
              req->hdr_se ? req->hdr_se : "-");

    /* 详细错误缓冲：curl_easy_strerror 只给类别描述（如“Couldn't connect to
     * server”），无法区分具体原因（端口不可达 / 本地绑定失败 / 代理拒绝……），
     * 问题现场只能靠猜。ERRORBUFFER 会给出 libcurl 的原始描述（包含 errno 文本）。
     * 注：缓冲必须存活到 curl_easy_perform 返回之后，故放在本函数栈上；
     * 且需先置空——perform 成功时 libcurl 不会写入任何内容。 */
    char err_buf[CURL_ERROR_SIZE];
    err_buf[0] = '\0';
    PDNS_SETOPT(CURLOPT_ERRORBUFFER, err_buf);

    CURLcode rc = curl_easy_perform(curl);
    resp->curl_code = (int) rc;

    double total = 0.0;
    if (curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total) == CURLE_OK) {
        resp->rtt_ms = (long) (total * 1000.0);
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp->http_code);

    int result;
    if (rc == CURLE_OK) {
        resp->body     = buf.data;   /* 交接给 resp，由调用方释放 */
        resp->body_len = buf.size;
        result = 0;
    } else {
        PDNS_LOGW("http get failed: rid=%s url=%s err=%s (curl=%d%s%s)",
                  req->request_id ? req->request_id : "-", req->url,
                  curl_easy_strerror(rc), (int) rc,
                  err_buf[0] ? ", " : "", err_buf[0] ? err_buf : "");
        free(buf.data);
        result = 1;
    }

    /* ERRORBUFFER 指向本函数栈，handle 进连接池前必须解除，
     * 否则下次复用时 libcurl 会向已失效的栈帧写入。 */
    PDNS_SETOPT(CURLOPT_ERRORBUFFER, NULL);

    if (resolve_list != NULL) {
        curl_slist_free_all(resolve_list);
    }
    /* handle 来自连接池会被复用：重置自定义头，避免 c/ne/se 泄漏到下一次请求 */
    if (headers != NULL) {
        PDNS_SETOPT(CURLOPT_HTTPHEADER, NULL);
        curl_slist_free_all(headers);
    }
    /* 选项设置宏使命完成，及时撤销避免泄漏到其他函数 */
#undef PDNS_SETOPT

    pdns_session_release(curl);
    return result;
}

void pdns_http_response_free(pdns_http_response_t *resp) {
    if (resp == NULL) {
        return;
    }
    free(resp->body);
    resp->body     = NULL;
    resp->body_len = 0;
}
