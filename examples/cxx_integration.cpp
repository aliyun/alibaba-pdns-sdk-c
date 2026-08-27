/*
 * C++ / Qt 集成示例
 *
 * 前四个示例（sync / async / preload / keepalive）都止步于「打印 IP 列表」，
 * 本示例补上真正的落地环节：**拿到 IP 之后怎么用**。
 *
 * 演示内容：
 *   1. RAII 封装 —— 用析构函数保证 pdns_result_list_cleanup / client_cleanup / sdk_cleanup
 *      一定被调用，杜绝 C++ 早返回或抛异常导致的资源泄漏；
 *   2. IP 直连 + SNI 证书校验 —— libcurl CURLOPT_RESOLVE 把 "host:port:ip" 注入，
 *      TCP 连到 HTTPDNS 返回的 IP，而 TLS 握手与证书校验仍按【域名】进行；
 *   3. 多 IP failover —— 首个 IP 连不通时按顺序换下一个（解析结果已按测速排序，
 *      顺序即优先级）；
 *   4. 异步解析回调跨线程投递 —— 回调在 SDK 后台线程执行，示例演示如何安全地
 *      交回主线程处理（Qt 中对应 QMetaObject::invokeMethod / 信号槽）。
 *
 * 用法：cxx_integration [host]
 *
 * 提示：若解析成功但所有 IP 都连不上，先用
 *   curl --resolve <host>:443:<ip> https://<host>/
 * 对比同一 IP。HTTPDNS 会按服务端看到的出口位置调度到就近的运营商 CDN 节点，
 * 部分企业网络 / 安全软件会限制对这些网段的连接（表现为 connect 立即返回
 * EBADF，而同机 curl 命令行可访通）—— 这属环境限制，与 SDK 无关。
 * 此时可改用阿里云直属域名验证流程，例如：
 *   ./cxx_integration help.aliyun.com     (返回 HTTP 302)
 *   ./cxx_integration dns.alidns.com      (返回 HTTP 404)
 */
#include "pdns/pdns_api.h"

#include <curl/curl.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#define MOCK_HOST       "help.aliyun.com"
/* TODO 请替换鉴权参数
 * 鉴权参数（account_id / access_key_id / access_key_secret）从阿里云控制台获取，
 * 详见移动解析 HTTPDNS 产品文档。https://dnsnext.console.aliyun.com/pdnsDoh
 */
#define MOCK_ACCOUNT    "******"
#define MOCK_AK_ID      "******"
#define MOCK_AK_SECRET  "******"

/* ============================ 1. RAII 封装 ============================ */

/*
 * SDK 全局环境守卫：构造即 init，析构即 cleanup。
 * 必须比所有 client 存活得更久，故在 main 里最先声明。
 */
class PdnsSdkGuard {
public:
    PdnsSdkGuard() : ok_(pdns_sdk_init() == PDNS_OK) {}

    ~PdnsSdkGuard() {
        if (ok_) {
            pdns_sdk_cleanup();
        }
    }

    bool ok() const { return ok_; }

    /* 禁止拷贝：全局环境只能有一份 */
    PdnsSdkGuard(const PdnsSdkGuard &)            = delete;
    PdnsSdkGuard &operator=(const PdnsSdkGuard &) = delete;

private:
    bool ok_;
};

/* 客户端守卫：持有 pdns_client_t*，析构自动 cleanup。
 * 构造内分两步：先 create（只建实例），再 init_public_dns 配置鉴权——
 * 鉴权三参数必填，缺一即失败。 */
class PdnsClient {
public:
    PdnsClient(const char *account, const char *ak_id, const char *ak_secret)
        : client_(pdns_client_create()) {
        if (client_ == nullptr) {
            return;
        }
        pdns_status_t st = pdns_client_init_public_dns(client_, account, ak_id, ak_secret);
        if (!pdns_status_is_ok(&st)) {
            std::cerr << "[APP] pdns_client_init_public_dns failed: " << st.error_msg << std::endl;
            pdns_client_cleanup(client_);
            client_ = nullptr;
        }
    }

    ~PdnsClient() {
        if (client_ != nullptr) {
            pdns_client_cleanup(client_);
        }
    }

    pdns_client_t *get() const { return client_; }
    bool           valid() const { return client_ != nullptr; }

    PdnsClient(const PdnsClient &)            = delete;
    PdnsClient &operator=(const PdnsClient &) = delete;

private:
    pdns_client_t *client_;
};

/*
 * 解析结果守卫：pdns_result_list_t 是 C 侧堆内存，C++ 这边最容易忘记释放。
 * 用 RAII 包住，并提供 std::vector<std::string> 转换，后续按 C++ 习惯使用。
 */
class PdnsResults {
public:
    PdnsResults() : list_(nullptr) {}

    ~PdnsResults() { reset(); }

    void reset() {
        if (list_ != nullptr) {
            pdns_result_list_cleanup(list_);
            list_ = nullptr;
        }
    }

    /* 传给 SDK 的出参地址；调用前先释放上一次的结果 */
    pdns_result_list_t **out() {
        reset();
        return &list_;
    }

    pdns_result_list_t *get() const { return list_; }

    std::vector<std::string> toVector() const {
        std::vector<std::string> ips;
        size_t                   n = pdns_result_list_size(list_);
        ips.reserve(n);
        for (size_t i = 0; i < n; i++) {
            const char *ip = pdns_result_list_get(list_, i);
            if (ip != nullptr && ip[0] != '\0') {
                ips.emplace_back(ip);
            }
        }
        return ips;
    }

    PdnsResults(const PdnsResults &)            = delete;
    PdnsResults &operator=(const PdnsResults &) = delete;

private:
    pdns_result_list_t *list_;
};

/* ============================ 2. 日志接管 ============================ */

/*
 * 把 SDK 日志转接到 C++ 输出流。Qt 中改为 qDebug()/qWarning() 即可。
 * 注意：回调可能来自 SDK 后台线程，若转接到非线程安全的日志组件需自行加锁。
 */
static void cxx_logger(pdns_log_level_t level, const char *msg) {
    const char *tag = "D";
    switch (level) {
        case PDNS_LOG_LEVEL_ERROR: tag = "E"; break;
        case PDNS_LOG_LEVEL_WARN:  tag = "W"; break;
        case PDNS_LOG_LEVEL_INFO:  tag = "I"; break;
        case PDNS_LOG_LEVEL_DEBUG: tag = "D"; break;
    }
    std::cout << "[PDNS-" << tag << "] " << (msg ? msg : "") << std::endl;
}

/* ============================ 3. IP 直连访问业务 ============================ */

/* 响应体回调：示例只统计字节数，不保留内容 */
static size_t write_cb(void *buffer, size_t size, size_t nmemb, void *userdata) {
    (void) buffer;
    size_t real = size * nmemb;
    if (userdata != nullptr) {
        *static_cast<size_t *>(userdata) += real;
    }
    return real;
}

/*
 * 用指定 IP 直连访问业务域名。
 *
 * 关键点：URL 里仍写【域名】，通过 CURLOPT_RESOLVE 注入 "host:port:ip"，
 * 使 libcurl 跳过系统 DNS 直接连该 IP，同时 SNI 与证书校验依旧基于域名 ——
 * 这是 HTTPDNS 落地的标准做法，绝不能改成 "https://<ip>/" 再关掉证书校验。
 *
 * @return HTTP 状态码；连接失败返回 0。
 */
static long access_business_by_ip(const std::string &host, const std::string &ip, bool use_https) {
    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        return 0;
    }

    const int   port = use_https ? 443 : 80;
    std::string url  = (use_https ? "https://" : "http://") + host + "/";

    /* "host:port:ip" —— IPv6 需用方括号包裹，与 SDK 内部 pdns_http.c 的处理一致 */
    std::string entry = host + ":" + std::to_string(port) + ":";
    entry += (ip.find(':') != std::string::npos) ? ("[" + ip + "]") : ip;

    struct curl_slist *resolve_list = curl_slist_append(nullptr, entry.c_str());
    size_t             body_bytes   = 0;
    long               http_code    = 0;
    char               errbuf[CURL_ERROR_SIZE];
    errbuf[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body_bytes);
    /* 证书校验保持开启（默认值），SNI 与 CN/SAN 均按 URL 中的域名匹配 */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
#if defined(_WIN32)
    /* Windows 使用系统证书库，避免额外部署 CA bundle */
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        std::cout << "  [OK] " << ip << " -> HTTP " << http_code
                  << ", " << body_bytes << " bytes" << std::endl;
    } else {
        std::cerr << "  [FAIL] " << ip << " (" << entry << ") -> "
                  << curl_easy_strerror(rc)
                  << (errbuf[0] != '\0' ? std::string(": ") + errbuf : "") << std::endl;
    }

    curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);
    return http_code;
}

/*
 * 多 IP failover：解析结果已按测速 RTT 排序，顺序即优先级，
 * 逐个尝试直到某个 IP 成功。生产代码应把成功的 IP 缓存起来优先复用。
 */
static bool access_with_failover(const std::string &host, const std::vector<std::string> &ips) {
    for (const std::string &ip : ips) {
        if (access_business_by_ip(host, ip, true) > 0) {
            return true;
        }
    }
    return false;
}

/* ============================ 4. 异步回调跨线程投递 ============================ */

/*
 * 异步解析结果的线程间传递。
 *
 * SDK 回调在自己的后台线程执行，**不能在回调里直接操作 UI 控件**，也不应做耗时操作。
 * 这里用 mutex + condition_variable 把结果交回主线程；
 * Qt 中的等价做法是在回调里 QMetaObject::invokeMethod(obj, ..., Qt::QueuedConnection)
 * 或 emit 信号（跨线程连接默认走 QueuedConnection），由 UI 线程的事件循环处理。
 */
struct AsyncBridge {
    std::mutex               mtx;
    std::condition_variable  cv;
    bool                     done = false;
    std::string              host;
    std::vector<std::string> ips;
};

static void async_cb(const char *host, pdns_query_type_t query_type,
                     pdns_result_list_t *results, void *user_data) {
    (void) query_type;
    AsyncBridge *bridge = static_cast<AsyncBridge *>(user_data);
    if (bridge == nullptr) {
        return;
    }

    /* 回调返回后 SDK 会释放 results，需要保留的内容必须在此拷贝 */
    std::vector<std::string> ips;
    size_t                   n = pdns_result_list_size(results);
    ips.reserve(n);
    for (size_t i = 0; i < n; i++) {
        const char *ip = pdns_result_list_get(results, i);
        if (ip != nullptr) {
            ips.emplace_back(ip);
        }
    }

    {
        std::lock_guard<std::mutex> lock(bridge->mtx);
        bridge->host = (host != nullptr) ? host : "";
        bridge->ips  = std::move(ips);
        bridge->done = true;
    }
    bridge->cv.notify_one();
}

/* ============================ main ============================ */

int main(int argc, char **argv) {
    const std::string host = (argc > 1) ? argv[1] : MOCK_HOST;

    /* 打开日志并接管输出（生产集成路径） */
    pdns_log_set_enable(true);
    pdns_log_set_level(PDNS_LOG_LEVEL_DEBUG);
    pdns_log_set_logger(cxx_logger);

    /* 1. SDK 环境（RAII，最先声明、最后销毁） */
    PdnsSdkGuard sdk;
    if (!sdk.ok()) {
        std::cerr << "[APP] pdns_sdk_init failed" << std::endl;
        return 1;
    }

    /* 2. 创建并配置客户端（构造内部：create + init_public_dns） */
    PdnsClient client(MOCK_ACCOUNT, MOCK_AK_ID, MOCK_AK_SECRET);
    if (!client.valid()) {
        std::cerr << "[APP] create/init pdns client failed" << std::endl;
        return 1;
    }
    pdns_client_set_timeout(client.get(), 3000);
    pdns_client_set_enable_cache(client.get(), true);
    pdns_client_set_schema_type(client.get(), PDNS_SCHEMA_HTTPS);
    /* 开启业务 IP 测速排序：返回列表按 RTT 升序，首个即最优 */
    pdns_client_set_enable_speed_test(client.get(), true);
    pdns_client_set_speed_port(client.get(), 443);

    /* 3. 启动（拉取服务节点列表与黑白名单配置） */
    pdns_status_t st = pdns_client_start(client.get());
    if (!pdns_status_is_ok(&st)) {
        std::cerr << "[APP] client start failed: " << st.error_msg << std::endl;
        return 1;
    }

    /* ---------------- 同步解析 + IP 直连访问 ---------------- */

    std::cout << "\n[APP] === [1] sync resolve + direct-ip access ===" << std::endl;

    PdnsResults results;
    st = pdns_resolve_sync(client.get(), host.c_str(), PDNS_QUERY_AUTO, results.out());
    if (!pdns_status_is_ok(&st)) {
        std::cerr << "[APP] resolve failed: code=" << st.code
                  << " error_code=" << st.error_code
                  << " msg=" << st.error_msg << std::endl;
        return 1;
    }

    std::vector<std::string> ips = results.toVector();
    if (ips.empty()) {
        /* 空结果的两种正常情形：黑白名单拦截、否定响应（NXDOMAIN/NODATA） */
        if (std::strcmp(st.error_code, "ACL_REJECTED") == 0) {
            std::cout << "[APP] host=" << host << " rejected by ACL, nothing to access" << std::endl;
        } else {
            std::cout << "[APP] host=" << host << " resolved to empty (negative response)" << std::endl;
        }
        return 0;
    }

    std::cout << "[APP] resolved " << ips.size() << " ip(s), requestId=" << st.request_id << std::endl;
    for (size_t i = 0; i < ips.size(); i++) {
        std::cout << "  [" << i << "] " << ips[i] << std::endl;
    }

    /* 打印解析结果来源（按地址族区分；命中缓存时另标注 from_cache） */
    {
        pdns_source_t src4 = pdns_result_list_get_source(results.get(), PDNS_QUERY_IPV4);
        pdns_source_t src6 = pdns_result_list_get_source(results.get(), PDNS_QUERY_IPV6);
        if (src4 != PDNS_SOURCE_UNKNOWN) {
            std::cout << "  source(v4): " << pdns_source_name(src4)
                      << (pdns_result_list_is_from_cache(results.get(), PDNS_QUERY_IPV4)
                              ? " (from cache)" : "")
                      << std::endl;
        }
        if (src6 != PDNS_SOURCE_UNKNOWN) {
            std::cout << "  source(v6): " << pdns_source_name(src6)
                      << (pdns_result_list_is_from_cache(results.get(), PDNS_QUERY_IPV6)
                              ? " (from cache)" : "")
                      << std::endl;
        }
    }

    /* 也可用 SDK 提供的选择接口（按 query_type 过滤地址族） */
    char best[PDNS_IP_ADDRESS_STRING_LENGTH] = {0};
    if (pdns_select_ip_first(results.get(), PDNS_QUERY_AUTO, best) == PDNS_OK) {
        std::cout << "[APP] best ip (by speed test): " << best << std::endl;
    }

    std::cout << "[APP] accessing https://" << host << "/ via resolved ip ..." << std::endl;
    if (!access_with_failover(host, ips)) {
        /*
         * 全部 IP 均失败时的排查方向：解析已成功（上方已打印 IP），说明问题
         * 不在 HTTPDNS，而在后续的业务连接环节。常见原因：
         *   - 本机安全软件 / EDR 拦截未签名程序的出站连接（表现为 connect 立即
         *     返回 EBADF “Bad file descriptor”，而同机 curl 命令行却能访通）；
         *   - 企业网络限制目标 IP，或该 CDN 节点对当前出口不可达；
         *   - 目标域名不支持 IP 直连（未在该 IP 上配置对应的证书 / 主机头）。
         * 验证方法：curl --resolve <host>:443:<ip> https://<host>/ 对比同一 IP 的连通性。
         */
        std::cerr << "[APP] all ips failed --- 解析已成功，失败发生在业务连接阶段。\n"
                     "  常见原因：HTTPDNS 调度到的运营商 CDN 网段在当前网络不可达。\n"
                     "  可改用阿里云直属域名验证：./cxx_integration help.aliyun.com" << std::endl;
    }

    /* ---------------- 异步解析 + 回调跨线程投递 ---------------- */

    std::cout << "\n[APP] === [2] async resolve + cross-thread callback ===" << std::endl;

    AsyncBridge bridge;
    st = pdns_resolve_async(client.get(), host.c_str(), PDNS_QUERY_IPV4,
                                        async_cb, &bridge);
    if (!pdns_status_is_ok(&st)) {
        std::cerr << "[APP] async submit failed: " << st.error_msg << std::endl;
        return 1;
    }

    /* 主线程等待后台回调（GUI 程序中不要这样阻塞，应交由事件循环驱动） */
    {
        std::unique_lock<std::mutex> lock(bridge.mtx);
        if (!bridge.cv.wait_for(lock, std::chrono::seconds(10), [&] { return bridge.done; })) {
            std::cerr << "[APP] async resolve timed out" << std::endl;
            return 1;
        }
    }
    std::cout << "[APP] async callback: host=" << bridge.host
              << ", " << bridge.ips.size() << " ip(s)" << std::endl;
    for (const std::string &ip : bridge.ips) {
        std::cout << "  - " << ip << std::endl;
    }

    /* 4. 资源释放全部由 RAII 完成：results → client → sdk（声明逆序） */
    std::cout << "\n[APP] OK, Exit." << std::endl;
    return 0;
}
