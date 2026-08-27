/*
 * 阿里云 移动解析HTTPDNS C SDK —— 对外唯一头文件
 *
 * 说明：
 *  - 所有对外 API 使用 pdns_ 前缀，宏/枚举使用 PDNS_ 前缀。
 *  - 头文件使用 extern "C" 包裹，保证 C++（如 Qt）可正确调用。
 *  - 详细设计见仓库根目录 DESIGN.md。
 */
#ifndef PDNS_API_H
#define PDNS_API_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* ---------- 符号导出控制 ---------- */
#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(PDNS_BUILDING_SHARED)
#    define PDNS_API __declspec(dllexport)
#  elif defined(PDNS_USING_SHARED)
#    define PDNS_API __declspec(dllimport)
#  else
#    define PDNS_API
#  endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#  define PDNS_API __attribute__((visibility("default")))
#else
#  define PDNS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ============================ 常量 ============================ */

/*
 * SDK 版本号（唯一定义处）。
 *   - 编译期：集成方可用本宏做条件编译 / 版本断言 / 拼接自定义 UA。
 *   - 与 pdns_version() 配套：宏反映「编译时头文件的版本」，
 *     函数反映「运行时实际链接进库的版本」，两者不一致即说明
 *     头文件与静态库版本不匹配（排障关键线索）。
 * 全项目仅此一处字面量，内部 PDNS_SDK_VERSION 亦指向本宏。
 */
#define PDNS_VERSION                 "1.0.0"

#define PDNS_OK                          0     /* 操作成功 */
#define PDNS_ERROR_CODE_LEN              64     /* error_code 缓冲长度 */
#define PDNS_ERROR_MSG_LEN              256     /* error_msg 缓冲长度 */
#define PDNS_IP_ADDRESS_STRING_LENGTH   64     /* IP 字符串缓冲长度（含 IPv6） */
#define PDNS_REQUEST_ID_LEN             48     /* 请求追踪 ID 缓冲长度（{platform}_{16hex}_{16hex}） */

/* ============================ 状态 ============================ */

/*
 * 操作状态。code 为 0（PDNS_OK）表示成功，否则表示失败，
 * error_code / error_msg 携带错误信息；request_id 用于追踪本次解析链路。
 */
typedef struct {
    int  code;
    char error_code[PDNS_ERROR_CODE_LEN];
    char error_msg[PDNS_ERROR_MSG_LEN];
    char request_id[PDNS_REQUEST_ID_LEN];
} pdns_status_t;

/*
 * 判断状态是否成功。
 * @param[in]  status  待判断的状态
 * @return true 表示成功（code == PDNS_OK）；status 为 NULL 时返回 false。
 */
PDNS_API bool pdns_status_is_ok(const pdns_status_t *status);

/*
 * 返回运行期实际编译进库的 SDK 版本字符串（即 PDNS_VERSION 的值）。
 * 用途：日志 / 数据上报 / 关于页展示；亦可与编译期宏 PDNS_VERSION
 * 比对，验证「头文件版本 == 静态库版本」。
 * @return 以 '\0' 结尾的静态字符串，调用方不得释放。
 */
PDNS_API const char *pdns_version(void);

/* ============================ 查询类型 ============================ */

typedef enum {
    PDNS_QUERY_AUTO = 0,   /* 根据网络栈自动解析 */
    PDNS_QUERY_IPV4,       /* 仅 IPv4（A 记录） */
    PDNS_QUERY_IPV6,       /* 仅 IPv6（AAAA 记录） */
    PDNS_QUERY_BOTH        /* 同时解析 IPv4 和 IPv6 */
} pdns_query_type_t;

/* ============================ 请求协议 ============================ */

typedef enum {
    PDNS_SCHEMA_HTTP = 0,   /* HTTP */
    PDNS_SCHEMA_HTTPS       /* HTTPS（默认） */
} pdns_schema_type_t;

/* ============================ 解析结果来源 ============================ */

/*
 * 解析结果的来源。
 *
 * UNKNOWN 必须为 0：结果列表零初始化时落在「未知」这一安全侧，
 * 避免未填充的字段被误读为某个具体来源。
 */
typedef enum {
    PDNS_SOURCE_UNKNOWN = 0,   /* 未知：该地址族本次无结果，或未经解析 */
    PDNS_SOURCE_PUBLIC_DNS,    /* 阿里云公共 DNS */
    PDNS_SOURCE_FUSION_DNS,    /* 自建 DNS */
    PDNS_SOURCE_LOCAL_DNS      /* LocalDNS（系统 DNS 兜底） */
} pdns_source_t;

/*
 * 来源名称（日志 / 展示用）。
 * @param[in]  source  来源枚举
 * @return 只读字符串字面量，如 "PublicDNS"；未知值返回 "Unknown"。
 */
PDNS_API const char *pdns_source_name(pdns_source_t source);

/* ============================ 不透明类型 ============================ */

/* 客户端实例（线程安全，可多线程共享） */
typedef struct pdns_client_s pdns_client_t;

/* 域名列表（入参）：由使用方构造，用于批量预解析 / 保活域名等接口 */
typedef struct pdns_domain_list_s pdns_domain_list_t;

/*
 * 解析结果列表（出参）：由 SDK 构造并返回，使用方只读 + 负责释放。
 *
 * 与 pdns_domain_list_t 分为两个类型是有意为之：
 *   - 结果列表不提供 create / add，使用方无法篡改 SDK 的输出（否则插入的
 *     地址会没有对应的来源信息，与元信息不一致）；
 *   - 结果列表额外携带来源元信息，而入参的域名列表上这类字段毫无意义。
 */
typedef struct pdns_result_list_s pdns_result_list_t;

/* ============================ 域名列表（入参） ============================ */

/*
 * 创建域名列表。
 * @return 成功返回实例（需通过 pdns_domain_list_cleanup 释放），失败返回 NULL。
 */
PDNS_API pdns_domain_list_t *pdns_domain_list_create(void);

/*
 * 向域名列表追加一个域名（内部拷贝，调用后 domain 可释放）。
 * @param[in]  list    目标列表
 * @param[in]  domain  待添加的域名
 * @return 操作状态，code 为 0 表示成功。
 */
PDNS_API pdns_status_t pdns_domain_list_add(pdns_domain_list_t *list, const char *domain);

/*
 * 域名个数。
 * @param[in]  list  待查询的列表
 * @return 个数；list 为 NULL 时返回 0。
 */
PDNS_API size_t pdns_domain_list_size(const pdns_domain_list_t *list);

/*
 * 获取第 index 个域名。
 * @param[in]  list   待查询的列表
 * @param[in]  index  下标（从 0 开始）
 * @return 只读字符串，生命周期随列表；越界或 list 为 NULL 时返回 NULL。
 */
PDNS_API const char *pdns_domain_list_get(const pdns_domain_list_t *list, size_t index);

/*
 * 释放域名列表。
 * @param[in]  list  待释放的列表（可为 NULL）
 */
PDNS_API void pdns_domain_list_cleanup(pdns_domain_list_t *list);

/* ============================ 解析结果列表（出参） ============================ */

/*
 * 结果中的 IP 个数。
 * @param[in]  results  解析结果
 * @return 个数；results 为 NULL 时返回 0。
 */
PDNS_API size_t pdns_result_list_size(const pdns_result_list_t *results);

/*
 * 获取第 index 个 IP。
 * @param[in]  results  解析结果
 * @param[in]  index    下标（从 0 开始）
 * @return 只读字符串，生命周期随列表；越界或 results 为 NULL 时返回 NULL。
 */
PDNS_API const char *pdns_result_list_get(const pdns_result_list_t *results, size_t index);

/*
 * 释放解析结果列表。
 * @param[in]  results  待释放的结果（可为 NULL）
 */
PDNS_API void pdns_result_list_cleanup(pdns_result_list_t *results);

/*
 * 查询本次结果中指定地址族的来源。
 *
 * 按地址族（而非按单个 IP）组织是无损的：同一地址族的全部 IP 必然来自同一次
 * 解析（缓存条目按地址族分键，一次网络解析的结果也全部来自同一个来源），
 * 故不会出现同族内来源不同的情况。
 *
 * 注：BOTH 查询开启测速时，返回列表中的 v4 / v6 可能是混排的。若需定位某个
 * 具体 IP 的来源，请先判断该 IP 属于哪个地址族（含 ':' 即 IPv6），再查对应族。
 *
 * @param[in]  results  解析结果
 * @param[in]  family   地址族：PDNS_QUERY_IPV4 / PDNS_QUERY_IPV6 查对应族；
 *                      传 AUTO / BOTH 时返回「有结果的那一族」（两族都有则取 IPv4）。
 *                      单类型查询只有对应族有值，另一族恒为 UNKNOWN。
 * @return 来源枚举；results 为 NULL 或该族无结果时返回 PDNS_SOURCE_UNKNOWN。
 */
PDNS_API pdns_source_t pdns_result_list_get_source(const pdns_result_list_t *results,
                                          pdns_query_type_t family);

/*
 * 查询指定地址族的结果是否直接取自缓存（本次未发起网络请求）。
 *
 * 与 pdns_result_list_get_source 配合使用：source 回答「这批 IP 最初是谁解析的」，
 * 本函数回答「本次是否走了网络」。缓存命中时 source 仍为当初写入缓存的真实来源
 * （PublicDNS / FusionDNS / LocalDNS），而不是笼统的「Cache」——否则无法得知缓存里
 * 这批地址到底是 HTTPDNS 还是 LocalDNS 兜底来的。
 *
 * @param[in]  results  解析结果
 * @param[in]  family   地址族，语义同 pdns_result_list_get_source
 * @return true 表示取自缓存；results 为 NULL 或该族无结果时返回 false。
 */
PDNS_API bool pdns_result_list_is_from_cache(const pdns_result_list_t *results,
                                    pdns_query_type_t family);

/* ============================ SDK 生命周期 ============================ */

/*
 * SDK 环境初始化（全局随机数、网络检测、线程池、依赖库初始化等）。
 * @return PDNS_OK 成功；非 0 失败。
 * @note  调用后务必配对调用一次 pdns_sdk_cleanup；该接口非线程安全。
 */
PDNS_API int pdns_sdk_init(void);

/* 释放 SDK 环境资源 */
PDNS_API void pdns_sdk_cleanup(void);

/*
 * 创建客户端实例（只建实例与基础设施，不含任何 DNS 服务配置）。
 *
 * 创建后须至少成功调用 pdns_client_init_public_dns 或
 * pdns_client_init_fusion_dns 之一，否则 pdns_client_start 返回错误。
 * @return 成功返回实例指针，失败返回 NULL。
 */
PDNS_API pdns_client_t *pdns_client_create(void);

/*
 * 配置公共 DNS 鉴权参数。须在 pdns_client_start 之前调用。
 *
 * 三个参数均为必填，任一为空即返回错误且不启用公共 DNS
 * （鉴权三者须全非空，否则该 Provider 不参与调度）。
 * 可重复调用以更新鉴权参数。
 * @param[in]  client             客户端实例
 * @param[in]  account_id         账户 ID
 * @param[in]  access_key_id      访问密钥 ID
 * @param[in]  access_key_secret  访问密钥（仅参与 SHA-256 签名，不在 URL 中传输）
 * @return 操作状态，code 为 0 表示成功。
 */
PDNS_API pdns_status_t pdns_client_init_public_dns(pdns_client_t *client,
                                          const char *account_id,
                                          const char *access_key_id,
                                          const char *access_key_secret);

/*
 * 配置自建 DNS。须在 pdns_client_start 之前调用。
 *
 * 自建的服务节点完全由集成方提供（SDK 无内置默认节点，也不从服务端拉取优选
 * 列表），且持有独立于公共 DNS 的鉴权密钥。以下校验任一不满足即返回错误，
 * 且不改动已有配置（不会产生“半配置”状态）：
 *   - 三个地址数组至少有一个非空
 *   - health_check_domain 必填（熔断后用于探测节点是否恢复）
 *   - access_key_id / access_key_secret 必填
 *
 * 注：与公共 DNS 不同，本接口**不需要 account_id**——自建服务部署在集成方侧，
 * 不按阿里云账号维度区分调用方，uid 由 SDK 内部置为固定值。
 *
 * 与 pdns_client_init_public_dns 的调用顺序决定主备关系（先配者为主用）：
 *   仅调 public                     → 单公共
 *   仅调 fusion                     → 单自建
 *   先 public 再 fusion             → 公共主用，自建备用（默认降级阈值 4）
 *   先 fusion 再 public             → 自建主用，公共备用（默认降级阈值 2）
 *
 * @param[in]  client              客户端实例
 * @param[in]  server_ipv4_arr     IPv4 节点数组，可为 NULL
 * @param[in]  v4_count            IPv4 节点个数
 * @param[in]  server_ipv6_arr     IPv6 节点数组（不带方括号），可为 NULL
 * @param[in]  v6_count            IPv6 节点个数
 * @param[in]  server_host_arr     域名节点数组，可为 NULL
 * @param[in]  host_count          域名节点个数
 * @param[in]  port                服务端口；<=0 时取默认 443
 * @param[in]  health_check_domain 熔断恢复探测域名（必填）
 * @param[in]  access_key_id       访问密钥 ID
 * @param[in]  access_key_secret   访问密钥
 * @return 操作状态，code 为 0 表示成功。
 */
PDNS_API pdns_status_t pdns_client_init_fusion_dns(pdns_client_t *client,
                                          const char *const *server_ipv4_arr, int v4_count,
                                          const char *const *server_ipv6_arr, int v6_count,
                                          const char *const *server_host_arr, int host_count,
                                          int         port,
                                          const char *health_check_domain,
                                          const char *access_key_id,
                                          const char *access_key_secret);

/*
 * 是否校验自建服务端证书，默认 true。
 *
 * 仅影响自建 DNS（公共 DNS 恒校验，无开关）。仅供自签证书的私有化部署
 * 在测试环境下关闭；生产环境不得关闭，否则失去中间人防护。
 * @param[in]  client  客户端实例
 * @param[in]  enable  true 校验，false 不校验
 */
PDNS_API void pdns_client_set_fusion_certificate_validation(pdns_client_t *client, bool enable);

/*
 * 设置主用 provider 的失败降级阈值。
 *
 * 仅在公共与自建都已配置（互为兜底）时生效：单次解析中主用累计失败达到
 * 该次数后，剩下的重试切到备用 provider。取值范围 [0, 4]，越界自动夹紧；
 * 0 表示不给主用机会，直接用备用。
 * 不调用时取默认值：公共主用=4，自建主用=2。
 * 注：需在两个 init 之后调用——init 会重建 provider 主备关系并重置为默认阈值。
 * @param[in]  client              客户端实例
 * @param[in]  fallback_threshold  降级阈值
 */
PDNS_API void pdns_client_set_fallback_threshold(pdns_client_t *client, int32_t fallback_threshold);

/*
 * 启动客户端（预解析、拉取服务列表等）。
 * @param[in]  client  客户端实例
 * @return 操作状态，code 为 0 表示成功；未配置任何 DNS 服务时返回错误。
 */
PDNS_API pdns_status_t pdns_client_start(pdns_client_t *client);

/*
 * 释放客户端实例。
 * @param[in]  client  待释放的客户端实例（可为 NULL）
 */
PDNS_API void pdns_client_cleanup(pdns_client_t *client);

/* ============================ 配置接口 ============================ */

/*
 * 设置解析服务端超时时间，单位毫秒，建议 2000~5000，默认 3000。
 * 小于等于 0 回退为默认值 3000，超过 60000 夹紧到 60000。
 * @param[in]  client      客户端实例
 * @param[in]  timeout_ms  超时时间（毫秒）
 */
PDNS_API void pdns_client_set_timeout(pdns_client_t *client, int32_t timeout_ms);

/*
 * 是否启用本地缓存，默认 true。
 * @param[in]  client        客户端实例
 * @param[in]  enable_cache  true 启用，false 关闭
 */
PDNS_API void pdns_client_set_enable_cache(pdns_client_t *client, bool enable_cache);

/*
 * 设置与 HTTPDNS 服务端通信的协议（HTTP / HTTPS），默认 PDNS_SCHEMA_HTTPS。
 * @param[in]  client  客户端实例
 * @param[in]  schema  协议类型
 */
PDNS_API void pdns_client_set_schema_type(pdns_client_t *client, pdns_schema_type_t schema);

/*
 * 是否启用 IP 测速排序（基于 TCP 连接 RTT），默认 true。
 * @param[in]  client  客户端实例
 * @param[in]  enable  true 启用，false 关闭
 */
PDNS_API void pdns_client_set_enable_speed_test(pdns_client_t *client, bool enable);

/*
 * 设置测速使用的目标端口，默认 80。钳制到 [0, 65535] 越界夹紧
 * （无效端口仅导致测速失败，不影响解析）。
 * @param[in]  client      客户端实例
 * @param[in]  speed_port  测速目标端口
 */
PDNS_API void pdns_client_set_speed_port(pdns_client_t *client, int32_t speed_port);

/*
 * 设置 IPv6 测速让分（毫秒）。在测速开启的 v4/v6 双栈混排中，
 * IPv6 的有效 RTT 会减去该值，使 v6 与 v4 测速相差不超过该值时优先选 v6。
 * 默认 0（关闭，纯 RTT 排序），有效范围 [0,1000] 越界裁剪，仅测速开启时生效。
 * @param[in]  client  客户端实例
 * @param[in]  ms      让分毫秒数
 */
PDNS_API void pdns_client_set_speed_test_ipv6_prefer_ms(pdns_client_t *client, int32_t ms);

/*
 * HTTPDNS 解析失败时是否降级到系统 LocalDNS，默认 true。
 * @param[in]  client  客户端实例
 * @param[in]  enable  true 启用，false 关闭
 */
PDNS_API void pdns_client_set_enable_localdns(pdns_client_t *client, bool enable);

/*
 * 双栈环境下首次请求是否优先使用 IPv6 服务地址发起解析，默认 false。
 * @param[in]  client  客户端实例
 * @param[in]  enable  true 启用，false 关闭
 */
PDNS_API void pdns_client_set_enable_ipv6(pdns_client_t *client, bool enable);

/*
 * 是否启用不可变缓存（缓存永不过期），默认 false。
 * @param[in]  client  客户端实例
 * @param[in]  enable  true 启用，false 关闭
 */
PDNS_API void pdns_client_set_enable_immutable_cache(pdns_client_t *client, bool enable);

/*
 * 设置 EDNS Client Subnet（ECS），用于精准调度。
 * @param[in]  client  客户端实例
 * @param[in]  ecs     ECS 字符串；传 NULL 清除
 */
PDNS_API void pdns_client_set_edns_client_subnet(pdns_client_t *client, const char *ecs);

/*
 * 设置缓存 TTL 上限（秒），服务端返回 TTL 超过此值将被截断，默认 3600。
 * @param[in]  client   客户端实例
 * @param[in]  seconds  TTL 上限（秒）
 */
PDNS_API void pdns_client_set_max_ttl_cache(pdns_client_t *client, int32_t seconds);

/*
 * 设置缓存 TTL 下限（秒），服务端返回 TTL 低于此值将被抬高，默认 60。
 * @param[in]  client   客户端实例
 * @param[in]  seconds  TTL 下限（秒），上限 300
 */
PDNS_API void pdns_client_set_min_ttl_cache(pdns_client_t *client, int32_t seconds);

/*
 * 设置否定缓存（解析失败）的最大 TTL（秒），默认 30。
 * 负数归 0，最大值不钳制；0 表示关闭否定缓存。
 * @param[in]  client   客户端实例
 * @param[in]  seconds  否定缓存最大 TTL（秒）
 */
PDNS_API void pdns_client_set_max_negative_cache(pdns_client_t *client, int32_t seconds);

/*
 * 设置缓存条目最大数量，默认 100。
 * @param[in]  client    客户端实例
 * @param[in]  max_size  最大条目数；负数按 0 处理；0 表示清空缓存且不再写入
 */
PDNS_API void pdns_client_set_max_cache_size(pdns_client_t *client, int32_t max_size);

/*
 * 设置异步解析同时在飞的最大并发数。
 * 取值范围 [1, 50]，越界自动夹紧；默认 10，推荐范围 [5, 30]。
 * 可在 pdns_client_start 前后调用，运行期修改对后续任务立即生效。
 * 注：
 *   - 同步解析在调用者线程执行，不占用此并发额度；
 *   - 本项仅约束解析任务。SDK 内部后台任务（IP 测速 / 黑白名单拉取 /
 *     服务节点拉取 / 保活刷新）跑在独立的辅助线程池，不受本项影响，
 *     也不会与解析互相阻塞。
 * @param[in]  client  客户端实例
 * @param[in]  count   最大并发数
 */
PDNS_API void pdns_client_set_max_concurrent_resolve_count(pdns_client_t *client, int32_t count);

/*
 * 是否启用网络切换感知（后台轮询检测网络变化并刷新），默认 true。
 * 网络栈为宿主机级属性，故本开关为进程全局配置，
 * 对所有 client 生效。运行期可随时调用，立即开关后台轮询线程。
 * @param[in]  enable  true 启用，false 关闭
 */
PDNS_API void pdns_set_enable_network_change(bool enable);

/*
 * 是否启用 short 模式，默认 false。
 * 启用后请求追加 &short=1，服务端返回纯 IP 数组（["1.2.3.4",...]）而非完整
 * Answer 结构；此模式下无服务端 TTL（统一使用 min_ttl_cache）且不支持否定缓存。
 * @param[in]  client  客户端实例
 * @param[in]  enable  true 启用，false 关闭
 */
PDNS_API void pdns_client_set_enable_short(pdns_client_t *client, bool enable);

/*
 * 是否启用 HTTP/2 传输，默认 true。
 * 启用后解析请求通过 TLS ALPN 协商优先走 HTTP/2，服务端或 libcurl 不支持时
 * 自动回落 HTTP/1.1（不会导致请求失败）。
 * 编译期约束：仅当编译环境的 libcurl 头文件提供 HTTP/2 相关宏（≥7.43.0）时
 * 本开关才生效；旧版本 libcurl（如 CentOS 7 自带 7.29.0）编译时该选项不参与
 * 编译，默认走 HTTP/1.1，不影响构建与运行。
 * @param[in]  client  客户端实例
 * @param[in]  enable  true 启用，false 关闭
 */
PDNS_API void pdns_client_set_enable_http2(pdns_client_t *client, bool enable);

/*
 * 获取会话 ID：12 位 A-Za-z0-9 随机串，
 * client 创建时生成一次、生命周期内不变，随每次解析请求以 &did= 上报，
 * 用于服务端日志聚合分析；多 client 实例各自独立。
 * @param[in]  client  客户端实例
 * @return 只读字符串，生命周期随 client；client 为 NULL 时返回 NULL。
 */
PDNS_API const char *pdns_client_get_session_id(pdns_client_t *client);

/* ============================ 解析接口 ============================ */

/*
 * 从缓存中获取该域名解析，同步返回 + 后台异步刷新。
 * 缓存缺失：先返回空，再异步请求并写入缓存。
 * 缓存过期：is_allow_exp=true 返回过期数据并异步刷新；false 返回空并异步刷新。
 * @param[in]   client        客户端实例
 * @param[in]   host          待解析域名
 * @param[in]   query_type    解析类型（AUTO / IPV4 / IPV6 / BOTH）
 * @param[in]   is_allow_exp  是否允许返回过期缓存数据
 * @param[out]  results       解析结果，需通过 pdns_result_list_cleanup 释放
 * @return 操作状态，code 为 0 表示成功。
 */
PDNS_API pdns_status_t pdns_resolve_sync_from_cache(pdns_client_t *client,
                                                       const char *host,
                                                       pdns_query_type_t query_type,
                                                       bool is_allow_exp,
                                                       pdns_result_list_t **results);

/*
 * 域名同步解析（阻塞）。先查缓存，命中直接返回；未命中或过期则查询
 * HTTPDNS 服务器，直到有结果或超时。
 * @param[in]   client      客户端实例
 * @param[in]   host        待解析域名
 * @param[in]   query_type  解析类型（AUTO / IPV4 / IPV6 / BOTH）
 * @param[out]  results     解析结果，需通过 pdns_result_list_cleanup 释放
 * @return 操作状态，code 为 0 表示成功。
 */
PDNS_API pdns_status_t pdns_resolve_sync(pdns_client_t *client,
                                            const char *host,
                                            pdns_query_type_t query_type,
                                            pdns_result_list_t **results);

/*
 * 异步解析完成回调。
 * @param[in]  host        本次解析的域名
 * @param[in]  query_type  本次解析类型
 * @param[in]  results     解析结果（可能为空）；由 SDK 在回调返回后释放，
 *                         如需保留请在回调内自行拷贝
 * @param[in]  user_data   发起请求时传入的透传指针
 * @note 回调在 SDK 后台线程执行，回调内不要执行耗时阻塞操作。
 */
typedef void (*pdns_resolve_callback_fn)(const char *host,
                                         pdns_query_type_t query_type,
                                         pdns_result_list_t *results,
                                         void *user_data);

/*
 * 域名异步解析（非阻塞）。立即返回，解析完成后在后台线程回调。
 * 先查缓存，未命中/过期则回源 HTTPDNS，结果写入缓存后回调。
 * @param[in]  client      客户端实例
 * @param[in]  host        待解析域名
 * @param[in]  query_type  解析类型（AUTO / IPV4 / IPV6 / BOTH）
 * @param[in]  callback    解析结束后的回调函数，可为 NULL（仅后台刷新缓存）
 * @param[in]  user_data   回调函数的用户自定义参数，SDK 原样透传不解析，
 *                         需保证存活到回调执行完成；可为 NULL
 * @return 任务提交状态（非解析结果）；code=0 表示已成功入队。
 */
PDNS_API pdns_status_t pdns_resolve_async(pdns_client_t *client,
                                             const char *host,
                                             pdns_query_type_t query_type,
                                             pdns_resolve_callback_fn callback,
                                             void *user_data);

/* ============================ 预解析 / 保活 ============================ */

/*
 * 批量预解析域名。
 * @param[in]  client      客户端实例
 * @param[in]  query_type  解析类型（AUTO / IPV4 / IPV6 / BOTH）
 * @param[in]  domains     待预解析的域名列表（内部拷贝，调用后可释放）
 */
PDNS_API void pdns_client_add_pre_load_domains(pdns_client_t *client,
                                      pdns_query_type_t query_type,
                                      pdns_domain_list_t *domains);

/*
 * 设置保活域名（TTL×75% 自动刷新）。
 * @param[in]  client   客户端实例
 * @param[in]  domains  保活域名列表（内部拷贝，调用后可释放）
 */
PDNS_API void pdns_client_set_keep_alive_domains(pdns_client_t *client,
                                        pdns_domain_list_t *domains);

/* ============================ 网络切换感知 ============================ */

/*
 * 手动通知 SDK 网络已发生变化（供集成方监听到系统网络事件时调用）。
 * 内部会重探网络栈并在确认变化时重置服务节点测速。
 * 若已启用网络切换感知，SDK 也会后台轮询自动检测。
 * 检测器为进程全局单例，本接口对所有 client 生效。
 */
PDNS_API void pdns_on_network_changed(void);

/* ============================ IP 选择 ============================ */

/*
 * 从结果中随机选择一个符合 query_type 的 IP。
 * @param[in]   results     已获取的解析结果
 * @param[in]   query_type  族过滤条件：IPV4 仅选 IPv4，IPV6 仅选 IPv6，
 *                          BOTH/AUTO 不过滤（双栈全接受）
 * @param[out]  ip_out      接收选中 IP 的缓冲，长度需不小于 PDNS_IP_ADDRESS_STRING_LENGTH
 * @return 成功返回 PDNS_OK；列表为空、无同族 IP 或参数无效时返回非 0 且 ip_out 置空串。
 */
PDNS_API int pdns_select_ip_randomly(const pdns_result_list_t *results,
                            pdns_query_type_t query_type,
                            char *ip_out);

/*
 * 返回解析结果列表中符合 query_type 的第一个 IP；若已开启 IP 测速排序，
 * 往往意味着最优 IP。本函数仅收到 IP 字符串列表、无 RTT 数据，不在函数内重新测速或排序。
 * @param[in]   results     已获取的解析结果
 * @param[in]   query_type  族过滤条件：IPV4 仅选 IPv4，IPV6 仅选 IPv6，
 *                          BOTH/AUTO 不过滤（双栈全接受，保持混排顺序）
 * @param[out]  ip_out      接收选中 IP 的缓冲，长度需不小于 PDNS_IP_ADDRESS_STRING_LENGTH
 * @return 成功返回 PDNS_OK；列表为空、无同族 IP 或参数无效时返回非 0 且 ip_out 置空串。
 */
PDNS_API int pdns_select_ip_first(const pdns_result_list_t *results,
                         pdns_query_type_t query_type,
                         char *ip_out);

/* ============================ 日志 ============================ */

/* 日志级别（由高到低） */
typedef enum {
    PDNS_LOG_LEVEL_ERROR = 0,   /* 错误 */
    PDNS_LOG_LEVEL_WARN,        /* 警告 */
    PDNS_LOG_LEVEL_INFO,        /* 信息 */
    PDNS_LOG_LEVEL_DEBUG        /* 调试 */
} pdns_log_level_t;

/*
 * 日志回调。使用方可将其转接到自有日志系统。
 * @param[in]  level  日志级别
 * @param[in]  msg    已格式化好的完整日志文本（含级别与 "pdns" 前缀）
 */
typedef void (*pdns_logger_fn)(pdns_log_level_t level, const char *msg);

/*
 * 开关调试日志（默认关闭）。
 * @param[in]  enable  true 开启，false 关闭
 */
PDNS_API void pdns_log_set_enable(bool enable);

/*
 * 设置日志级别过滤（默认 PDNS_LOG_LEVEL_DEBUG，即输出全部级别）。
 * 仅输出「级别不低于设定值」的日志：枚举数值越小级别越高，
 * 如设为 PDNS_LOG_LEVEL_WARN，则只输出 ERROR 与 WARN，过滤 INFO/DEBUG。
 * @param[in]  level  日志级别阈值
 */
PDNS_API void pdns_log_set_level(pdns_log_level_t level);

/*
 * 注入日志回调。
 * @param[in]  logger  日志回调函数；传 NULL 恢复默认（输出到 stderr）
 */
PDNS_API void pdns_log_set_logger(pdns_logger_fn logger);

#ifdef __cplusplus
}
#endif

#endif /* PDNS_API_H */
