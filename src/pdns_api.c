/*
 * 阿里云 移动解析HTTPDNS C SDK —— 对外 API 实现
 *
 * 汇聚 SDK 生命周期、客户端配置、解析入口（同步/缓存/异步）、预解析与保活、
 * 测速调度与结果排序；具体能力分布于各子模块（resolver / cache / server_manager /
 * acl / speedtest / net 等）。
 */
#include "pdns/pdns_api.h"
#include "pdns_list.h"
#include "pdns_resolver.h"
#include "pdns_executor.h"
#include "pdns_cache.h"
#include "pdns_http.h"       /* PDNS_DEFAULT_TIMEOUT_MS */
#include "pdns_log.h"
#include "pdns_server_manager.h"
#include "pdns_localdns.h"
#include "pdns_netstack.h"
#include "pdns_net.h"
#include "pdns_util.h"
#include "pdns_session.h"
#include "pdns_reqstat.h"
#include "pdns_tempip.h"
#include "pdns_acl.h"
#include "pdns_conf.h"
#include "pdns_speedtest.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* 三方依赖：此处引用并在 pdns_sdk_init 中调用，用于打通编译链接 */
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_pool.h>
#include <apu_version.h>
#include <apr_thread_proc.h>
#include <apr_thread_mutex.h>
#include <apr_hash.h>
#include <apr_time.h>
#include <curl/curl.h>
#include "pdns_cjson.h"

/* ============================ 内部结构 ============================ */

/* ============================ 保活域名（keep-alive） ============================ */

/* 保活域名上限（最多 10 个） */
#define PDNS_KEEP_ALIVE_MAX   10
/* 保活域名长度上限 */
#define PDNS_KA_HOST_LEN      256

/*
 * 保活 slot：每个登记域名预分配 v4/v6 两个 slot（缓存按族分键 host_1/host_28）。
 * slot 本身作为延时任务上下文传入线程池（生命周期随 client，无需 malloc/free，
 * cleanup 取消排期任务时不会泄漏）。pending 防重入：同一 host+type 同时只有一条保活链。
 */
typedef struct {
    pdns_client_t     *client;                  /* 回指客户端（worker 使用） */
    char               host[PDNS_KA_HOST_LEN];  /* 保活域名 */
    pdns_query_type_t  qtype;                   /* PDNS_QUERY_IPV4 / PDNS_QUERY_IPV6 */
    bool               pending;                 /* 已有排期任务（防重入） */
} pdns_ka_slot_t;

struct pdns_client_s {
    char               *account_id;
    char               *access_key_id;
    char               *access_key_secret;
    char               *ecs;
    char                session_id[13];  /* 会话 ID：create 时生成，随请求 &did= 上报；按 client 隔离 */
    int32_t             timeout_ms;
    pdns_schema_type_t  schema;
    int32_t             speed_port;
    int32_t             max_ttl_cache;
    int32_t             min_ttl_cache;
    int32_t             max_negative_cache;
    int32_t             max_cache_size;
    bool                enable_cache;
    bool                enable_speed_test;
    bool                enable_localdns;
    bool                enable_immutable_cache;
    bool                enable_ipv6;
    bool                enable_short;            /* 是否启用 short 模式（默认 false） */
    bool                enable_http2;            /* 是否启用 HTTP/2 传输（默认 true，ALPN 协商失败自动回落 1.1） */
    pdns_cache_t       *cache;
    /* provider 调度管理器：持有 public / fusion 两个
     * provider、主备降级决策与失败计数。 */
    pdns_server_manager_t *server_manager;
    pdns_acl_t         *acl;           /* 黑白名单 ACL 管理器 */
    apr_pool_t         *pool;          /* 客户端级内存池（承载线程池） */
    apr_thread_pool_t  *thread_pool;   /* 解析池：仅异步解析，上限由 max_concurrent_resolve 控制 */
    apr_thread_pool_t  *aux_pool;      /* 辅助池：测速 / conf 拉取 / 优选 IP 拉取 / 保活排期 */
    apr_thread_t       *timer_thread;  /* 配置刷新定时器线程（serverTtl / userConfTTL 周期刷新） */
    volatile int        timer_stop;    /* 定时器停止标志 */
    pdns_list_impl_t   *pre_load_domains; /* 预解析域名集合（网络切换后重新预解析，惰性创建） */
    pdns_query_type_t   pre_load_qtype;   /* 预解析查询类型（最近一次 add 的类型） */
    apr_thread_mutex_t *pre_load_lock;    /* 保护 pre_load_domains 的并发访问 */
    pdns_ka_slot_t      keep_alive_slots[PDNS_KEEP_ALIVE_MAX * 2]; /* 保活 slot：域名 i → [2i]=v4 [2i+1]=v6 */
    int                 keep_alive_count;  /* 已登记保活域名数 */
    apr_thread_mutex_t *keep_alive_lock;   /* 保护保活 slot 的并发访问 */
    int32_t             speed_test_ipv6_prefer_ms; /* IPv6 测速让分(ms)，[0,1000]，0=关闭，仅测速开启时生效 */
    apr_hash_t         *speeding;          /* 域名级测速去重："host_1"/"host_28" → 测速中标记 */
    apr_thread_mutex_t *speed_lock;        /* 保护 speeding 表 */
    int32_t             max_concurrent_resolve; /* 异步解析最大并发数，[1,50]，默认 10 */
};

/* 并发解析数配置边界（对外可调，见 pdns_client_set_max_concurrent_resolve_count）。
 * 该配置的语义就是「并发解析线程上限」，故直接作为解析池的 max_threads。 */
#define PDNS_MAX_CONCURRENT_MIN     1
#define PDNS_MAX_CONCURRENT_MAX     50
#define PDNS_MAX_CONCURRENT_DEFAULT 10

/*
 * 线程池预创建线程数：0 = 惰启动，不预先起线程。
 * SDK 是被宿主集成的库，且不少集成方只用同步解析（跑在调用方线程），
 * 按需创建：避免 pdns_client_create 即占用宿主的线程资源。
 *
 * ⚠ APR 语义陷阱：apr_thread_pool_create 的 init_threads 会被同时用作
 * idle_max（空闲线程保留上限）。仅传 0 会使线程做完任务立即销毁，
 * 造成每次异步解析都重新 pthread_create（高频解析下是持续开销），
 * 故 create 后必须显式 apr_thread_pool_idle_max_set 恢复线程复用。
 * 最终行为：不用则零线程，用过则保留复用（惰启动 + 全复用）。
 */
#define PDNS_TP_INIT_THREADS 0

/*
 * APR-util 线程池「收缩」安全性判定。
 *
 * APR-util < 1.6 的 apr_thread_pool 在批量回收线程时，recycled_thds 环中
 * 元素的 prev 指针未被正确初始化；后续 elt_new() 复用该元素时会执行
 * prev->next = next，对空指针写入 → SIGSEGV。
 *
 * 触发路径（两条都会走批量回收）：
 *   apr_thread_pool_thread_max_set(pool, n)  n < 当前 thread_max
 *   apr_thread_pool_idle_max_set(pool, n)    n < 当前空闲线程数
 *
 * 已确认：CentOS 7 自带 APR-util 1.5.2 必崩，1.6.3 已修复。
 */
#if defined(APU_MAJOR_VERSION) && (APU_MAJOR_VERSION == 1) && (APU_MINOR_VERSION < 6)
#  define PDNS_APU_THREAD_POOL_SHRINK_UNSAFE 1
#else
#  define PDNS_APU_THREAD_POOL_SHRINK_UNSAFE 0
#endif

/* 辅助池：承载测速 / 黑白名单 conf 拉取 / 优选 IP 拉取 / 保活排期。
 * 与解析池分离，使 max_concurrent_resolve 只约束解析：调用方将其调小时
 * 不会出现「一次慢测速占住唯一线程、后续解析全部排队」。
 * 容量固定且小：这些任务频率低（conf / tempip 为 60s 级周期）、并发度天然有限。 */
#define PDNS_AUX_MAX_THREADS  4
#define PDNS_AUX_IDLE_THREADS 2   /* 空闲保留数（频率低，无需保留到 MAX） */

/* 待处理任务积压上限（仅解析池；超过则拒收新异步任务，避免无限积压） */
#define PDNS_TP_MAX_TASK_COUNT 200

/*
 * 解析任务优先级：解析池内部排队时，先服务正在等回调的调用方。
 * 注：APR 优先级仅影响出队顺序，不能抢占已在执行的任务。
 */
#define PDNS_PRIO_USER    APR_THREAD_TASK_PRIORITY_HIGH   /* 用户主动异步解析（有人等回调） */
#define PDNS_PRIO_REFRESH APR_THREAD_TASK_PRIORITY_NORMAL /* 缓存后台刷新（已返回旧值） */
#define PDNS_PRIO_PREHEAT APR_THREAD_TASK_PRIORITY_LOW    /* 预解析 / 保活定时刷新 */

/* ============================ 全局网络检测器 ============================ */

/*
 * 网络栈是宿主机级属性，与 client 实例无关，故 detector 采用全局单例：
 * 在 pdns_sdk_init 创建并启动、pdns_sdk_cleanup 销毁。
 * 消除多 client 下的冗余探测与轮询线程开销，并保证同进程内网络栈判定一致。
 */
static pdns_net_detector_t *g_pdns_net_detector = NULL;

/*
 * 网络切换感知开关（全局静态开关）；不与任何 client 实例绑定。默认开启。
 */
static volatile bool g_pdns_enable_network_change = true;

/* ============================ 内部辅助 ============================ */

static pdns_status_t pdns_status_ok(void) {
    pdns_status_t s;
    memset(&s, 0, sizeof(s));
    s.code = PDNS_OK;
    return s;
}

static pdns_status_t pdns_status_fail(int code, const char *msg) {
    pdns_status_t s;
    memset(&s, 0, sizeof(s));
    s.code = code;
    if (msg) {
        strncpy(s.error_msg, msg, PDNS_ERROR_MSG_LEN - 1);
    }
    return s;
}

static char *pdns_strdup(const char *src) {
    if (!src) {
        return NULL;
    }
    size_t len = strlen(src) + 1;
    char *dst = (char *) malloc(len);
    if (dst) {
        memcpy(dst, src, len);
    }
    return dst;
}

/* ============================ 状态 ============================ */

bool pdns_status_is_ok(const pdns_status_t *status) {
    return status != NULL && status->code == PDNS_OK;
}

const char *pdns_version(void) {
    return PDNS_VERSION;
}

/* 链表实现见 pdns_list.c（域名列表 / 解析结果列表共用同一底层） */

/* ============================ SDK 生命周期 ============================ */

int pdns_sdk_init(void) {
    /* 初始化 APR 运行时 */
    if (apr_initialize() != APR_SUCCESS) {
        return 1;
    }
    /* 初始化 libcurl 全局环境 */
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        apr_terminate();
        return 1;
    }
    /* 初始化日志全局锁 */
    pdns_log_init();
    /* 初始化 curl 连接池 */
    pdns_session_init();
    /* 初始化工具模块（requestId 设备前缀/计数器） */
    pdns_util_init();
    /* 初始化请求级统计头状态（c/ne/se） */
    pdns_reqstat_init();
    /* 创建并启动全局网络检测器（网络栈与 client 无关，进程内共一份） */
    if (g_pdns_net_detector == NULL) {
        g_pdns_net_detector = pdns_net_detector_create();
        pdns_net_detector_start(g_pdns_net_detector, g_pdns_enable_network_change);
    }
    /* 触达 pdns_cJSON 符号，确保链接通过 */
    (void) pdns_cJSON_Version();
    return PDNS_OK;
}

void pdns_sdk_cleanup(void) {
    /* 先销毁全局检测器（停轮询线程），再释放其余全局资源 */
    if (g_pdns_net_detector) {
        pdns_net_detector_destroy(g_pdns_net_detector);
        g_pdns_net_detector = NULL;
    }
    pdns_util_cleanup();
    pdns_reqstat_cleanup();
    pdns_session_cleanup();
    pdns_log_cleanup();
    curl_global_cleanup();
    apr_terminate();
}

pdns_client_t *pdns_client_create(void) {
    pdns_client_t *client = (pdns_client_t *) calloc(1, sizeof(pdns_client_t));
    if (!client) {
        return NULL;
    }
    /* 先建客户端内存池（承载鉴权字符串与线程池） */
    if (apr_pool_create(&client->pool, NULL) != APR_SUCCESS) {
        free(client);
        return NULL;
    }
    /* 鉴权参数不在此设置：由 pdns_client_init_public_dns 显式配置。
     * calloc 已将三个指针置 NULL，未配置时 pdns_client_start 会拒绝启动。 */
    /* 会话 ID：每个 client 创建时生成一次、终身不变（C 多 client 按实例隔离） */
    pdns_gen_session_id(client->session_id, sizeof(client->session_id));
    PDNS_LOGD("session id: %s", client->session_id);
    /* 默认配置 */
    client->timeout_ms         = PDNS_DEFAULT_TIMEOUT_MS;
    client->schema             = PDNS_SCHEMA_HTTPS;
    client->speed_port         = 80;
    client->max_ttl_cache      = 3600;
    client->min_ttl_cache      = 60;
    client->max_negative_cache = 30;
    client->max_cache_size     = 100;
    client->enable_cache        = true;
    client->enable_speed_test   = true;
    client->enable_localdns     = true;
    client->enable_immutable_cache    = false;
    client->enable_ipv6        = false;
    client->enable_short       = false;
    client->enable_http2       = true;
    client->max_concurrent_resolve = PDNS_MAX_CONCURRENT_DEFAULT;
    client->cache              = pdns_cache_create(NULL);
    client->server_manager     = pdns_server_manager_create();
    client->acl                = pdns_acl_create();
    /* 网络检测器为全局单例（pdns_sdk_init 已创建并启动） */
    /* 解析池（使用客户端 pool）：仅承载异步解析。
     * max_threads 直接取 max_concurrent_resolve（该配置的语义就是并发解析线程上限）；
     * init=0 惰启动，再用 idle_max_set 恢复线程复用（原因见 PDNS_TP_INIT_THREADS 注释）。 */
    apr_thread_pool_create(&client->thread_pool, PDNS_TP_INIT_THREADS,
                           (apr_size_t) client->max_concurrent_resolve, client->pool);
    if (client->thread_pool) {
        apr_thread_pool_idle_max_set(client->thread_pool,
                                     (apr_size_t) client->max_concurrent_resolve);
    }
    /* 辅助池：测速 / conf 拉取 / 优选 IP 拉取 / 保活排期。与解析池独立，
     * 使调用方调小 max_concurrent_resolve 不会让后台任务与解析相互阻塞。
     * 同样惰启动：未启动时（未调 pdns_client_start）不会预先占线程。 */
    apr_thread_pool_create(&client->aux_pool, PDNS_TP_INIT_THREADS,
                           PDNS_AUX_MAX_THREADS, client->pool);
    if (client->aux_pool) {
        apr_thread_pool_idle_max_set(client->aux_pool, PDNS_AUX_IDLE_THREADS);
    }
    /* 预解析集合互斥锁（惰性填充域名，供网络切换后重新预解析） */
    apr_thread_mutex_create(&client->pre_load_lock, APR_THREAD_MUTEX_DEFAULT,
                            client->pool);
    /* 保活 slot 互斥锁（setKeepAliveDomains 登记 + 写缓存 hook 排期） */
    apr_thread_mutex_create(&client->keep_alive_lock, APR_THREAD_MUTEX_DEFAULT,
                            client->pool);
    /* 测速去重表与锁（让分默认 0=关闭，calloc 已置零） */
    client->speeding = apr_hash_make(client->pool);
    apr_thread_mutex_create(&client->speed_lock, APR_THREAD_MUTEX_DEFAULT,
                            client->pool);
    return client;
}

/* 是否已配置任何 DNS 服务。
 * 鉴权完整性由各 provider 内部校验（isAccountAuthAvailable），
 * 此处只看最终是否有 provider 进入调度组。 */
static bool client_has_dns_provider(pdns_client_t *client) {
    return pdns_server_manager_provider_count(client->server_manager) > 0;
}

pdns_status_t pdns_client_init_public_dns(pdns_client_t *client,
                                         const char *account_id,
                                         const char *access_key_id,
                                         const char *access_key_secret) {
    if (!client) {
        return pdns_status_fail(1, "client is NULL");
    }
    /*
     * 三参数必填，缺一即失败：鉴权不全时该 Provider 不参与调度，等效于「不发请求」。
     * 故此处硬失败，不得放行后在解析层降级为无签名请求。
     * 具体校验在 provider 内完成，此处只做参数归因以便回错清楚。
     */
    if (!account_id || !account_id[0]) {
        return pdns_status_fail(1, "account_id can not be empty");
    }
    if (!access_key_id || !access_key_id[0]) {
        return pdns_status_fail(1, "access_key_id can not be empty");
    }
    if (!access_key_secret || !access_key_secret[0]) {
        return pdns_status_fail(1, "access_key_secret can not be empty");
    }
    /* 鉴权落在 public provider 内，并触发 provider group 重建。 */
    if (pdns_server_manager_init_public_dns(client->server_manager, account_id,
                                                access_key_id, access_key_secret) != 0) {
        return pdns_status_fail(1, "init public dns failed");
    }
    PDNS_LOGI("public dns configured: uid=%s ak=%s", account_id, access_key_id);
    return pdns_status_ok();
}

pdns_status_t pdns_client_init_fusion_dns(pdns_client_t *client,
                                         const char *const *server_ipv4_arr, int v4_count,
                                         const char *const *server_ipv6_arr, int v6_count,
                                         const char *const *server_host_arr, int host_count,
                                         int         port,
                                         const char *health_check_domain,
                                         const char *access_key_id,
                                         const char *access_key_secret) {
    if (!client) {
        return pdns_status_fail(1, "client is NULL");
    }
    /* 逐项回错：自建的参数全由调用方提供，错一项就完全不可用，
     * 统一回一个 "init fusion dns failed" 会让调用方无法定位。 */
    if ((server_ipv4_arr == NULL || v4_count <= 0) &&
        (server_ipv6_arr == NULL || v6_count <= 0) &&
        (server_host_arr == NULL || host_count <= 0)) {
        return pdns_status_fail(1, "fusion dns needs at least one server address");
    }
    if (!health_check_domain || !health_check_domain[0]) {
        return pdns_status_fail(1, "health_check_domain can not be empty");
    }
    if (!access_key_id || !access_key_id[0]) {
        return pdns_status_fail(1, "access_key_id can not be empty");
    }
    if (!access_key_secret || !access_key_secret[0]) {
        return pdns_status_fail(1, "access_key_secret can not be empty");
    }
    /* uid 不由调用方传入，固定为 PDNS_FUSION_DEFAULT_ACCOUNT_ID（自建服务部署在
     * 集成方侧，不按账号区分调用方）。内部 provider 仍保留该形参。 */
    if (pdns_server_manager_init_fusion_dns(
            client->server_manager, server_ipv4_arr, v4_count, server_ipv6_arr, v6_count,
            server_host_arr, host_count, port, health_check_domain,
            PDNS_FUSION_DEFAULT_ACCOUNT_ID, access_key_id, access_key_secret) != 0) {
        return pdns_status_fail(1, "init fusion dns failed");
    }
    PDNS_LOGI("fusion dns configured: ak=%s port=%d v4=%d v6=%d host=%d hc=%s",
              access_key_id, port, v4_count, v6_count, host_count, health_check_domain);
    return pdns_status_ok();
}

void pdns_client_set_fusion_certificate_validation(pdns_client_t *client, bool enable) {
    if (!client) {
        return;
    }
    pdns_fusion_provider_set_enable_certificate_validation(
        pdns_server_manager_fusion(client->server_manager), enable);
}

void pdns_client_set_fallback_threshold(pdns_client_t *client, int32_t fallback_threshold) {
    if (!client) {
        return;
    }
    pdns_server_manager_set_fallback_threshold(client->server_manager,
                                                   (int) fallback_threshold);
}

/* ============================ 服务 IP 优选拉取 ============================ */

/* 后台拉取服务端优选 IP 列表的任务上下文 */
typedef struct {
    pdns_client_t *client;
    bool           is_expire;   /* true=serverTtl 过期刷新（继承 SRTT）；false=首次/网络切换 */
} pdns_tempip_task_t;

static void *APR_THREAD_FUNC pdns_tempip_worker(apr_thread_t *thd, void *param) {
    (void) thd;
    pdns_tempip_task_t *task   = (pdns_tempip_task_t *) param;
    pdns_client_t      *client = task->client;
    pdns_tempip_fetch(pdns_server_manager_public(client->server_manager),
                      pdns_net_get_type(g_pdns_net_detector),
                      client->enable_ipv6, (client->schema == PDNS_SCHEMA_HTTPS),
                      client->timeout_ms, task->is_expire);
    free(task);
    return NULL;
}

/* 将一次优选 IP 拉取任务推入辅助池（非阻塞） */
static void pdns_submit_tempip(pdns_client_t *client, bool is_expire) {
    if (client == NULL || client->aux_pool == NULL) {
        return;
    }
    pdns_tempip_task_t *task = (pdns_tempip_task_t *) calloc(1, sizeof(pdns_tempip_task_t));
    if (task == NULL) {
        return;
    }
    task->client    = client;
    task->is_expire = is_expire;
    if (apr_thread_pool_push(client->aux_pool, pdns_tempip_worker, task, 0, NULL)
        != APR_SUCCESS) {
        free(task);
    }
}

/* ============================ 黑白名单配置拉取 ============================ */

/* 后台拉取黑白名单 /conf 配置的任务上下文 */
typedef struct {
    pdns_client_t *client;
} pdns_conf_task_t;

static void *APR_THREAD_FUNC pdns_conf_worker(apr_thread_t *thd, void *param) {
    (void) thd;
    pdns_conf_task_t *task   = (pdns_conf_task_t *) param;
    pdns_client_t    *client = task->client;
    /*
     * 每个已启用的 provider 各拉一次，串行 public → fusion。两者共享同一个 ACL，
     * 后一次成功的结果覆盖前一次。
     */
    pdns_netstack_type_t stack = pdns_net_get_type(g_pdns_net_detector);
    bool using_https = (client->schema == PDNS_SCHEMA_HTTPS);

    pdns_server_provider_t *pub = pdns_public_provider_as_provider(
        pdns_server_manager_public(client->server_manager));
    if (pdns_provider_is_dns_provider_enabled(pub)) {
        pdns_conf_fetch(client->acl, pub, stack, client->enable_ipv6, using_https,
                        client->timeout_ms);
    }
    pdns_server_provider_t *fus = pdns_fusion_provider_as_provider(
        pdns_server_manager_fusion(client->server_manager));
    if (pdns_provider_is_dns_provider_enabled(fus)) {
        pdns_conf_fetch(client->acl, fus, stack, client->enable_ipv6, using_https,
                        client->timeout_ms);
    }
    free(task);
    return NULL;
}

/* 将一次黑白名单配置拉取任务推入辅助池（非阻塞） */
static void pdns_submit_conf(pdns_client_t *client) {
    if (client == NULL || client->aux_pool == NULL) {
        return;
    }
    pdns_conf_task_t *task = (pdns_conf_task_t *) calloc(1, sizeof(pdns_conf_task_t));
    if (task == NULL) {
        return;
    }
    task->client = client;
    if (apr_thread_pool_push(client->aux_pool, pdns_conf_worker, task, 0, NULL)
        != APR_SUCCESS) {
        free(task);
    }
}

/* ============================ 配置刷新定时器 ============================ */

/* 定时周期（60s） */
#define PDNS_REFRESH_TIMER_INTERVAL_MS 60000
/* 分段休眠步长，便于停止标志及时生效 */
#define PDNS_REFRESH_TIMER_STEP_MS     500

/* 后台定时器：周期检查 serverTtl / userConfTTL 是否过期并异步重拉。 */
static void *APR_THREAD_FUNC pdns_refresh_timer_worker(apr_thread_t *thd, void *param) {
    (void) thd;
    pdns_client_t *client = (pdns_client_t *) param;
    while (!client->timer_stop) {
        int slept = 0;
        while (slept < PDNS_REFRESH_TIMER_INTERVAL_MS && !client->timer_stop) {
            apr_sleep((apr_interval_time_t) PDNS_REFRESH_TIMER_STEP_MS * 1000);
            slept += PDNS_REFRESH_TIMER_STEP_MS;
        }
        if (client->timer_stop) {
            break;
        }
        /* serverTtl 过期：重拉优选 IP（is_expire=true 继承 SRTT）。
         * 仅公共 DNS 有服务端下发的优选列表。 */
        pdns_public_provider_t *pub =
            pdns_server_manager_public(client->server_manager);
        if (pdns_provider_is_dns_provider_enabled(
                pdns_public_provider_as_provider(pub)) &&
            pdns_base_provider_is_server_ip_expired(
                pdns_public_provider_as_base(pub))) {
            pdns_submit_tempip(client, true);
        }
        /* userConfTTL 过期：重拉黑白名单配置 */
        if (pdns_acl_is_conf_expired(client->acl)) {
            pdns_submit_conf(client);
        }
        /* 清理过期的失败计数记录：C 侧复用本已有的 60s 定时器，不新起线程。
         * 条目过期时长也是 60s，故最多多留 60s，无实际影响；定时器未启时由
         * tracker 内部惰性清理兜底。 */
        pdns_server_manager_cleanup_expired(client->server_manager);

        /* 自建节点健康检查（60s 周期探测）。
         * 复用本定时器而不新起线程。
         * 无熔断节点 / 未配自建 / 无探测域名时内部直接返回，不产生网络请求。
         * 探测是同步串行的，在本定时器线程内完成（不占用解析线程池）。 */
        pdns_server_manager_run_health_check(
            client->server_manager, pdns_net_get_type(g_pdns_net_detector),
            client->session_id, client->timeout_ms,
            client->schema == PDNS_SCHEMA_HTTPS);
    }
    return NULL;
}

/* 网络变化回调：重置服务节点 SRTT，
 * 并重新拉取一次服务端优选 IP（is_expire=false，新节点 SRTT 归零）。
 * 随后按已登记的预解析集合重新预解析。
 * （DNS 解析缓存保留） */
static void pdns_preload_again(pdns_client_t *client);   /* 前向声明，实现见预解析章节 */

/* 保活 hook 前向声明（写缓存即排期 TTL×0.75 刷新，实现见保活章节） */
static void pdns_keepalive_on_cache_write(pdns_client_t *client, const char *host,
                                          pdns_query_type_t query_type, int ttl);

/* 测速任务提交前向声明（写缓存后异步测速+排序，实现见测速章节） */
static void pdns_submit_speedtest(pdns_client_t *client, const char *host,
                                  pdns_query_type_t query_type,
                                  const pdns_result_list_t *ips,
                                  const char *rid,
                                  pdns_source_t source);

/* 双栈合并前向声明：默认 v4 前 v6 后；测速开启且两族都有时按 effectiveKey 混排（v6 让分）。
 * 两族的 meta 也会一并搬到 out（各自归位，不会互盖）。 */
static void pdns_merge_both_sorted(pdns_client_t *client, const char *host,
                                   const pdns_result_list_t *v4,
                                   const pdns_result_list_t *v6,
                                   pdns_result_list_t *out);

static void pdns_on_net_change_reset_srtt(void *user_data) {
    pdns_client_t *client = (pdns_client_t *) user_data;
    if (client) {
        pdns_server_manager_reset_srtt(client->server_manager);
        pdns_submit_tempip(client, false);
        pdns_preload_again(client);
    }
}

/* 将 client 的缓存相关配置同步进 cache（setter 运行期修改立即生效） */
static void apply_cache_config(pdns_client_t *client) {
    if (!client || !client->cache) {
        return;
    }
    pdns_cache_config_t cfg;
    cfg.max_ttl      = client->max_ttl_cache;
    cfg.min_ttl      = client->min_ttl_cache;
    cfg.max_negative = client->max_negative_cache;
    cfg.max_size     = client->max_cache_size;
    cfg.immutable    = client->enable_immutable_cache;
    pdns_cache_set_config(client->cache, &cfg);
}

pdns_status_t pdns_client_start(pdns_client_t *client) {
    if (!client) {
        return pdns_status_fail(1, "client is NULL");
    }
    /* 未配置任何 DNS 服务则拒绝启动：把配置错误提前暴露在启动阶段，
     * 而非首次解析时才失败。 */
    if (!client_has_dns_provider(client)) {
        return pdns_status_fail(2,
            "no dns service configured, call pdns_client_init_public_dns or "
            "pdns_client_init_fusion_dns first");
    }
    /* 兜底同步一次（setter 已实时同步，此处覆盖 start 前的批量配置） */
    apply_cache_config(client);
    /* 订阅网络变化：切换后重置服务节点测速（detector 为全局单例，以 client 为 owner 区分） */
    pdns_net_subscribe(g_pdns_net_detector, pdns_on_net_change_reset_srtt, client, client);
    /* detector 已在 pdns_sdk_init 启动，此处无需重复启动 */
    /* 首次拉取服务端优选 IP 列表（is_expire=false）。
     * 仅公共 DNS 适用；单自建配置时跳过（自建节点已由调用方在 init 中给齐）。 */
    if (pdns_provider_is_dns_provider_enabled(pdns_public_provider_as_provider(
            pdns_server_manager_public(client->server_manager)))) {
        pdns_submit_tempip(client, false);
    }
    /* 首次拉取黑白名单配置 */
    pdns_submit_conf(client);
    /* 启动配置刷新定时器（60s 周期） */
    if (client->timer_thread == NULL) {
        client->timer_stop = 0;
        apr_thread_create(&client->timer_thread, NULL, pdns_refresh_timer_worker,
                          client, client->pool);
    }
    return pdns_status_ok();
}

void pdns_client_cleanup(pdns_client_t *client) {
    if (!client) {
        return;
    }
    /* 先停配置刷新定时器，确保不再向线程池提交新拉取任务。 */
    if (client->timer_thread) {
        apr_status_t rv;
        client->timer_stop = 1;
        apr_thread_join(&rv, client->timer_thread);
        client->timer_thread = NULL;
    }
    /* 再退订本 client 在全局检测器上的订阅（关键：防止切换事件回调到已释放的
     * client，即 use-after-free）；detector 为全局单例，不在此销毁。 */
    pdns_net_unsubscribe(g_pdns_net_detector, client);
    /*
     * 线程池销毁顺序：必须先解析池、再辅助池。
     * 依赖方向是单向的：解析写缓存后会向辅助池提交测速与保活排期，
     * 而辅助池任务不会回投解析池（保活 worker 在自己线程内直接同步解析）。
     * 故先停解析池，才能保证此后不再有新任务进入辅助池。
     */
    if (client->thread_pool) {
        apr_thread_pool_destroy(client->thread_pool);
        client->thread_pool = NULL;
    }
    if (client->aux_pool) {
        /* 先取消以 client 为 owner 的保活排期任务（slot 随 client 回收，无泄漏） */
        apr_thread_pool_tasks_cancel(client->aux_pool, client);
        apr_thread_pool_destroy(client->aux_pool);
        client->aux_pool = NULL;
    }
    /* 线程池已停、网络切换回调已摘除，无并发访问，安全释放预解析集合
     * （链表由 malloc 管理；pre_load_lock 随 client->pool 一并回收） */
    if (client->pre_load_domains) {
        pdns_list_impl_destroy(client->pre_load_domains);
        client->pre_load_domains = NULL;
    }
    if (client->pool) {
        apr_pool_destroy(client->pool);
    }
    pdns_cache_destroy(client->cache);
    pdns_server_manager_destroy(client->server_manager);
    pdns_acl_destroy(client->acl);
    /* 鉴权参数由各 provider 自己的 pool 持有，随 manager 销毁，无需单独释放 */
    free(client->ecs);
    free(client);
}

/* ============================ 配置接口 ============================ */

/*
 * 超时配置上限（毫秒）。定为 60s 是防呆而非业务限制：
 * 弱网 / 跨境场景下十几秒仍属合理取值，但超过 60s 基本只可能是
 * 单位传错（如把微秒当毫秒传），任其生效会让解析长时间挂住。
 * 与 pdns_http.h 的 PDNS_DEFAULT_TIMEOUT_MS（3000，<=0 时采用的默认值）分工：
 * 本宏是调用方可配值的上界。
 */
#define PDNS_MAX_TIMEOUT_MS 60000
void pdns_client_set_timeout(pdns_client_t *client, int32_t timeout_ms) {
    if (client) {
        /* <=0 视为无效输入，统一回退到默认超时；上界钳到 PDNS_MAX_TIMEOUT_MS。
         * 钳制后 client->timeout_ms 恒为有效正值，HTTP 层对 <=0 的兜底
         * （PDNS_DEFAULT_TIMEOUT_MS）仅作为防御性保留，此路径不会再触发。 */
        if (timeout_ms <= 0) {
            timeout_ms = PDNS_DEFAULT_TIMEOUT_MS;
        } else if (timeout_ms > PDNS_MAX_TIMEOUT_MS) {
            timeout_ms = PDNS_MAX_TIMEOUT_MS;
        }
        client->timeout_ms = timeout_ms;
    }
}
void pdns_client_set_enable_cache(pdns_client_t *client, bool enable_cache) {
    if (client) client->enable_cache = enable_cache;
}
void pdns_client_set_schema_type(pdns_client_t *client, pdns_schema_type_t schema) {
    if (client) client->schema = schema;
}
void pdns_client_set_enable_speed_test(pdns_client_t *client, bool enable) {
    if (client) client->enable_speed_test = enable;
}
void pdns_client_set_speed_test_ipv6_prefer_ms(pdns_client_t *client, int32_t ms) {
    if (client == NULL) {
        return;
    }
    /* 取值范围 [0,1000]，越界裁剪 */
    if (ms < 0)    ms = 0;
    if (ms > 1000) ms = 1000;
    client->speed_test_ipv6_prefer_ms = ms;
}

const char *pdns_client_get_session_id(pdns_client_t *client) {
    if (client == NULL) {
        return NULL;
    }
    return client->session_id;
}
#define PDNS_SPEED_PORT_MAX 65535  /* TCP 端口号上限 */
void pdns_client_set_speed_port(pdns_client_t *client, int32_t speed_port) {
    if (client) {
        /* 钳制到 [0, 65535]：越界值不是合法 TCP 端口，夹紧后测速失败但不影响解析。 */
        if (speed_port < 0) {
            speed_port = 0;
        } else if (speed_port > PDNS_SPEED_PORT_MAX) {
            speed_port = PDNS_SPEED_PORT_MAX;
        }
        client->speed_port = speed_port;
    }
}
void pdns_client_set_enable_localdns(pdns_client_t *client, bool enable) {
    if (client) client->enable_localdns = enable;
}
void pdns_client_set_enable_ipv6(pdns_client_t *client, bool enable) {
    if (client) client->enable_ipv6 = enable;
}
void pdns_client_set_enable_immutable_cache(pdns_client_t *client, bool enable) {
    if (client) {
        client->enable_immutable_cache = enable;
        apply_cache_config(client);
    }
}
void pdns_client_set_edns_client_subnet(pdns_client_t *client, const char *ecs) {
    if (client) {
        free(client->ecs);
        client->ecs = pdns_strdup(ecs);
    }
}
void pdns_client_set_max_ttl_cache(pdns_client_t *client, int32_t seconds) {
    if (client) {
        if (seconds < 0) {
            seconds = 0;  /* 负数归 0 */
        }
        client->max_ttl_cache = seconds;
        if (client->min_ttl_cache > client->max_ttl_cache) {
            client->min_ttl_cache = client->max_ttl_cache;  /* max<min 时拉低 min */
        }
        apply_cache_config(client);
    }
}
#define PDNS_MIN_TTL_CACHE_MAX 300  /* 最小缓存TTL配置上限（300秒） */
void pdns_client_set_min_ttl_cache(pdns_client_t *client, int32_t seconds) {
    if (client) {
        if (seconds < 0) {
            seconds = 0;  /* 负数归 0 */
        }
        if (seconds > PDNS_MIN_TTL_CACHE_MAX) {
            seconds = PDNS_MIN_TTL_CACHE_MAX;  /* 上限 300s */
        }
        client->min_ttl_cache = seconds;
        if (client->min_ttl_cache > client->max_ttl_cache) {
            client->max_ttl_cache = client->min_ttl_cache;  /* min>max 时抬高 max */
        }
        apply_cache_config(client);
    }
}
void pdns_client_set_max_negative_cache(pdns_client_t *client, int32_t seconds) {
    if (client) {
        /* 负数归 0，最大值不钳制；0 表示关闭否定缓存
         * （解析层仅在 max_negative > 0 时才建立否定结果）。 */
        client->max_negative_cache = (seconds < 0) ? 0 : seconds;
        apply_cache_config(client);
    }
}
void pdns_client_set_max_cache_size(pdns_client_t *client, int32_t max_size) {
    if (client) {
        /* 负数归 0，最大值不钳制；0 时清空缓存且后续禁写 */
        client->max_cache_size = (max_size < 0) ? 0 : max_size;
        apply_cache_config(client);
        if (client->max_cache_size == 0 && client->cache) {
            pdns_cache_clear(client->cache);
        }
    }
}
void pdns_client_set_max_concurrent_resolve_count(pdns_client_t *client, int32_t count) {
    if (client) {
        /* 钳制到 [1,50]，越界自动夹紧 */
        if (count < PDNS_MAX_CONCURRENT_MIN) {
            count = PDNS_MAX_CONCURRENT_MIN;
        } else if (count > PDNS_MAX_CONCURRENT_MAX) {
            count = PDNS_MAX_CONCURRENT_MAX;
        }
        client->max_concurrent_resolve = count;
        if (client->thread_pool) {
#if PDNS_APU_THREAD_POOL_SHRINK_UNSAFE
            /* 旧 APR-util 上收缩线程池会写空指针崩溃（见
             * PDNS_APU_THREAD_POOL_SHRINK_UNSAFE 说明），故只放大不缩小。
             * 已创建的线程保留，不做回收。 */
            if ((apr_size_t) count < apr_thread_pool_thread_max_get(client->thread_pool)) {
                PDNS_LOGW("APR-util %d.%d 不支持安全收缩线程池，"
                          "仅记录并发配置 %d（已有线程不回收）",
                          APU_MAJOR_VERSION, APU_MINOR_VERSION, count);
                return;
            }
#endif
            /* thread_max（并发上限）与 idle_max（空闲保留上限）必须同步：
             * 只改 thread_max 会在调大并发后仍按旧 idle_max 过度回收线程，
             * 造成反复创建；调小时 idle_max_set 也会立即缩减多余空闲线程。 */
            apr_thread_pool_thread_max_set(client->thread_pool, (apr_size_t) count);
            apr_thread_pool_idle_max_set(client->thread_pool, (apr_size_t) count);
        }
        PDNS_LOGI("setMaxConcurrentResolveCount:%d", count);
    }
}

/* ============================ 回源解析（内部共用） ============================ */

/*
 * AUTO 查询类型归一：根据当前网络栈把 PDNS_QUERY_AUTO 映射为具体类型
 *   IPV4_ONLY → IPV4；IPV6_ONLY → IPV6；DUAL → BOTH；NONE → IPV4（兜底）。
 * 非 AUTO 类型原样返回。
 */
static pdns_query_type_t resolve_query_type(const pdns_client_t *client,
                                            pdns_query_type_t qt) {
    if (qt != PDNS_QUERY_AUTO) {
        return qt;
    }
    switch (pdns_net_get_type(g_pdns_net_detector)) {
        case PDNS_STACK_IPV6_ONLY:
            return PDNS_QUERY_IPV6;
        case PDNS_STACK_DUAL:
            return PDNS_QUERY_BOTH;
        case PDNS_STACK_IPV4_ONLY:
        default:
            return PDNS_QUERY_IPV4;
    }
}

/* 构造黑白名单拦截状态：code=OK + error_code="ACL_REJECTED"
 * （黑白名单是策略性跳过而非错误，与 NXDOMAIN 同类：无错误、无结果）。 */
static pdns_status_t pdns_acl_rejected_status(void) {
    pdns_status_t st = pdns_status_ok();
    strncpy(st.error_code, "ACL_REJECTED", PDNS_ERROR_CODE_LEN - 1);
    st.error_code[PDNS_ERROR_CODE_LEN - 1] = '\0';
    return st;
}

/* 前向声明：异步任务提交（供 resolve_both 信任窗口刷新调用；定义见异步解析区） */
static pdns_status_t pdns_submit_async(pdns_client_t *client, const char *host,
                                       pdns_query_type_t query_type, pdns_scene_t scene,
                                       pdns_resolve_callback_fn callback, void *user_data);

/*
 * 执行一次完整的回源解析：
 *   黑白名单拦截 → 选 provider/节点回源 → SRTT 更新/惩罚 → 重试
 *   → 空结果时 LocalDNS 降级 → 写入缓存。
 * 结果追加到 out（调用方保证已创建）。
 */
static pdns_status_t pdns_network_resolve(pdns_client_t *client,
                                          const char *host,
                                          pdns_query_type_t query_type,
                                          pdns_scene_t scene,
                                          pdns_result_list_t *out) {
    /* 生成本次解析的请求追踪 ID */
    char request_id[PDNS_REQUEST_ID_LEN];
    pdns_gen_request_id(request_id, sizeof(request_id));

    /* 黑白名单拦截：命中黑名单或不在白名单时
     * 不走 HTTPDNS，直接返回空结果（不做 LocalDNS 兜底、不写缓存），由调用方自行决定
     * 是否改用系统 DNS。
     * 语义：黑白名单是策略性跳过而非错误，故 code=OK（与 NXDOMAIN 同类：无错误、无结果）；
     * 额外置 error_code="ACL_REJECTED" 作为来源提示，不影响 is_ok。 */
    if (!pdns_acl_is_normal_resolver(client->acl, host)) {
        PDNS_LOGI("acl reject httpdns: host=%s, return empty (no localdns)", host);
        pdns_status_t acl_st = pdns_acl_rejected_status();
        strncpy(acl_st.request_id, request_id, PDNS_REQUEST_ID_LEN - 1);
        acl_st.request_id[PDNS_REQUEST_ID_LEN - 1] = '\0';
        return acl_st;
    }

    /* 1~3) 多服务器 failover 由执行器负责：
     *   选 provider（主用/降级）→ 选节点 → 回源 → 成功更新 SRTT / 失败惩罚并重试 → 末次 HOST 兜底。
     * 鉴权参数由各 provider 自带，url_path 由选中的 provider 生成。 */
    pdns_resolve_req_t req;
    memset(&req, 0, sizeof(req));
    req.host              = host;
    req.ecs               = client->ecs;
    req.request_id        = request_id;
    req.session_id        = client->session_id;
    req.query_type        = query_type;
    req.scene             = scene;
    req.using_https       = (client->schema == PDNS_SCHEMA_HTTPS);
    req.enable_short      = client->enable_short;
    req.min_ttl           = client->min_ttl_cache;
    req.max_ttl           = client->max_ttl_cache;
    req.max_negative      = client->max_negative_cache;
    req.timeout_ms        = client->timeout_ms;
    req.use_http2         = client->enable_http2;

    int           ttl          = 0;
    bool          is_negative  = false;
    long          conf_version = -1;
    pdns_status_t st  = pdns_execute_resolve_with_retry(
        client->server_manager, pdns_net_get_type(g_pdns_net_detector),
        client->enable_ipv6, &req, out, &ttl, &is_negative, &conf_version);

    /* Cv 响应头驱动的黑白名单刷新：
     *   - 服务端 Cv > 本地版本（且本地已建立）→ 立即异步刷新黑白名单
     *   - 否则（服务端确认本地已最新）→ 重置 conf 计时，推迟下次轮询 */
    if (conf_version >= 0) {
        long local_v = pdns_acl_get_version(client->acl);
        if (local_v != 0 && conf_version > local_v) {
            pdns_submit_conf(client);
        } else {
            pdns_acl_touch_conf_time(client->acl);
        }
    }

    /* 4) HTTPDNS 结果为空且非否定响应且开启降级：LocalDNS 兜底
     *    （否定响应是服务端明确的“无记录”，不走 LocalDNS，直接写否定缓存） */
    int  ttl_final       = ttl;
    bool from_localdns   = false;
    if (pdns_result_list_size(out) == 0 && !is_negative && client->enable_localdns) {
        /* 策略约定：同步路径空且非否定即兜底；
         * 异步路径（预解析/缓存刷新/保活）仅传输失败(非200/重试耗尽)兜底，
         * HTTP200 空响应（如 SERVFAIL/REFUSED/空body）不兜底 */
        bool do_fallback = (scene == PDNS_SCENE_SYNC) || !pdns_status_is_ok(&st);
        if (do_fallback) {
            PDNS_LOGI("[LocalDNS兜底] scene=%s host=%s type=%s 降级系统 DNS",
                      pdns_scene_name(scene), host,
                      (query_type == PDNS_QUERY_IPV6) ? "28" : "1");
            if (pdns_localdns_resolve(host, query_type, out) == PDNS_OK) {
                ttl_final     = PDNS_LOCALDNS_TTL;
                from_localdns = true;
                st            = pdns_status_ok();
            }
        } else {
            PDNS_LOGI("[LocalDNS兜底] scene=%s host=%s HTTP200空且非否定 异步路径按策略不兜底",
                      pdns_scene_name(scene), host);
        }
    }

    /*
     * 本次结果的来源：LocalDNS 兜底优先，否则为执行器末次实际使用的 provider。
     * 同时用于三处：回填结果 meta、写入缓存条目、以及测速日志。
     */
    pdns_source_t result_source = from_localdns ? PDNS_SOURCE_LOCAL_DNS : req.source;

    /* 回填本族的来源 meta（from_cache=false：本次确实走了网络）。
     * 仅当有结果、或服务端给出明确的否定答复时才填：纯失败（空结果且非否定）
     * 保持 UNKNOWN，与对外约定「该族无结果即 UNKNOWN」一致，避免报出「无结果
     * 却声称来自某 provider」这种误导信息。 */
    if (pdns_result_list_size(out) > 0 || is_negative) {
        pdns_result_list_set_meta(out, query_type, result_source, false);
    }

    /* 5) 写入缓存（TTL 已由解析层钳制）：
     *    - 否定响应：写否定缓存（out 为空，is_negative=true），避免不存在的域名反复回源
     *    - 正常：有结果且成功/降级时写入 */
    if (client->enable_cache && client->cache) {
        bool cached = false;
        if (is_negative && client->max_negative_cache > 0) {
            /* 否定结论始终来自 HTTPDNS（服务端明确的无记录），此处 result_source
             * 必为 Public / Fusion 之一（不会是 LocalDNS：否定响应不走兜底） */
            pdns_cache_put(client->cache, host, query_type, out, ttl_final, true, result_source);
            cached = true;
        } else if (pdns_result_list_size(out) > 0 &&
                   (pdns_status_is_ok(&st) || from_localdns)) {
            /* result_source 同时供缓存层做覆盖保护（LocalDNS 不覆盖 HTTPDNS） */
            pdns_cache_put(client->cache, host, query_type, out, ttl_final, false, result_source);
            cached = true;
        }
        /* 保活 hook：写缓存即排期 TTL×0.75 刷新（含否定缓存） */
        if (cached) {
            pdns_keepalive_on_cache_write(client, host, query_type, ttl_final);
        }
        /* 测速触发：写入正常结果后异步测速并排序（否定结果不测） */
        if (cached && !is_negative && client->enable_speed_test &&
            pdns_result_list_size(out) > 0) {
            pdns_submit_speedtest(client, host, query_type, out, request_id, result_source);
        }
    }
    /* 回填请求追踪 ID（统一在返回前，避免被降级分支重置的 st 覆盖） */
    strncpy(st.request_id, request_id, PDNS_REQUEST_ID_LEN - 1);
    st.request_id[PDNS_REQUEST_ID_LEN - 1] = '\0';
    return st;
}

/*
 * 判断某 query_type 在当前网络栈下是否可达：
 *   - 双栈(DUAL)或未知(NONE)时放行
 *   - IPv4_ONLY 时跳过显式 IPv6 族
 *   - IPv6_ONLY 时跳过显式 IPv4 族
 * 用于 BOTH 拆分、测速触发、保活刷新等场景，避免对当前网络不可达的地址族做无意义请求/测速。
 */
static bool pdns_query_type_match_stack(pdns_query_type_t query_type,
                                        pdns_netstack_type_t stack) {
    if (stack == PDNS_STACK_DUAL || stack == PDNS_STACK_NONE) {
        return true;
    }
    if (stack == PDNS_STACK_IPV4_ONLY) {
        return query_type != PDNS_QUERY_IPV6;
    }
    if (stack == PDNS_STACK_IPV6_ONLY) {
        return query_type != PDNS_QUERY_IPV4;
    }
    return true;
}

/*
 * 双栈解析（query_type=BOTH）：服务端只支持单类型查询，故拆成 A/AAAA 两次单类型请求。
 * 分族查缓存，某族命中则直接复用，仅对缺失/过期族回源补齐；
 * 结果按 v4 在前、v6 在后合并到 out。调用前须已通过 ACL 校验（读缓存前拦截）。
 */
static pdns_status_t pdns_resolve_both(pdns_client_t *client, const char *host,
                                       pdns_scene_t scene, pdns_result_list_t *out) {
    pdns_result_list_t *v4 = pdns_result_list_create();
    pdns_result_list_t *v6 = pdns_result_list_create();
    bool v4_hit = false, v6_hit = false;

    /* 分族查缓存：命中族直接复用；信任窗口内的过期族（仅同步场景）用旧值+异步刷新。
     * 两族各自的 meta 由 pdns_cache_get / pdns_network_resolve 写入各自的临时列表，
     * 最终由 pdns_merge_both_sorted 搬到 out（各归其位，不会互盖）。 */
    if (client->enable_cache && client->cache) {
        pdns_cache_result_t c4 = pdns_cache_get(client->cache, host, PDNS_QUERY_IPV4, v4);
        if (c4 == PDNS_CACHE_HIT) {
            v4_hit = true;
        } else if ((c4 == PDNS_CACHE_HIT_SOON || c4 == PDNS_CACHE_STALE_TRUST) && scene == PDNS_SCENE_SYNC) {
            v4_hit = true;
            pdns_submit_async(client, host, PDNS_QUERY_IPV4, PDNS_SCENE_CACHE_ASYNC, NULL, NULL);
        } else {
            pdns_result_list_cleanup(v4);
            v4 = pdns_result_list_create();
        }
        pdns_cache_result_t c6 = pdns_cache_get(client->cache, host, PDNS_QUERY_IPV6, v6);
        if (c6 == PDNS_CACHE_HIT) {
            v6_hit = true;
        } else if ((c6 == PDNS_CACHE_HIT_SOON || c6 == PDNS_CACHE_STALE_TRUST) && scene == PDNS_SCENE_SYNC) {
            v6_hit = true;
            pdns_submit_async(client, host, PDNS_QUERY_IPV6, PDNS_SCENE_CACHE_ASYNC, NULL, NULL);
        } else {
            pdns_result_list_cleanup(v6);
            v6 = pdns_result_list_create();
        }
    }

    /* 仅对缺失/过期族回源补齐（只补缺失，不重查已命中族） */
    pdns_status_t st       = pdns_status_ok();
    pdns_status_t last_err = pdns_status_ok();
    bool          has_err  = false;
    if (!v4_hit) {
        pdns_status_t s = pdns_network_resolve(client, host, PDNS_QUERY_IPV4, scene, v4);
        if (pdns_status_is_ok(&s)) { st = s; } else { last_err = s; has_err = true; }
    }
    if (!v6_hit) {
        pdns_status_t s = pdns_network_resolve(client, host, PDNS_QUERY_IPV6, scene, v6);
        if (pdns_status_is_ok(&s)) { st = s; } else { last_err = s; has_err = true; }
    }

    /* 合并：默认 v4 在前（安全兜底）；测速开启且两族都有结果时按 effectiveKey 混排（v6 让分） */
    pdns_merge_both_sorted(client, host, v4, v6, out);
    pdns_result_list_cleanup(v4);
    pdns_result_list_cleanup(v6);

    /* 状态：结果为空且有子请求出错 → 返回该错误；否则 OK */
    if (pdns_result_list_size(out) == 0 && has_err) {
        return last_err;
    }
    return st;
}

/* ============================ 解析接口 ============================ */

/* 前向声明：后台异步任务提交（定义见下方异步解析区） */
static pdns_status_t pdns_submit_async(pdns_client_t *client,
                                       const char *host,
                                       pdns_query_type_t query_type,
                                       pdns_scene_t scene,
                                       pdns_resolve_callback_fn callback,
                                       void *user_data);

pdns_status_t pdns_resolve_sync_from_cache(pdns_client_t *client,
                                                       const char *host,
                                                       pdns_query_type_t query_type,
                                                       bool is_allow_exp,
                                                       pdns_result_list_t **results) {
    /* 空域名属调用方传参错误，须显式报错：若放行会落到 ACL 分支被判为
     * ACL_REJECTED，误导集成方去排查黑白名单配置。 */
    if (!client || !results || !host || host[0] == '\0') {
        return pdns_status_fail(1, "invalid argument");
    }
    *results = pdns_result_list_create();

    /* 黑白名单拦截（读缓存前校验）：
     * 命中则返回空结果，不读缓存、不触发后台刷新，防止黑名单域名从缓存拿到旧结果。 */
    if (!pdns_acl_is_normal_resolver(client->acl, host)) {
        PDNS_LOGI("acl reject cache read: host=%s, return empty", host);
        return pdns_acl_rejected_status();
    }

    if (!client->enable_cache || !client->cache) {
        return pdns_status_ok();
    }

    /* AUTO 根据网络栈归一，保证缓存 key 与回源一致 */
    query_type = resolve_query_type(client, query_type);

    /* 双栈：分族处理缓存（命中/信任窗口内→取旧值；过期超窗且允许→取；均异步刷新）。
     * 合并默认 v4 在前；测速开启且两族都有时按 effectiveKey 混排（v6 让分）。 */
    if (query_type == PDNS_QUERY_BOTH) {
        pdns_query_type_t   fams[2]    = { PDNS_QUERY_IPV4, PDNS_QUERY_IPV6 };
        pdns_result_list_t *fam_ips[2] = { NULL, NULL };
        for (int i = 0; i < 2; i++) {
            pdns_result_list_t *fam = pdns_result_list_create();
            pdns_cache_result_t fcr = pdns_cache_get(client->cache, host, fams[i], fam);
            if (fcr == PDNS_CACHE_HIT || fcr == PDNS_CACHE_HIT_SOON || fcr == PDNS_CACHE_STALE_TRUST ||
                (fcr == PDNS_CACHE_EXPIRED && is_allow_exp)) {
                fam_ips[i] = fam;
            } else {
                pdns_result_list_cleanup(fam);
            }
            if (fcr != PDNS_CACHE_HIT) {
                pdns_submit_async(client, host, fams[i], PDNS_SCENE_CACHE_ASYNC, NULL, NULL);
            }
        }
        pdns_merge_both_sorted(client, host, fam_ips[0], fam_ips[1], *results);
        pdns_result_list_cleanup(fam_ips[0]);
        pdns_result_list_cleanup(fam_ips[1]);
        return pdns_status_ok();
    }

    pdns_cache_result_t cr = pdns_cache_get(client->cache, host, query_type, *results);
    if (cr == PDNS_CACHE_HIT) {
        return pdns_status_ok();
    }
    /* 信任窗口内的过期值一律可返回；快到期也返回；超窗过期则看 is_allow_exp */
    if (cr == PDNS_CACHE_HIT_SOON || cr == PDNS_CACHE_STALE_TRUST || (cr == PDNS_CACHE_EXPIRED && is_allow_exp)) {
        /* 返回（可能过期的）旧值，同时后台异步刷新 */
        pdns_submit_async(client, host, query_type, PDNS_SCENE_CACHE_ASYNC, NULL, NULL);
        return pdns_status_ok();
    }
    /* 过期且不允许，或未命中：返回空，并触发后台异步刷新缓存。
     * 重建而非仅清 IP：本次放弃了缓存旧值，meta 也应随之归零为 UNKNOWN，
     * 不能留下 pdns_cache_get 刚刚写入的来源。 */
    pdns_result_list_cleanup(*results);
    *results = pdns_result_list_create();
    pdns_submit_async(client, host, query_type, PDNS_SCENE_CACHE_ASYNC, NULL, NULL);
    return pdns_status_ok();
}

pdns_status_t pdns_resolve_sync(pdns_client_t *client,
                                            const char *host,
                                            pdns_query_type_t query_type,
                                            pdns_result_list_t **results) {
    /* 空域名属传参错误，显式报错（理由同 sync_from_cache） */
    if (!client || !results || !host || host[0] == '\0') {
        return pdns_status_fail(1, "invalid argument");
    }
    *results = pdns_result_list_create();

    /* 黑白名单拦截（读缓存前校验）：命中则返回空结果，不读缓存、不回源，
     * 防止黑名单域名从缓存命中分支拿到旧结果。 */
    if (!pdns_acl_is_normal_resolver(client->acl, host)) {
        PDNS_LOGI("acl reject resolve: host=%s, return empty", host);
        return pdns_acl_rejected_status();
    }

    /* AUTO 根据网络栈归一 */
    query_type = resolve_query_type(client, query_type);

    /* 双栈：服务端只支持单类型，拆 v4/v6 两次解析（分族查缓存 + 缺失族补齐 + 合并） */
    if (query_type == PDNS_QUERY_BOTH) {
        return pdns_resolve_both(client, host, PDNS_SCENE_SYNC, *results);
    }

    /* 先查缓存：命中未过期直接返回；过期在信任窗口(30s)内返回旧值+异步刷新（不阻塞）；
     * 过期超窗或未命中则清空后同步回源 */
    if (client->enable_cache && client->cache) {
        pdns_cache_result_t cr = pdns_cache_get(client->cache, host, query_type, *results);
        if (cr == PDNS_CACHE_HIT) {
            return pdns_status_ok();
        }
        if (cr == PDNS_CACHE_HIT_SOON || cr == PDNS_CACHE_STALE_TRUST) {
            /* 快到期或过期在信任窗口内：先返回（旧）值，后台异步刷新，不阻塞用户 */
            pdns_submit_async(client, host, query_type, PDNS_SCENE_CACHE_ASYNC, NULL, NULL);
            return pdns_status_ok();
        }
        /* 未命中或过期超窗：清空后回源（重建以一并清掉 meta） */
        pdns_result_list_cleanup(*results);
        *results = pdns_result_list_create();
    }

    /* 回源 HTTPDNS（含 provider/节点选优 / SRTT 更新 / LocalDNS 降级 / 写缓存） */
    return pdns_network_resolve(client, host, query_type, PDNS_SCENE_SYNC, *results);
}

/* ============================ 异步解析 ============================ */

/* 异步任务上下文 */
typedef struct {
    pdns_client_t            *client;
    char                     *host;       /* 拷贝，worker 释放 */
    pdns_query_type_t         query_type;
    pdns_scene_t              scene;      /* 解析场景（驱动兜底策略与日志） */
    pdns_resolve_callback_fn  callback;   /* 可为 NULL（仅后台刷新缓存） */
    void                     *user_data;
} pdns_async_task_t;

/* 线程池 worker：先查缓存，未命中/过期则回源，完成后回调 */
static void *APR_THREAD_FUNC pdns_async_worker(apr_thread_t *thd, void *param) {
    (void) thd;
    pdns_async_task_t *task = (pdns_async_task_t *) param;
    pdns_client_t     *client = task->client;

    pdns_result_list_t *results = pdns_result_list_create();

    /* 先查缓存，命中未过期直接用；否则回源 */
    bool resolved = false;
    /* 黑白名单拦截（缓存读取校验）：命中则不查缓存、不回源，直接回调空结果 */
    bool acl_ok = pdns_acl_is_normal_resolver(client->acl, task->host);
    if (!acl_ok) {
        PDNS_LOGI("acl reject async: host=%s, return empty", task->host);
        resolved = true;   /* 跳过缓存与回源，results 保持为空 */
    } else if (task->query_type == PDNS_QUERY_BOTH) {
        /* 双栈：分族查缓存 + 缺失族补齐 + 合并 */
        pdns_resolve_both(client, task->host, task->scene, results);
        resolved = true;
    } else if (client->enable_cache && client->cache) {
        pdns_cache_result_t cr =
            pdns_cache_get(client->cache, task->host, task->query_type, results);
        if (cr == PDNS_CACHE_HIT) {
            resolved = true;
        } else {
            pdns_result_list_cleanup(results);
            results = pdns_result_list_create();
        }
    }
    if (!resolved) {
        pdns_network_resolve(client, task->host, task->query_type, task->scene, results);
    }

    if (task->callback != NULL) {
        task->callback(task->host, task->query_type, results, task->user_data);
    }

    pdns_result_list_cleanup(results);
    free(task->host);
    free(task);
    return NULL;
}

/* 将一个解析任务推入线程池 */
static pdns_status_t pdns_submit_async(pdns_client_t *client,
                                       const char *host,
                                       pdns_query_type_t query_type,
                                       pdns_scene_t scene,
                                       pdns_resolve_callback_fn callback,
                                       void *user_data) {
    if (!client->thread_pool) {
        return pdns_status_fail(1, "thread pool unavailable");
    }
    pdns_async_task_t *task = (pdns_async_task_t *) calloc(1, sizeof(pdns_async_task_t));
    if (!task) {
        return pdns_status_fail(1, "out of memory");
    }
    task->client     = client;
    task->host       = pdns_strdup(host);
    task->query_type = query_type;
    task->scene      = scene;
    task->callback   = callback;
    task->user_data  = user_data;

    /* 任务积压保护：待处理任务过多时拒收，
     * 避免极端场景（批量预解析 / 网络卡顿占满线程）下队列无限增长 */
    if (apr_thread_pool_tasks_count(client->thread_pool) > PDNS_TP_MAX_TASK_COUNT) {
        PDNS_LOGW("[并发控制] 异步任务积压过多(>%d) 拒收本次提交 host=%s",
                  PDNS_TP_MAX_TASK_COUNT, host);
        free(task->host);
        free(task);
        return pdns_status_fail(1, "too many async tasks");
    }

    /*
     * 按 scene 定优先级：解析池排队时先服务正在等回调的调用方，
     * 避免一批预解析把用户主动请求压在队尾。
     *   SYNC        用户主动 pdns_resolve_async，有人等结果   → HIGH
     *   CACHE_ASYNC 缓存快到期的后台刷新，旧值已返回       → NORMAL
     *   PRELOAD / TIMER 纯预热与保活，无人等待            → LOW
     */
    apr_byte_t prio;
    if (scene == PDNS_SCENE_SYNC) {
        prio = PDNS_PRIO_USER;
    } else if (scene == PDNS_SCENE_CACHE_ASYNC) {
        prio = PDNS_PRIO_REFRESH;
    } else {
        prio = PDNS_PRIO_PREHEAT;
    }

    apr_status_t rv = apr_thread_pool_push(client->thread_pool, pdns_async_worker,
                                           task, prio, NULL);
    if (rv != APR_SUCCESS) {
        free(task->host);
        free(task);
        return pdns_status_fail(1, "submit async task failed");
    }
    return pdns_status_ok();
}

pdns_status_t pdns_resolve_async(pdns_client_t *client,
                                             const char *host,
                                             pdns_query_type_t query_type,
                                             pdns_resolve_callback_fn callback,
                                             void *user_data) {
    if (!client || !host || host[0] == '\0') {
        return pdns_status_fail(1, "invalid argument");
    }
    return pdns_submit_async(client, host, resolve_query_type(client, query_type),
                             PDNS_SCENE_SYNC, callback, user_data);
}

/* ============================ 网络切换感知 ============================ */

/*
 * 网络切换感知由 pdns_net 检测器承担：
 *   - 后台轮询线程用本机 IP 集合对比判定切换（防抖动）
 *   - 切换时先重探网络栈，再通知所有订阅回调（如重置 SRTT）
 * 本层仅提供对外接口。
 */
void pdns_on_network_changed(void) {
    if (!g_pdns_enable_network_change) {
        return;
    }
    pdns_net_trigger_check(g_pdns_net_detector);
}

void pdns_set_enable_network_change(bool enable) {
    /* 全局开关：不依赖 client，运行期可随时开关轮询。 */
    g_pdns_enable_network_change = enable;
    pdns_net_detector_set_poll(g_pdns_net_detector, enable);
    PDNS_LOGI("setEnableNetworkChange:%s", enable ? "true" : "false");
}

void pdns_client_set_enable_short(pdns_client_t *client, bool enable) {
    if (client) client->enable_short = enable;
}

void pdns_client_set_enable_http2(pdns_client_t *client, bool enable) {
    if (client) client->enable_http2 = enable;
}

/* ============================ 预解析 / 保活 ============================ */

/*
 * 预解析单个域名的单一记录类型：
 *   - 未过期即跳过：HIT / HIT_SOON（即 age<ttl）时缓存仍有效，跳过；
 *     快到期缓存的续命由保活/读取路径异步刷新负责，非预解析职责；
 *   - 否则提交 scene=PRELOAD 的异步任务（无回调，结果只入缓存）。
 * ACL 校验、缓存命中判定由 pdns_async_worker 统一执行，此处仅做新鲜缓存预筛。
 */
static void pdns_preload_fire_one(pdns_client_t *client, const char *host,
                                  pdns_query_type_t qt) {
    if (client->enable_cache && client->cache) {
        pdns_result_list_t *tmp = pdns_result_list_create();
        pdns_cache_result_t cr = pdns_cache_get(client->cache, host, qt, tmp);
        pdns_result_list_cleanup(tmp);
        if (cr == PDNS_CACHE_HIT || cr == PDNS_CACHE_HIT_SOON) {
            PDNS_LOGD("preload skip (cache fresh): host=%s type=%s",
                      host, (qt == PDNS_QUERY_IPV6) ? "28" : "1");
            return;
        }
    }
    PDNS_LOGD("preload submit: host=%s type=%s scene=%s",
              host, (qt == PDNS_QUERY_IPV6) ? "28" : "1",
              pdns_scene_name(PDNS_SCENE_PRELOAD));
    pdns_submit_async(client, host, qt, PDNS_SCENE_PRELOAD, NULL, NULL);
}

/* 预解析单个域名：AUTO 按网络栈归一；BOTH 拆分为 v4/v6 两次单类型预解析
 * （服务端只支持单类型查询，缓存按族分键 host_1 / host_28）。 */
static void pdns_preload_fire_domain(pdns_client_t *client, const char *host,
                                     pdns_query_type_t qt) {
    if (host == NULL || host[0] == '\0') {
        return;
    }
    qt = resolve_query_type(client, qt);
    if (qt == PDNS_QUERY_BOTH) {
        pdns_preload_fire_one(client, host, PDNS_QUERY_IPV4);
        pdns_preload_fire_one(client, host, PDNS_QUERY_IPV6);
    } else {
        pdns_preload_fire_one(client, host, qt);
    }
}

/* 遍历域名链表逐个预解析（内部通用链表：既可是入参域名列表的 impl，
 * 也可是网络切换时的快照） */
static void pdns_preload_run(pdns_client_t *client, pdns_query_type_t qt,
                             const pdns_list_impl_t *domains) {
    size_t n = pdns_list_impl_size(domains);
    for (size_t i = 0; i < n; i++) {
        const char *host = pdns_list_impl_get(domains, i);
        pdns_preload_fire_domain(client, host, qt);
    }
}

/* 网络切换后按已登记的预解析集合重新预解析（快照后释放锁再触发，避免持锁回源） */
static void pdns_preload_again(pdns_client_t *client) {
    if (client == NULL || client->pre_load_lock == NULL) {
        return;
    }
    pdns_query_type_t qt = PDNS_QUERY_AUTO;
    pdns_list_impl_t *snapshot = NULL;
    apr_thread_mutex_lock(client->pre_load_lock);
    if (client->pre_load_domains != NULL &&
        pdns_list_impl_size(client->pre_load_domains) > 0) {
        qt = client->pre_load_qtype;
        snapshot = pdns_list_impl_clone(client->pre_load_domains);
    }
    apr_thread_mutex_unlock(client->pre_load_lock);
    if (snapshot != NULL) {
        PDNS_LOGI("preload again on network change: count=%zu",
                  pdns_list_impl_size(snapshot));
        pdns_preload_run(client, qt, snapshot);
        pdns_list_impl_destroy(snapshot);
    }
}

void pdns_client_add_pre_load_domains(pdns_client_t *client,
                                      pdns_query_type_t query_type,
                                      pdns_domain_list_t *domains) {
    if (client == NULL || domains == NULL || pdns_domain_list_size(domains) == 0) {
        return;
    }
    /* 登记预解析集合（去重累加 + 记录最近一次查询类型），供网络切换后重新预解析 */
    if (client->pre_load_lock != NULL) {
        apr_thread_mutex_lock(client->pre_load_lock);
        if (client->pre_load_domains == NULL) {
            client->pre_load_domains = pdns_list_impl_create();
        }
        client->pre_load_qtype = query_type;
        size_t n = pdns_domain_list_size(domains);
        for (size_t i = 0; i < n; i++) {
            const char *host = pdns_domain_list_get(domains, i);
            if (host == NULL || host[0] == '\0') {
                continue;
            }
            /* 去重：已登记则不重复追加 */
            bool dup = false;
            size_t m = pdns_list_impl_size(client->pre_load_domains);
            for (size_t j = 0; j < m; j++) {
                const char *exist = pdns_list_impl_get(client->pre_load_domains, j);
                if (exist != NULL && strcmp(exist, host) == 0) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                pdns_list_impl_add(client->pre_load_domains, host);
            }
        }
        apr_thread_mutex_unlock(client->pre_load_lock);
    }
    /* 立即触发一轮预解析 */
    PDNS_LOGI("add pre load domains: count=%zu type=%d",
              pdns_domain_list_size(domains), (int) query_type);
    pdns_preload_run(client, query_type, &domains->impl);
}

/* ============================ 保活域名（TTL×0.75 自循环刷新） ============================ */

/* 保活刷新系数（TTL 用掉 75% 时刷新） */
#define PDNS_KA_REFRESH_FACTOR 0.75

/*
 * 保活刷新 worker（到点执行）：
 *   1. 先清 pending 标记，使本次解析的写缓存能重新排期下一轮（闭环）；
 *   2. 回源解析 scene=TIMER → 写缓存 → hook 再次排期。
 * 域名被拉黑时 network_resolve 返回空且不写缓存 → 链自动终止（ACL 天然收敛）。
 */
static void *APR_THREAD_FUNC pdns_keepalive_worker(apr_thread_t *thd, void *param) {
    (void) thd;
    pdns_ka_slot_t *slot   = (pdns_ka_slot_t *) param;
    pdns_client_t  *client = slot->client;

    apr_thread_mutex_lock(client->keep_alive_lock);
    slot->pending = false;
    apr_thread_mutex_unlock(client->keep_alive_lock);

    PDNS_LOGI("keepalive refresh: host=%s type=%s scene=%s",
              slot->host, (slot->qtype == PDNS_QUERY_IPV6) ? "28" : "1",
              pdns_scene_name(PDNS_SCENE_TIMER));
    pdns_result_list_t *out = pdns_result_list_create();
    pdns_network_resolve(client, slot->host, slot->qtype, PDNS_SCENE_TIMER, out);
    pdns_result_list_cleanup(out);
    return NULL;
}

/*
 * 写缓存 hook：
 *   host 在保活列表 且 该 host+type 无 pending 任务 且 ttl>0
 *   → 排期 TTL×0.75 后的刷新任务（owner=client，供 cleanup 批量取消）。
 * 含否定缓存：否定 TTL×0.75 到点后刷新，域名恢复可解后及时替换否定结果。
 */
static void pdns_keepalive_on_cache_write(pdns_client_t *client, const char *host,
                                          pdns_query_type_t query_type, int ttl) {
    if (client == NULL || host == NULL || ttl <= 0 ||
        client->keep_alive_lock == NULL || client->keep_alive_count == 0) {
        return;
    }
    if (query_type != PDNS_QUERY_IPV4 && query_type != PDNS_QUERY_IPV6) {
        return;   /* network_resolve 层已归一为单类型，防御性拦截 */
    }
    apr_thread_mutex_lock(client->keep_alive_lock);
    pdns_ka_slot_t *slot = NULL;
    for (int i = 0; i < client->keep_alive_count; i++) {
        pdns_ka_slot_t *s = &client->keep_alive_slots[i * 2 +
                            ((query_type == PDNS_QUERY_IPV6) ? 1 : 0)];
        if (strcmp(s->host, host) == 0) {
            slot = s;
            break;
        }
    }
    if (slot == NULL || slot->pending) {
        apr_thread_mutex_unlock(client->keep_alive_lock);
        return;   /* 不在保活列表 / 已有保活链在跑（防重入） */
    }
    slot->pending = true;
    apr_thread_mutex_unlock(client->keep_alive_lock);

    apr_interval_time_t delay =
        (apr_interval_time_t) (ttl * PDNS_KA_REFRESH_FACTOR * 1000000.0);
    apr_status_t rv = apr_thread_pool_schedule(client->aux_pool,
                                               pdns_keepalive_worker, slot,
                                               delay, client /* owner */);
    if (rv != APR_SUCCESS) {
        apr_thread_mutex_lock(client->keep_alive_lock);
        slot->pending = false;
        apr_thread_mutex_unlock(client->keep_alive_lock);
        PDNS_LOGW("keepalive schedule failed: host=%s type=%s",
                  host, (query_type == PDNS_QUERY_IPV6) ? "28" : "1");
        return;
    }
    PDNS_LOGD("keepalive schedule: host=%s type=%s ttl=%d delay=%.1fs",
              host, (query_type == PDNS_QUERY_IPV6) ? "28" : "1",
              ttl, ttl * PDNS_KA_REFRESH_FACTOR);
}

void pdns_client_set_keep_alive_domains(pdns_client_t *client,
                                        pdns_domain_list_t *domains) {
    if (client == NULL || domains == NULL || pdns_domain_list_size(domains) == 0 ||
        client->keep_alive_lock == NULL) {
        return;
    }
    /* 仅登记域名集合（去重追加）：
     * 不解析、不排期；保活由后续“写缓存事件”触发（哪个 type 写缓存保活哪个 type） */
    apr_thread_mutex_lock(client->keep_alive_lock);
    size_t n = pdns_domain_list_size(domains);
    for (size_t i = 0; i < n; i++) {
        const char *host = pdns_domain_list_get(domains, i);
        if (host == NULL || host[0] == '\0' ||
            strlen(host) >= PDNS_KA_HOST_LEN) {
            continue;
        }
        /* 去重：已登记则跳过 */
        bool dup = false;
        for (int j = 0; j < client->keep_alive_count; j++) {
            if (strcmp(client->keep_alive_slots[j * 2].host, host) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) {
            continue;
        }
        if (client->keep_alive_count >= PDNS_KEEP_ALIVE_MAX) {
            PDNS_LOGW("keepalive domains exceed limit %d, ignore: %s",
                      PDNS_KEEP_ALIVE_MAX, host);
            continue;
        }
        /* 登记 v4/v6 两个 slot（缓存分族键，双栈各自独立保活链） */
        int idx = client->keep_alive_count;
        pdns_ka_slot_t *v4 = &client->keep_alive_slots[idx * 2];
        pdns_ka_slot_t *v6 = &client->keep_alive_slots[idx * 2 + 1];
        v4->client = client; v4->qtype = PDNS_QUERY_IPV4; v4->pending = false;
        v6->client = client; v6->qtype = PDNS_QUERY_IPV6; v6->pending = false;
        strncpy(v4->host, host, PDNS_KA_HOST_LEN - 1);
        strncpy(v6->host, host, PDNS_KA_HOST_LEN - 1);
        client->keep_alive_count++;
    }
    int total = client->keep_alive_count;
    apr_thread_mutex_unlock(client->keep_alive_lock);
    PDNS_LOGI("set keep alive domains: total=%d (max=%d)",
              total, PDNS_KEEP_ALIVE_MAX);
}

/* ============================ IP 测速与排序 ============================ */

/* 测速去重标记值（apr_hash 不能存 NULL 以外的“无”，用哨兵指针区分状态） */
#define PDNS_SPEEDING_ON  ((void *) 1)
#define PDNS_SPEEDING_OFF ((void *) 2)
/* 单条目混排快照容量上限 */
#define PDNS_SPEED_MAX_IPS 64

static void pdns_speed_key(char *buf, size_t n, const char *host,
                           pdns_query_type_t qt) {
    snprintf(buf, n, "%s_%d", host, (qt == PDNS_QUERY_IPV6) ? 28 : 1);
}

/* 尝试获取域名级测速标记；已在测返回 false */
static bool pdns_speeding_try_acquire(pdns_client_t *client, const char *key) {
    bool ok = false;
    apr_thread_mutex_lock(client->speed_lock);
    void *v = apr_hash_get(client->speeding, key, APR_HASH_KEY_STRING);
    if (v != PDNS_SPEEDING_ON) {
        if (v == NULL) {
            /* 首次登记：key 需持久内存（pool 分配，域名种类有限，量级受缓存上限约束） */
            apr_hash_set(client->speeding, apr_pstrdup(client->pool, key),
                         APR_HASH_KEY_STRING, PDNS_SPEEDING_ON);
        } else {
            /* entry 已存在：apr_hash_set 仅更新 value，保留原 key 指针 */
            apr_hash_set(client->speeding, key, APR_HASH_KEY_STRING, PDNS_SPEEDING_ON);
        }
        ok = true;
    }
    apr_thread_mutex_unlock(client->speed_lock);
    return ok;
}

static void pdns_speeding_release(pdns_client_t *client, const char *key) {
    apr_thread_mutex_lock(client->speed_lock);
    apr_hash_set(client->speeding, key, APR_HASH_KEY_STRING, PDNS_SPEEDING_OFF);
    apr_thread_mutex_unlock(client->speed_lock);
}

/* 测速任务上下文 */
typedef struct {
    pdns_client_t      *client;
    char               *host;   /* 拷贝，worker 释放 */
    pdns_query_type_t   qtype;
    pdns_result_list_t *ips;    /* 待测 IP 快照（即未测速前的解析顺序），worker 释放 */
    char               *rid;    /* 触发本次测速的解析 requestId，拷贝，worker 释放 */
    pdns_source_t       source; /* 本次结果的来源（日志用） */
} pdns_speed_task_t;

/*
 * 测速 worker：串行测每个 IP（3s×1次），
 * 逐个回写缓存 RTT，全部完成后条目内按 RTT 升序重排。
 */
static void *APR_THREAD_FUNC pdns_speed_worker(apr_thread_t *thd, void *param) {
    (void) thd;
    pdns_speed_task_t *task   = (pdns_speed_task_t *) param;
    pdns_client_t     *client = task->client;
    const char        *tname  = (task->qtype == PDNS_QUERY_IPV6) ? "28" : "1";

    size_t n = pdns_result_list_size(task->ips);
    PDNS_LOGD("speedtest begin: host=%s type=%s count=%zu port=%d",
              task->host, tname, n, client->speed_port);
    for (size_t i = 0; i < n; i++) {
        const char *ip = pdns_result_list_get(task->ips, i);
        if (ip == NULL || ip[0] == '\0') {
            continue;
        }
        float rtt = pdns_speedtest_tcp(ip, client->speed_port);
        pdns_cache_update_ip_rtt(client->cache, task->host, task->qtype, ip, rtt);
    }
    /* 测完排序回写（单条目内同族，纯 RTT 升序） */
    pdns_cache_sort_entry(client->cache, task->host, task->qtype);

    /* 测速完成后 dump 排序后条目 */
    {
        pdns_list_impl_t *dump_ips = pdns_list_impl_create();
        float             dump_rtts[PDNS_SPEED_MAX_IPS];
        size_t dn = pdns_cache_get_rtts(client->cache, task->host, task->qtype,
                                        dump_ips, dump_rtts, PDNS_SPEED_MAX_IPS);

        /* 未测速之前的解析 IP：提交测速时的快照顺序（';' 分隔），便于与下方
         * 测速后的排序结果逐条对照，直观看出测速对顺序的影响。 */
        char   raw_ips[512];
        size_t roff = 0;
        raw_ips[0]  = '\0';
        for (size_t i = 0; i < pdns_result_list_size(task->ips) && roff + 1 < sizeof(raw_ips); i++) {
            const char *rip = pdns_result_list_get(task->ips, i);
            if (rip == NULL || rip[0] == '\0') {
                continue;
            }
            int w = snprintf(raw_ips + roff, sizeof(raw_ips) - roff, "%s%s",
                             (roff > 0) ? ";" : "", rip);
            if (w <= 0 || (size_t) w >= sizeof(raw_ips) - roff) {
                break;   /* 缓冲不足即停，保留已拼接部分 */
            }
            roff += (size_t) w;
        }

        char buf[2048];
        int  off = snprintf(buf, sizeof(buf),
                            "speedtest cache dump =======domainModel\n"
                            "requestId:%s\n"
                            "域名:%s\n"
                            "域名解析类型：%s\n"
                            "域名解析的IP：%s\n"
                            "域名解析数据记录类型：type= %s\n",
                            (task->rid != NULL) ? task->rid : "-",
                            task->host,
                            pdns_source_name(task->source),
                            raw_ips, tname);
        for (size_t i = 0; i < dn && off > 0 && (size_t) off < sizeof(buf); i++) {
            off += snprintf(buf + off, sizeof(buf) - off,
                            "-- *-- |服务器ip = %s-- |服务器端口 = %d-- |rtt = %.1f|--*\n",
                            pdns_list_impl_get(dump_ips, i), client->speed_port, dump_rtts[i]);
        }
        if (off > 0 && (size_t) off < sizeof(buf)) {
            snprintf(buf + off, sizeof(buf) - off,
                     "------------------------------------------------------");
        }
        PDNS_LOGD("%s", buf);
        pdns_list_impl_destroy(dump_ips);
    }
    PDNS_LOGI("speedtest done: host=%s type=%s count=%zu (entry sorted)",
              task->host, tname, n);

    char key[300];
    pdns_speed_key(key, sizeof(key), task->host, task->qtype);
    pdns_speeding_release(client, key);

    free(task->host);
    free(task->rid);
    pdns_result_list_cleanup(task->ips);
    free(task);
    return NULL;
}

/* 写缓存后提交异步测速（去重 + RTT 复用后先排一次） */
static void pdns_submit_speedtest(pdns_client_t *client, const char *host,
                                  pdns_query_type_t query_type,
                                  const pdns_result_list_t *ips,
                                  const char *rid,
                                  pdns_source_t source) {
    if (client->aux_pool == NULL || client->cache == NULL ||
        !client->enable_cache || client->speed_lock == NULL) {
        return;
    }
    char key[300];
    pdns_speed_key(key, sizeof(key), host, query_type);
    if (!pdns_speeding_try_acquire(client, key)) {
        PDNS_LOGD("speedtest dedup skip: %s (already testing)", key);
        return;
    }
    /* RTT 复用已在 cache_put 完成；若存在复用值先按其排一次（全未测速时无变化） */
    pdns_cache_sort_entry(client->cache, host, query_type);

    /* 按当前网络栈过滤不可达族，避免 IPv4_ONLY 网络对 IPv6 地址做无意义测速（快速失败 9999）。
     * currentNetType 为 ipv4Only 时只测 v4，ipv6Only 时只测 v6。 */
    pdns_netstack_type_t stack = pdns_net_get_type(g_pdns_net_detector);
    if (!pdns_query_type_match_stack(query_type, stack)) {
        PDNS_LOGI("speedtest skip by stack: host=%s type=%s stack=%s",
                  host, (query_type == PDNS_QUERY_IPV6) ? "28" : "1",
                  pdns_netstack_name(stack));
        pdns_speeding_release(client, key);
        return;
    }

    pdns_speed_task_t *task = (pdns_speed_task_t *) calloc(1, sizeof(pdns_speed_task_t));
    if (task == NULL) {
        pdns_speeding_release(client, key);
        return;
    }
    task->client = client;
    task->host   = pdns_strdup(host);
    task->qtype  = query_type;
    task->ips    = pdns_result_list_clone(ips);
    task->rid    = (rid != NULL) ? pdns_strdup(rid) : NULL;
    task->source = source;
    if (task->host == NULL || task->ips == NULL ||
        apr_thread_pool_push(client->aux_pool, pdns_speed_worker, task, 0, NULL)
            != APR_SUCCESS) {
        pdns_speeding_release(client, key);
        free(task->host);
        free(task->rid);
        pdns_result_list_cleanup(task->ips);
        free(task);
    }
}

/*
 * 统一 effectiveKey（保证全序性）：
 *   未测速(rtt==5000)：key = 5000 + (v6 ? 0.5 : 0) —— v4 微量靠前、不施加让分；
 *   已测速(含超时 9999)：key = rtt - (v6 ? offset : 0) —— 正常施加 IPv6 让分。
 */
static float pdns_effective_key(float rtt, bool is_v6, int32_t offset) {
    if (rtt == PDNS_RTT_DEFAULT) {
        return PDNS_RTT_DEFAULT + (is_v6 ? 0.5f : 0.0f);
    }
    return rtt - (is_v6 ? (float) offset : 0.0f);
}

/* 把 v4 列表的 v4 族 meta、v6 列表的 v6 族 meta 分别搬到合并结果 out（各归其位，互不覆盖）。
 * BOTH 由两次单族解析拼成，故 v4 的来源信息在其 meta_v4、v6 的在其 meta_v6。 */
static void copy_family_meta(pdns_result_list_t *out,
                             const pdns_result_list_t *v4,
                             const pdns_result_list_t *v6) {
    const pdns_result_meta_t *m4 = pdns_result_list_meta(v4, PDNS_QUERY_IPV4);
    const pdns_result_meta_t *m6 = pdns_result_list_meta(v6, PDNS_QUERY_IPV6);
    if (m4 != NULL) {
        pdns_result_list_set_meta(out, PDNS_QUERY_IPV4, m4->source, m4->from_cache);
    }
    if (m6 != NULL) {
        pdns_result_list_set_meta(out, PDNS_QUERY_IPV6, m6->source, m6->from_cache);
    }
}

/* 顺序拼接（安全兜底：v4 在前）；同时把两族 meta 搬到 out（各归其位） */
static void merge_concat(const pdns_result_list_t *v4, const pdns_result_list_t *v6,
                         pdns_result_list_t *out) {
    for (size_t i = 0; i < pdns_result_list_size(v4); i++) {
        pdns_result_list_add(out, pdns_result_list_get(v4, i));
    }
    for (size_t i = 0; i < pdns_result_list_size(v6); i++) {
        pdns_result_list_add(out, pdns_result_list_get(v6, i));
    }
    copy_family_meta(out, v4, v6);
}

/*
 * 双栈合并：
 *   默认 v4 在前拼接（未开测速/单族/无 RTT 数据的保守兜底）；
 *   测速开启且两族都有结果时，按 effectiveKey 升序混排（v6 让分仅此处生效）。
 */
static void pdns_merge_both_sorted(pdns_client_t *client, const char *host,
                                   const pdns_result_list_t *v4,
                                   const pdns_result_list_t *v6,
                                   pdns_result_list_t *out) {
    size_t n4 = pdns_result_list_size(v4);
    size_t n6 = pdns_result_list_size(v6);
    if (!client->enable_speed_test || n4 == 0 || n6 == 0 ||
        !client->enable_cache || client->cache == NULL) {
        merge_concat(v4, v6, out);
        return;
    }
    /* 从缓存取两族 (ip,rtt) 快照（缓存为权威数据源） */
    pdns_list_impl_t *s4 = pdns_list_impl_create();
    pdns_list_impl_t *s6 = pdns_list_impl_create();
    float r4[PDNS_SPEED_MAX_IPS], r6[PDNS_SPEED_MAX_IPS];
    size_t m4 = pdns_cache_get_rtts(client->cache, host, PDNS_QUERY_IPV4, s4, r4, PDNS_SPEED_MAX_IPS);
    size_t m6 = pdns_cache_get_rtts(client->cache, host, PDNS_QUERY_IPV6, s6, r6, PDNS_SPEED_MAX_IPS);
    if (m4 == 0 || m6 == 0) {
        pdns_list_impl_destroy(s4);
        pdns_list_impl_destroy(s6);
        merge_concat(v4, v6, out);
        return;
    }
    /* 构建 (ip,key) 数组：v4 先入（稳定排序下同 key 时 v4 靠前），插入排序升序输出 */
    size_t      total = m4 + m6;
    const char *ips_arr[PDNS_SPEED_MAX_IPS * 2];
    float       keys[PDNS_SPEED_MAX_IPS * 2];
    int32_t     offset = client->speed_test_ipv6_prefer_ms;
    size_t      cnt = 0;
    for (size_t i = 0; i < m4; i++) {
        ips_arr[cnt] = pdns_list_impl_get(s4, i);
        keys[cnt]    = pdns_effective_key(r4[i], false, offset);
        cnt++;
    }
    for (size_t i = 0; i < m6; i++) {
        ips_arr[cnt] = pdns_list_impl_get(s6, i);
        keys[cnt]    = pdns_effective_key(r6[i], true, offset);
        cnt++;
    }
    for (size_t i = 1; i < total; i++) {
        const char *ip_cur  = ips_arr[i];
        float       key_cur = keys[i];
        size_t      j       = i;
        while (j > 0 && keys[j - 1] > key_cur) {
            keys[j]    = keys[j - 1];
            ips_arr[j] = ips_arr[j - 1];
            j--;
        }
        keys[j]    = key_cur;
        ips_arr[j] = ip_cur;
    }
    for (size_t i = 0; i < total; i++) {
        if (ips_arr[i]) {
            pdns_result_list_add(out, ips_arr[i]);
        }
    }
    copy_family_meta(out, v4, v6);
    PDNS_LOGD("both merge sorted: host=%s v4=%zu v6=%zu offset=%d",
              host, m4, m6, offset);
    pdns_list_impl_destroy(s4);
    pdns_list_impl_destroy(s6);
}

/* ============================ IP 选择 ============================ */

/* IP 字符串族判定：合法 IPv6 文本必含 ':'，IPv4 点分十进制必不含 */
static bool ip_is_v6(const char *ip) {
    return (ip != NULL) && (strchr(ip, ':') != NULL);
}

/*
 * 按 query_type 判定某个 IP 是否可选：
 *   IPV4 → 仅 v4；IPV6 → 仅 v6；BOTH/AUTO → 不过滤（双栈全接受）。
 * 注：AUTO 无需在此探测网络栈——解析入口 resolve_query_type 已按网络栈
 * 将 AUTO 归一为具体族，results 内容本身已符合当前网络环境。
 */
static bool ip_match_query_type(const char *ip, pdns_query_type_t query_type) {
    switch (query_type) {
        case PDNS_QUERY_IPV4:
            return !ip_is_v6(ip);
        case PDNS_QUERY_IPV6:
            return ip_is_v6(ip);
        case PDNS_QUERY_BOTH:
        case PDNS_QUERY_AUTO:
        default:
            return true;
    }
}

int pdns_select_ip_randomly(const pdns_result_list_t *results,
                            pdns_query_type_t query_type,
                            char *ip_out) {
    if (ip_out == NULL) {
        return 1;
    }
    size_t n = pdns_result_list_size(results);
    if (n == 0) {
        ip_out[0] = '\0';
        return 1;
    }
    /* 先按 query_type 筛出同族候选下标（保持原列表相对顺序），再在候选中随机 */
    size_t *cand = (size_t *) malloc(sizeof(size_t) * n);
    if (cand == NULL) {
        ip_out[0] = '\0';
        return 1;
    }
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        const char *cur = pdns_result_list_get(results, i);
        if (cur != NULL && ip_match_query_type(cur, query_type)) {
            cand[m++] = i;
        }
    }
    if (m == 0) {
        free(cand);
        ip_out[0] = '\0';
        return 1;
    }
    /* 生成 [0, m) 的随机下标。
     * 优先用系统随机源，不可用时以时间+地址扰动兜底。 */
    size_t pick = 0;
    if (m > 1) {
        apr_uint32_t rnd = 0;
        if (apr_generate_random_bytes((unsigned char *) &rnd, sizeof(rnd)) != APR_SUCCESS) {
            apr_uint64_t seed = (apr_uint64_t) apr_time_now() ^ (apr_uint64_t) (uintptr_t) ip_out;
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            rnd = (apr_uint32_t) (seed >> 32);
        }
        pick = (size_t) (rnd % m);
    }
    const char *ip = pdns_result_list_get(results, cand[pick]);
    free(cand);
    if (ip == NULL) {
        ip_out[0] = '\0';
        return 1;
    }
    strncpy(ip_out, ip, PDNS_IP_ADDRESS_STRING_LENGTH - 1);
    ip_out[PDNS_IP_ADDRESS_STRING_LENGTH - 1] = '\0';
    return PDNS_OK;
}

int pdns_select_ip_first(const pdns_result_list_t *results,
                         pdns_query_type_t query_type,
                         char *ip_out) {
    /* 取符合 query_type 的首个 IP；开启测速时列表已按 RTT 升序 / 双栈让分混排，
     * 故首个往往即最优；测速未完成或未开启时列表为服务端原序。 */
    if (ip_out == NULL) {
        return 1;
    }
    size_t n = pdns_result_list_size(results);
    for (size_t i = 0; i < n; i++) {
        const char *ip = pdns_result_list_get(results, i);
        if (ip != NULL && ip_match_query_type(ip, query_type)) {
            strncpy(ip_out, ip, PDNS_IP_ADDRESS_STRING_LENGTH - 1);
            ip_out[PDNS_IP_ADDRESS_STRING_LENGTH - 1] = '\0';
            return PDNS_OK;
        }
    }
    ip_out[0] = '\0';
    return 1;
}
