/*
 * DNS 服务提供者抽象基类实现
 *
 * 节点三分类、SRTT、失败惩罚、serverTtl 全部集中在本基类内。
 */
#include "pdns_base_provider.h"
#include "pdns_const.h"
#include "pdns_sign.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <apr_strings.h>   /* apr_pstrdup */

/* SRTT 算法常量 */
#define PDNS_SRTT_ALPHA_OLD   0.7f    /* 历史 SRTT 权重 */
#define PDNS_SRTT_ALPHA_NEW   0.3f    /* 本次 RTT 权重 */
#define PDNS_SRTT_PUNISH_MS   200.0f  /* 失败节点惩罚增量（毫秒） */
#define PDNS_SRTT_WEAKEN      0.98f   /* 其余节点衰减系数 */

/* ---------------- 构造 / 析构 ---------------- */

int pdns_base_provider_init(pdns_base_provider_t              *base,
                                const pdns_server_provider_vtbl_t *vtbl) {
    if (base == NULL || vtbl == NULL) {
        return 1;
    }
    memset(base, 0, sizeof(*base));
    base->vtbl = vtbl;
    if (apr_pool_create(&base->pool, NULL) != APR_SUCCESS) {
        return 1;
    }
    if (apr_thread_mutex_create(&base->lock, APR_THREAD_MUTEX_DEFAULT, base->pool)
        != APR_SUCCESS) {
        apr_pool_destroy(base->pool);
        base->pool = NULL;
        return 1;
    }
    return 0;
}

void pdns_base_provider_destroy(pdns_base_provider_t *base) {
    if (base == NULL) {
        return;
    }
    if (base->lock != NULL) {
        apr_thread_mutex_destroy(base->lock);
        base->lock = NULL;
    }
    if (base->pool != NULL) {
        apr_pool_destroy(base->pool);
        base->pool = NULL;
    }
}

/* ---------------- 鉴权 ---------------- */

int pdns_base_provider_set_auth(pdns_base_provider_t *base,
                                    const char *account_id,
                                    const char *access_key_id,
                                    const char *access_key_secret) {
    if (base == NULL) {
        return 1;
    }
    /* 三者须全非空：「鉴权不全则 Provider 不启用」，不存在部分鉴权状态 */
    if (account_id == NULL || account_id[0] == '\0' ||
        access_key_id == NULL || access_key_id[0] == '\0' ||
        access_key_secret == NULL || access_key_secret[0] == '\0') {
        return 1;
    }
    apr_thread_mutex_lock(base->lock);
    /* 字符串由 base->pool 分配，随 provider 回收。重复设置（更新鉴权）时旧串留在
     * pool 内不单独释放，量级为几十字节且通常只设一次，可忽略。 */
    base->account_id        = apr_pstrdup(base->pool, account_id);
    base->access_key_id     = apr_pstrdup(base->pool, access_key_id);
    base->access_key_secret = apr_pstrdup(base->pool, access_key_secret);
    apr_thread_mutex_unlock(base->lock);
    return 0;
}

bool pdns_base_provider_is_account_auth_available(pdns_base_provider_t *base) {
    if (base == NULL) {
        return false;
    }
    apr_thread_mutex_lock(base->lock);
    bool ok = base->account_id && base->account_id[0] &&
              base->access_key_id && base->access_key_id[0] &&
              base->access_key_secret && base->access_key_secret[0];
    apr_thread_mutex_unlock(base->lock);
    return ok;
}

bool pdns_base_provider_is_server_available(pdns_base_provider_t *base) {
    if (base == NULL) {
        return false;
    }
    apr_thread_mutex_lock(base->lock);
    bool ok = (base->v4_count > 0) || (base->v6_count > 0) || (base->host_count > 0);
    apr_thread_mutex_unlock(base->lock);
    return ok;
}

/* 鉴权只读访问器：鉴权一旦 set 就不再变更（仅 init 入口写一次），
 * 故这里取指针不需要持锁，返回后也不会被释放。 */
const char *pdns_base_provider_account_id(pdns_base_provider_t *base) {
    return (base != NULL) ? base->account_id : NULL;
}

const char *pdns_base_provider_access_key_id(pdns_base_provider_t *base) {
    return (base != NULL) ? base->access_key_id : NULL;
}

const char *pdns_base_provider_access_key_secret(pdns_base_provider_t *base) {
    return (base != NULL) ? base->access_key_secret : NULL;
}

/*
 * 该类型是否有「存活」节点。已熔断（is_alive=false）者不计入。持锁调用。
 */
static bool has_alive(const pdns_server_ip_model_t *arr, int count) {
    for (int i = 0; i < count; i++) {
        if (arr[i].is_alive) {
            return true;
        }
    }
    return false;
}

bool pdns_base_provider_has_active_servers(pdns_base_provider_t *base,
                                               pdns_netstack_type_t stack,
                                               bool enable_ipv6) {
    if (base == NULL) {
        return false;
    }
    apr_thread_mutex_lock(base->lock);
    bool has_v4   = has_alive(base->v4, base->v4_count);
    bool has_v6   = has_alive(base->v6, base->v6_count);
    bool has_host = has_alive(base->host, base->host_count);
    apr_thread_mutex_unlock(base->lock);

    /* 按网络栈判定 */
    switch (stack) {
        case PDNS_STACK_IPV6_ONLY:
            return has_v6 || has_host;
        case PDNS_STACK_IPV4_ONLY:
            return has_v4 || has_host;
        case PDNS_STACK_DUAL:
            return enable_ipv6 ? (has_v6 || has_v4 || has_host) : (has_v4 || has_host);
        default:
            return has_v4 || has_host;
    }
}

/* ---------------- 节点装载 ---------------- */

/* 追加一个节点并初始化状态（SRTT 归零、标记存活）。 */
static void add_node(pdns_server_ip_model_t *arr, int *count,
                     const char *ip, pdns_svr_ip_type_t type) {
    if (*count >= PDNS_MAX_NODES_PER_TYPE || ip == NULL || ip[0] == '\0') {
        return;
    }
    pdns_server_ip_model_t *n = &arr[(*count)++];
    memset(n, 0, sizeof(*n));
    strncpy(n->ip, ip, sizeof(n->ip) - 1);
    n->ip[sizeof(n->ip) - 1] = '\0';
    n->type     = type;
    n->srtt     = 0.0f;
    n->is_alive = true;
}

void pdns_base_provider_setup_servers(pdns_base_provider_t *base,
                                          const char *const *v4, int v4_count,
                                          const char *const *v6, int v6_count,
                                          const char *const *host, int host_count) {
    if (base == NULL) {
        return;
    }
    apr_thread_mutex_lock(base->lock);
    base->v4_count = base->v6_count = base->host_count = 0;
    for (int i = 0; i < v4_count && v4 != NULL; i++) {
        add_node(base->v4, &base->v4_count, v4[i], PDNS_SVR_IP_TYPE_V4);
    }
    for (int i = 0; i < v6_count && v6 != NULL; i++) {
        add_node(base->v6, &base->v6_count, v6[i], PDNS_SVR_IP_TYPE_V6);
    }
    for (int i = 0; i < host_count && host != NULL; i++) {
        add_node(base->host, &base->host_count, host[i], PDNS_SVR_IP_TYPE_HOST);
    }
    int nv4 = base->v4_count, nv6 = base->v6_count, nhost = base->host_count;
    apr_thread_mutex_unlock(base->lock);
    PDNS_LOGD("provider setup servers: v4=%d v6=%d host=%d", nv4, nv6, nhost);
}

/* ---------------- 选点 ---------------- */

/* getScoreIpModel：数组内取 SRTT 最优（srtt==0 未测量者优先，保证被探测）。
 * 已熔断节点不参与调度。持锁调用。 */
static pdns_server_ip_model_t *get_score_ip(pdns_server_ip_model_t *arr, int count) {
    int   best_idx  = -1;
    float best_srtt = 0.0f;
    for (int i = 0; i < count; i++) {
        if (!arr[i].is_alive) {
            continue;
        }
        float s = arr[i].srtt;
        if (s == 0.0f) {
            return &arr[i];
        }
        if (best_idx < 0 || s < best_srtt) {
            best_srtt = s;
            best_idx  = i;
        }
    }
    return (best_idx >= 0) ? &arr[best_idx] : NULL;
}

/* getServerIPWithType：按类型取该数组最优节点 IP。
 *   - V4 / V6：返回具体 IP（空数组返回 NULL）
 *   - HOST：返回 NULL，由上层走系统 DNS 解析服务域名（不做 IP 直连）
 * 持锁调用。 */
static const char *get_server_by_type(pdns_base_provider_t *base, pdns_svr_ip_type_t type) {
    pdns_server_ip_model_t *arr;
    int                         count;
    switch (type) {
        case PDNS_SVR_IP_TYPE_V6:
            arr   = base->v6;
            count = base->v6_count;
            break;
        case PDNS_SVR_IP_TYPE_HOST:
            return NULL;
        case PDNS_SVR_IP_TYPE_V4:
        default:
            arr   = base->v4;
            count = base->v4_count;
            break;
    }
    pdns_server_ip_model_t *n = get_score_ip(arr, count);
    return (n != NULL) ? n->ip : NULL;
}

const char *pdns_base_provider_get_server_ip_with_request_count(
        pdns_base_provider_t *base, pdns_netstack_type_t stack,
        bool enable_ipv6, int request_count, bool *out_is_host) {
    if (out_is_host != NULL) {
        *out_is_host = false;
    }
    if (base == NULL) {
        return NULL;
    }
    apr_thread_mutex_lock(base->lock);

    /* 「有该类型节点」须按存活判定：整类节点全被熔断时不应再选该类型，
     * 否则选中后取不到节点而返回 NULL，白白消耗一次重试。 */
    bool has_v4   = has_alive(base->v4, base->v4_count);
    bool has_v6   = has_alive(base->v6, base->v6_count);
    bool has_host = has_alive(base->host, base->host_count);

    /* getServerIPWithRequestCount：先决定 type，再按类型取最优节点 */
    pdns_svr_ip_type_t type;
    if (request_count >= PDNS_RETRY_COUNT) {
        /* 达到重试阈值：切 HOST 域名兜底（无 host 节点则退回 V4）。
         * 公共 DNS 恒有 host 节点（dns.alidns.com），因此回退分支只会在自建
         * 触发——调用方可能只配了 IP 节点，此时末次重试继续用 IP 比直接放弃更好。 */
        type = has_host ? PDNS_SVR_IP_TYPE_HOST : PDNS_SVR_IP_TYPE_V4;
    } else {
        switch (stack) {
            case PDNS_STACK_IPV6_ONLY:
                type = has_v6 ? PDNS_SVR_IP_TYPE_V6 : PDNS_SVR_IP_TYPE_HOST;
                break;
            case PDNS_STACK_IPV4_ONLY:
                type = has_v4 ? PDNS_SVR_IP_TYPE_V4 : PDNS_SVR_IP_TYPE_HOST;
                break;
            case PDNS_STACK_DUAL:
                /* 双栈：仅首次且 enable_ipv6 时优先 v6（v6→host→v4），其余取 v4 */
                if (request_count == 0 && enable_ipv6) {
                    type = has_v6 ? PDNS_SVR_IP_TYPE_V6
                                  : (has_host ? PDNS_SVR_IP_TYPE_HOST : PDNS_SVR_IP_TYPE_V4);
                } else {
                    type = has_v4 ? PDNS_SVR_IP_TYPE_V4 : PDNS_SVR_IP_TYPE_HOST;
                }
                break;
            default:      /* NONE 兜底：优先 HOST 域名 */
                type = has_host ? PDNS_SVR_IP_TYPE_HOST : PDNS_SVR_IP_TYPE_V4;
                break;
        }
    }

    const char *ip = get_server_by_type(base, type);
    /* HOST 兜底须与「该类型无可用节点」区分：前者是正常策略，后者是无节点可用 */
    if (out_is_host != NULL) {
        *out_is_host = (type == PDNS_SVR_IP_TYPE_HOST) && has_host;
    }

    apr_thread_mutex_unlock(base->lock);
    return ip;
}

/* 前向声明（定义在 SRTT 章节） */
static int collect_arrays(pdns_base_provider_t *base,
                          pdns_server_ip_model_t *arrs[], int counts[]);

float pdns_base_provider_get_node_srtt(pdns_base_provider_t *base, const char *node_ip) {
    if (base == NULL || node_ip == NULL) {
        return 0.0f;
    }
    float srtt = 0.0f;
    apr_thread_mutex_lock(base->lock);
    /* find_node 定义在熔断章节，此处改用内联查找以避免前向声明 */
    pdns_server_ip_model_t *arrs[3];
    int                         counts[3];
    int                         groups = collect_arrays(base, arrs, counts);
    for (int g = 0; g < groups; g++) {
        for (int i = 0; i < counts[g]; i++) {
            if (strcmp(arrs[g][i].ip, node_ip) == 0) {
                srtt = arrs[g][i].srtt;
                apr_thread_mutex_unlock(base->lock);
                return srtt;
            }
        }
    }
    apr_thread_mutex_unlock(base->lock);
    return srtt;
}

/* ---------------- SRTT ---------------- */

/*
 * 取本 provider 的名称用于日志（"PublicDNS" / "FusionDNS"）。
 * 基类 → 接口的向上转型，合法性同 pdns_base_of 的反向：基类首成员即 vtbl，
 * 而接口对象也只有 vtbl，两者地址等价。provider_name 只返回字符串字面量、
 * 不触碰实例状态，故在持锁区内调用亦安全。
 */
static const char *base_source_name(pdns_base_provider_t *base) {
    return pdns_provider_name((pdns_server_provider_t *) base);
}

/* 收集三类节点数组，便于 SRTT 类操作统一遍历。持锁调用。 */
static int collect_arrays(pdns_base_provider_t *base,
                          pdns_server_ip_model_t *arrs[], int counts[]) {
    arrs[0]   = base->v4;   counts[0] = base->v4_count;
    arrs[1]   = base->v6;   counts[1] = base->v6_count;
    arrs[2]   = base->host; counts[2] = base->host_count;
    return 3;
}

void pdns_base_provider_update_srtt(pdns_base_provider_t *base,
                                        const char *server_ip, long rtt_ms) {
    if (base == NULL || server_ip == NULL) {
        return;
    }
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *arrs[3];
    int                         counts[3];
    int                         groups = collect_arrays(base, arrs, counts);
    for (int g = 0; g < groups; g++) {
        for (int i = 0; i < counts[g]; i++) {
            if (strcmp(arrs[g][i].ip, server_ip) == 0) {
                float last = arrs[g][i].srtt;
                if (last <= 0.0f) {
                    arrs[g][i].srtt = (float) rtt_ms;
                } else {
                    arrs[g][i].srtt =
                        last * PDNS_SRTT_ALPHA_OLD + (float) rtt_ms * PDNS_SRTT_ALPHA_NEW;
                }
                PDNS_LOGD("provider srtt update: source=%s ip=%s rtt=%ldms srtt=%.1f",
                          base_source_name(base), server_ip, rtt_ms, arrs[g][i].srtt);
                apr_thread_mutex_unlock(base->lock);
                return;
            }
        }
    }
    apr_thread_mutex_unlock(base->lock);
}

void pdns_base_provider_punish(pdns_base_provider_t *base, const char *server_ip) {
    if (base == NULL || server_ip == NULL) {
        return;
    }
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *arrs[3];
    int                         counts[3];
    int                         groups = collect_arrays(base, arrs, counts);
    for (int g = 0; g < groups; g++) {
        for (int i = 0; i < counts[g]; i++) {
            float last = arrs[g][i].srtt;
            if (strcmp(arrs[g][i].ip, server_ip) == 0) {
                arrs[g][i].srtt = last + PDNS_SRTT_PUNISH_MS;   /* 失败节点 +200ms */
                PDNS_LOGD("provider punish: source=%s ip=%s srtt=%.1f->%.1f",
                          base_source_name(base), server_ip, last, arrs[g][i].srtt);
            } else {
                arrs[g][i].srtt = last * PDNS_SRTT_WEAKEN;      /* 其余节点 ×0.98 */
            }
        }
    }
    apr_thread_mutex_unlock(base->lock);
}

void pdns_base_provider_reset_srtt(pdns_base_provider_t *base) {
    if (base == NULL) {
        return;
    }
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *arrs[3];
    int                         counts[3];
    int                         groups = collect_arrays(base, arrs, counts);
    for (int g = 0; g < groups; g++) {
        for (int i = 0; i < counts[g]; i++) {
            arrs[g][i].srtt = 0.0f;
            /*
             * 网络切换时一并解除熔断：熔断是基于旧网络环境得出的结论，新网络下必须
             * 重新评估。不清的后果是真实的：熔断仅对自建生效，而自建没有服务端下发
             * 的优选列表（不走 tempip 合并，不会重建节点数组），若不在此复位，切网后只能
             * 等下一轮 60s 探测才能恢复。
             * 注：这是一处主动增强，熔断的触发与恢复规则本身仍保持原有语义。
             */
            arrs[g][i].is_alive                  = true;
            arrs[g][i].consecutive_failure_count = 0;
            arrs[g][i].consecutive_success_count = 0;
        }
    }
    PDNS_LOGD("provider reset srtt: source=%s", base_source_name(base));
    apr_thread_mutex_unlock(base->lock);
}

/* ---------------- 服务端下发优选节点合并 ---------------- */

/* 在旧节点快照中按 IP 查历史 SRTT，未命中返回 0（复用测速）。 */
static float find_old_srtt(const pdns_server_ip_model_t *old, int old_count, const char *ip) {
    for (int i = 0; i < old_count; i++) {
        if (strcmp(old[i].ip, ip) == 0) {
            return old[i].srtt;
        }
    }
    return 0.0f;
}

/* 目标数组中是否已存在该 IP（合并默认节点时去重）。 */
static bool arr_contains(const pdns_server_ip_model_t *arr, int count, const char *ip) {
    for (int i = 0; i < count; i++) {
        if (strcmp(arr[i].ip, ip) == 0) {
            return true;
        }
    }
    return false;
}

/* 追加节点并设置 SRTT（inherit=true 继承旧值，否则归零）。 */
static void add_merged(pdns_server_ip_model_t *arr, int *count, const char *ip,
                       pdns_svr_ip_type_t type,
                       const pdns_server_ip_model_t *old, int old_count, bool inherit) {
    if (*count >= PDNS_MAX_NODES_PER_TYPE || ip == NULL || ip[0] == '\0') {
        return;
    }
    if (arr_contains(arr, *count, ip)) {
        return;
    }
    pdns_server_ip_model_t *n = &arr[(*count)++];
    memset(n, 0, sizeof(*n));
    strncpy(n->ip, ip, sizeof(n->ip) - 1);
    n->ip[sizeof(n->ip) - 1] = '\0';
    n->type     = type;
    n->is_alive = true;
    n->srtt     = inherit ? find_old_srtt(old, old_count, ip) : 0.0f;
}

/* 重建单类型数组：先服务端下发节点，再补默认 bootstrap 节点（去重）。持锁调用。 */
static void merge_one(pdns_server_ip_model_t *arr, int *count, pdns_svr_ip_type_t type,
                      const char *const *server, int server_count,
                      const char *const *defs, int def_count, bool inherit) {
    /* 先快照旧节点用于 SRTT 继承（arr 即将被覆盖） */
    pdns_server_ip_model_t old[PDNS_MAX_NODES_PER_TYPE];
    int                        old_count = *count;
    if (old_count > PDNS_MAX_NODES_PER_TYPE) {
        old_count = PDNS_MAX_NODES_PER_TYPE;
    }
    memcpy(old, arr, sizeof(pdns_server_ip_model_t) * old_count);

    *count = 0;
    for (int i = 0; i < server_count && server != NULL; i++) {
        add_merged(arr, count, server[i], type, old, old_count, inherit);
    }
    for (int i = 0; i < def_count && defs != NULL; i++) {
        add_merged(arr, count, defs[i], type, old, old_count, inherit);
    }
}

void pdns_base_provider_merge_server_list(pdns_base_provider_t *base,
                                              const char *const *v4, int v4_count,
                                              const char *const *v6, int v6_count,
                                              const char *const *host, int host_count,
                                              const char *const *def_v4, int def_v4_count,
                                              const char *const *def_v6, int def_v6_count,
                                              const char *const *def_host, int def_host_count,
                                              int ttl_sec, bool inherit_srtt) {
    if (base == NULL) {
        return;
    }
    apr_thread_mutex_lock(base->lock);
    merge_one(base->v4, &base->v4_count, PDNS_SVR_IP_TYPE_V4,
              v4, v4_count, def_v4, def_v4_count, inherit_srtt);
    merge_one(base->v6, &base->v6_count, PDNS_SVR_IP_TYPE_V6,
              v6, v6_count, def_v6, def_v6_count, inherit_srtt);
    merge_one(base->host, &base->host_count, PDNS_SVR_IP_TYPE_HOST,
              host, host_count, def_host, def_host_count, inherit_srtt);
    if (ttl_sec <= 0) {
        ttl_sec = PDNS_SERVER_DEFAULT_TTL;
    }
    base->server_expire_at = apr_time_now() + (apr_time_t) ttl_sec * APR_USEC_PER_SEC;
    int nv4 = base->v4_count, nv6 = base->v6_count, nhost = base->host_count;
    apr_thread_mutex_unlock(base->lock);
    PDNS_LOGI("provider merge server list: v4=%d v6=%d host=%d ttl=%ds inherit=%d",
              nv4, nv6, nhost, ttl_sec, inherit_srtt);
}

bool pdns_base_provider_is_server_ip_expired(pdns_base_provider_t *base) {
    if (base == NULL) {
        return false;
    }
    apr_thread_mutex_lock(base->lock);
    apr_time_t exp = base->server_expire_at;
    apr_thread_mutex_unlock(base->lock);
    if (exp == 0) {
        return false;   /* 尚未成功下发过：交由启动流程首拉，避免解析路径反复拉取 */
    }
    return apr_time_now() >= exp;
}

void pdns_base_provider_touch_server_expire(pdns_base_provider_t *base, int ttl_sec) {
    if (base == NULL) {
        return;
    }
    if (ttl_sec <= 0) {
        ttl_sec = PDNS_SERVER_DEFAULT_TTL;
    }
    apr_thread_mutex_lock(base->lock);
    base->server_expire_at = apr_time_now() + (apr_time_t) ttl_sec * APR_USEC_PER_SEC;
    apr_thread_mutex_unlock(base->lock);
}

/* ---------------- 熔断与健康检查 ---------------- */

/* 在三类节点中按 IP 查找节点。持锁调用；未命中返回 NULL。 */
static pdns_server_ip_model_t *find_node(pdns_base_provider_t *base,
                                             const char *node_ip) {
    pdns_server_ip_model_t *arrs[3];
    int                         counts[3];
    int                         groups = collect_arrays(base, arrs, counts);
    for (int g = 0; g < groups; g++) {
        for (int i = 0; i < counts[g]; i++) {
            if (strcmp(arrs[g][i].ip, node_ip) == 0) {
                return &arrs[g][i];
            }
        }
    }
    return NULL;
}

bool pdns_base_provider_record_node_failure(pdns_base_provider_t *base,
                                                const char *node_ip) {
    if (base == NULL || node_ip == NULL) {
        return false;
    }
    bool just_broken = false;
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *n = find_node(base, node_ip);
    if (n != NULL) {
        n->consecutive_failure_count++;
        n->consecutive_success_count = 0;   /* 成功链中断 */
        n->last_failed_time          = apr_time_now();
        /* 仅在「从存活转为熔断」的那一刻返回 true，避免重复告警 */
        if (n->is_alive && n->consecutive_failure_count >= PDNS_MIN_CONSECUTIVE_FAILURES) {
            n->is_alive = false;
            just_broken = true;
        }
    }
    int fail_count = (n != NULL) ? n->consecutive_failure_count : 0;
    apr_thread_mutex_unlock(base->lock);

    if (just_broken) {
        PDNS_LOGW("provider circuit break: source=%s node=%s consecutive_failures=%d",
                  base_source_name(base), node_ip, fail_count);
    }
    return just_broken;
}

void pdns_base_provider_record_node_success(pdns_base_provider_t *base,
                                                const char *node_ip) {
    if (base == NULL || node_ip == NULL) {
        return;
    }
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *n = find_node(base, node_ip);
    if (n != NULL) {
        n->consecutive_failure_count = 0;   /* 失败链中断 */
        n->consecutive_success_count++;
    }
    apr_thread_mutex_unlock(base->lock);
}

int pdns_base_provider_collect_broken_nodes(
        pdns_base_provider_t *base, pdns_netstack_type_t stack,
        char out_ips[][PDNS_IP_ADDRESS_STRING_LENGTH], int max_out) {
    if (base == NULL || out_ips == NULL || max_out <= 0) {
        return 0;
    }
    /* 按栈决定探哪几类：host 节点任何栈下都要探。 */
    bool probe_v4 = (stack != PDNS_STACK_IPV6_ONLY);
    bool probe_v6 = (stack == PDNS_STACK_IPV6_ONLY) || (stack == PDNS_STACK_DUAL);

    int n_out = 0;
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *arrs[3];
    int                         counts[3];
    int                         groups = collect_arrays(base, arrs, counts);
    /* collect_arrays 的顺序：0=v4、1=v6、2=host */
    const bool want[3] = { probe_v4, probe_v6, true };
    for (int g = 0; g < groups && n_out < max_out; g++) {
        if (!want[g]) {
            continue;
        }
        for (int i = 0; i < counts[g] && n_out < max_out; i++) {
            if (!arrs[g][i].is_alive) {
                strncpy(out_ips[n_out], arrs[g][i].ip, PDNS_IP_ADDRESS_STRING_LENGTH - 1);
                out_ips[n_out][PDNS_IP_ADDRESS_STRING_LENGTH - 1] = '\0';
                n_out++;
            }
        }
    }
    apr_thread_mutex_unlock(base->lock);
    return n_out;
}

bool pdns_base_provider_record_probe_result(pdns_base_provider_t *base,
                                                const char *node_ip, bool success) {
    if (base == NULL || node_ip == NULL) {
        return false;
    }
    bool recovered = false;
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *n = find_node(base, node_ip);
    if (n != NULL) {
        if (success) {
            n->consecutive_success_count++;
            n->consecutive_failure_count = 0;
            if (!n->is_alive &&
                n->consecutive_success_count >= PDNS_MIN_CONSECUTIVE_SUCCESS) {
                n->is_alive                  = true;
                n->consecutive_success_count = 0;
                /* srtt 归零：get_score_ip 对未测量节点优先返回，
                 * 使刚恢复的节点优先被真实请求验证一次。 */
                n->srtt     = 0.0f;
                recovered   = true;
            }
        } else {
            n->consecutive_success_count = 0;   /* 保持熔断，等下一轮探测 */
        }
    }
    apr_thread_mutex_unlock(base->lock);

    if (recovered) {
        PDNS_LOGI("provider circuit recover: source=%s node=%s",
                  base_source_name(base), node_ip);
    }
    return recovered;
}

bool pdns_base_provider_has_broken_nodes(pdns_base_provider_t *base) {
    if (base == NULL) {
        return false;
    }
    bool found = false;
    apr_thread_mutex_lock(base->lock);
    pdns_server_ip_model_t *arrs[3];
    int                         counts[3];
    int                         groups = collect_arrays(base, arrs, counts);
    for (int g = 0; g < groups && !found; g++) {
        for (int i = 0; i < counts[g]; i++) {
            if (!arrs[g][i].is_alive) {
                found = true;
                break;
            }
        }
    }
    apr_thread_mutex_unlock(base->lock);
    return found;
}

const char *pdns_base_provider_alive_host_node(pdns_base_provider_t *base) {
    if (base == NULL) {
        return NULL;
    }
    apr_thread_mutex_lock(base->lock);
    /* 走 get_score_ip 而非直接取 host[0]：后者会选中已熔断的节点。
     * 返回指针指向节点数组内部，生命周期随 provider（同 node_ip 的约定）。 */
    pdns_server_ip_model_t *n = get_score_ip(base->host, base->host_count);
    const char                 *ip = (n != NULL) ? n->ip : NULL;
    apr_thread_mutex_unlock(base->lock);
    return ip;
}

/* ---------------- 鉴权 path ---------------- */

int pdns_base_provider_build_auth_url_path(pdns_base_provider_t *base,
                                               const char *ascii_host,
                                               const char *type_str,
                                               const char *session_id,
                                               const char *ecs,
                                               bool        enable_short,
                                               char *out, size_t out_len) {
    if (base == NULL || ascii_host == NULL || type_str == NULL || out == NULL || out_len == 0) {
        return 1;
    }
    apr_thread_mutex_lock(base->lock);
    const char *uid = base->account_id;
    const char *ak  = base->access_key_id;
    const char *sk  = base->access_key_secret;
    if (uid == NULL || uid[0] == '\0' || ak == NULL || ak[0] == '\0' ||
        sk == NULL || sk[0] == '\0') {
        apr_thread_mutex_unlock(base->lock);
        return 1;   /* 鉴权不全：不构造 URL（Provider 不启用、不发请求） */
    }

    long ts = pdns_sign_now();
    char content[512];
    snprintf(content, sizeof(content), "%s%s%ld%s%s", uid, sk, ts, ascii_host, ak);
    char key_hex[65];
    pdns_sha256_hex(content, key_hex);

    int off = snprintf(out, out_len,
                       "/resolve?name=%s&type=%s&uid=%s&pf=%s&sv=%s&ts=%ld&key=%s&ak=%s",
                       ascii_host, type_str, uid, PDNS_PLATFORM, PDNS_SDK_VERSION,
                       ts, key_hex, ak);
    apr_thread_mutex_unlock(base->lock);

    if (off <= 0 || (size_t) off >= out_len) {
        return 1;
    }
    /* 会话 ID（&did=，供服务端日志聚合分析） */
    if (session_id != NULL && session_id[0] != '\0') {
        off += snprintf(out + off, out_len - (size_t) off, "&did=%s", session_id);
        if (off <= 0 || (size_t) off >= out_len) {
            return 1;
        }
    }
    if (ecs != NULL && ecs[0] != '\0') {
        off += snprintf(out + off, out_len - (size_t) off, "&edns_client_subnet=%s", ecs);
        if (off <= 0 || (size_t) off >= out_len) {
            return 1;
        }
    }
    /* short 模式：追加 &short=1 */
    if (enable_short) {
        off += snprintf(out + off, out_len - (size_t) off, "&short=1");
        if (off <= 0 || (size_t) off >= out_len) {
            return 1;
        }
    }
    return 0;
}
