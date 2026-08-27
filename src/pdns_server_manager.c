/*
 * DNS 服务提供者调度管理器实现
 *
 * 实现要点：
 *   1. 取服务 URL 为同步返回（C 侧无回调/异步等待封装）；
 *   2. manager 直接持有两个具体实例，用指针比较区分 provider 取重试预算，
 *      无需在 vtable 上加类型标记。
 */
#include "pdns_server_manager.h"
#include "pdns_health_checker.h"

#include "pdns_failure_tracker.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <string.h>

#include <apr_pools.h>
#include <apr_thread_mutex.h>

struct pdns_server_manager_s {
    apr_pool_t         *pool;
    apr_thread_mutex_t *lock;

    /* 两个 provider 实体恒存在，未配置时 is_dns_provider_enabled 为假 */
    pdns_public_provider_t *public_provider;
    pdns_fusion_provider_t *fusion_provider;

    /* provider group：按优先级排序，[0]=主用，[1]=备用 */
    pdns_server_provider_t  *group[2];
    int                          group_count;

    pdns_first_configured_type_t first_configured_type;
    int                          fallback_threshold;

    pdns_failure_tracker_t  *failure_tracker;
};

/* ---------------- 内部辅助 ---------------- */

/* 已持锁：重建 provider group */
static void rebuild_provider_group_locked(pdns_server_manager_t *m) {
    pdns_server_provider_t *pub =
        pdns_public_provider_as_provider(m->public_provider);
    pdns_server_provider_t *fus =
        pdns_fusion_provider_as_provider(m->fusion_provider);

    bool public_enabled = pdns_provider_is_dns_provider_enabled(pub);
    bool fusion_enabled = pdns_provider_is_dns_provider_enabled(fus);

    m->group[0]    = NULL;
    m->group[1]    = NULL;
    m->group_count = 0;

    if (!public_enabled && !fusion_enabled) {
        /* 保持空列表 */
    } else if (public_enabled && !fusion_enabled) {
        m->group[0]    = pub;
        m->group_count = 1;
    } else if (!public_enabled && fusion_enabled) {
        m->group[0]    = fus;
        m->group_count = 1;
    } else {
        /* 两者都启用 → 按首次配置类型决定主备顺序与默认阈值 */
        if (m->first_configured_type == PDNS_FIRST_CONFIGURED_PUBLIC) {
            m->group[0]          = pub;
            m->group[1]          = fus;
            m->fallback_threshold = PDNS_FALLBACK_THRESHOLD_PUBLIC_PRIMARY;
        } else {
            m->group[0]          = fus;
            m->group[1]          = pub;
            m->fallback_threshold = PDNS_FALLBACK_THRESHOLD_FUSION_PRIMARY;
        }
        m->group_count = 2;
    }

    PDNS_LOGI("provider group rebuilt: count=%d primary=%s backup=%s threshold=%d",
              m->group_count,
              pdns_provider_name(m->group[0]),
              pdns_provider_name(m->group[1]),
              m->fallback_threshold);
}

/* 该 provider 的重试预算（按类型取 PUBLICRETRYCOUNT / FUSIONRETRYCOUNT） */
static int retry_count_of(pdns_server_manager_t *m,
                          pdns_server_provider_t *p) {
    if (p == (pdns_server_provider_t *) m->public_provider) {
        return PDNS_PUBLIC_RETRY_COUNT;
    }
    return PDNS_FUSION_RETRY_COUNT;
}

/* ---------------- 生命周期 ---------------- */

pdns_server_manager_t *pdns_server_manager_create(void) {
    pdns_server_manager_t *m =
        (pdns_server_manager_t *) calloc(1, sizeof(pdns_server_manager_t));
    if (m == NULL) {
        return NULL;
    }
    if (apr_pool_create(&m->pool, NULL) != APR_SUCCESS) {
        free(m);
        return NULL;
    }
    if (apr_thread_mutex_create(&m->lock, APR_THREAD_MUTEX_DEFAULT, m->pool)
        != APR_SUCCESS) {
        apr_pool_destroy(m->pool);
        free(m);
        return NULL;
    }

    m->public_provider = pdns_public_provider_create();
    m->fusion_provider = pdns_fusion_provider_create();
    m->failure_tracker = pdns_failure_tracker_create();
    if (m->public_provider == NULL || m->fusion_provider == NULL ||
        m->failure_tracker == NULL) {
        pdns_server_manager_destroy(m);
        return NULL;
    }

    m->first_configured_type = PDNS_FIRST_CONFIGURED_NONE;
    m->fallback_threshold    = PDNS_FALLBACK_THRESHOLD_PUBLIC_PRIMARY;
    return m;
}

void pdns_server_manager_destroy(pdns_server_manager_t *m) {
    if (m == NULL) {
        return;
    }
    pdns_failure_tracker_destroy(m->failure_tracker);
    pdns_public_provider_destroy(m->public_provider);
    pdns_fusion_provider_destroy(m->fusion_provider);
    if (m->pool != NULL) {
        apr_pool_destroy(m->pool);   /* 互斥量随 pool 销毁 */
    }
    free(m);
}

/* ---------------- 配置入口 ---------------- */

int pdns_server_manager_init_public_dns(pdns_server_manager_t *m,
                                            const char *account_id,
                                            const char *access_key_id,
                                            const char *access_key_secret) {
    if (m == NULL) {
        return 1;
    }
    /* 先落地鉴权（provider 内部做三参数强校验），失败则不触碰 group */
    int rc = pdns_public_provider_set_auth(m->public_provider, account_id,
                                               access_key_id, access_key_secret);
    if (rc != 0) {
        return rc;
    }

    apr_thread_mutex_lock(m->lock);
    if (m->first_configured_type == PDNS_FIRST_CONFIGURED_NONE) {
        m->first_configured_type = PDNS_FIRST_CONFIGURED_PUBLIC;
    }
    rebuild_provider_group_locked(m);
    apr_thread_mutex_unlock(m->lock);
    return 0;
}

int pdns_server_manager_init_fusion_dns(pdns_server_manager_t *m,
                                            const char *const *server_ipv4_arr, int v4_count,
                                            const char *const *server_ipv6_arr, int v6_count,
                                            const char *const *server_host_arr, int host_count,
                                            int         port,
                                            const char *health_check_domain,
                                            const char *account_id,
                                            const char *access_key_id,
                                            const char *access_key_secret) {
    if (m == NULL) {
        return 1;
    }
    int rc = pdns_fusion_provider_init_fusion_dns(
        m->fusion_provider, server_ipv4_arr, v4_count, server_ipv6_arr, v6_count,
        server_host_arr, host_count, port, health_check_domain,
        account_id, access_key_id, access_key_secret);
    if (rc != 0) {
        return rc;
    }

    apr_thread_mutex_lock(m->lock);
    if (m->first_configured_type == PDNS_FIRST_CONFIGURED_NONE) {
        m->first_configured_type = PDNS_FIRST_CONFIGURED_FUSION;
    }
    rebuild_provider_group_locked(m);
    apr_thread_mutex_unlock(m->lock);
    return 0;
}

/* ---------------- provider 访问 ---------------- */

pdns_public_provider_t *pdns_server_manager_public(pdns_server_manager_t *m) {
    return (m != NULL) ? m->public_provider : NULL;
}

pdns_fusion_provider_t *pdns_server_manager_fusion(pdns_server_manager_t *m) {
    return (m != NULL) ? m->fusion_provider : NULL;
}

int pdns_server_manager_provider_count(pdns_server_manager_t *m) {
    if (m == NULL) {
        return 0;
    }
    apr_thread_mutex_lock(m->lock);
    int n = m->group_count;
    apr_thread_mutex_unlock(m->lock);
    return n;
}

pdns_server_provider_t *pdns_server_manager_primary(pdns_server_manager_t *m) {
    if (m == NULL) {
        return NULL;
    }
    apr_thread_mutex_lock(m->lock);
    pdns_server_provider_t *p = m->group[0];
    apr_thread_mutex_unlock(m->lock);
    return p;
}

pdns_server_provider_t *pdns_server_manager_backup(pdns_server_manager_t *m) {
    if (m == NULL) {
        return NULL;
    }
    apr_thread_mutex_lock(m->lock);
    pdns_server_provider_t *p = m->group[1];
    apr_thread_mutex_unlock(m->lock);
    return p;
}

pdns_first_configured_type_t
pdns_server_manager_first_configured_type(pdns_server_manager_t *m) {
    if (m == NULL) {
        return PDNS_FIRST_CONFIGURED_NONE;
    }
    apr_thread_mutex_lock(m->lock);
    pdns_first_configured_type_t t = m->first_configured_type;
    apr_thread_mutex_unlock(m->lock);
    return t;
}

/* ---------------- fallback_threshold ---------------- */

int pdns_server_manager_get_fallback_threshold(pdns_server_manager_t *m) {
    if (m == NULL) {
        return 0;
    }
    apr_thread_mutex_lock(m->lock);
    int v = m->fallback_threshold;
    apr_thread_mutex_unlock(m->lock);
    return v;
}

void pdns_server_manager_set_fallback_threshold(pdns_server_manager_t *m,
                                                    int fallback_threshold) {
    if (m == NULL) {
        return;
    }
    int v = fallback_threshold;
    if (v < 0) {
        v = 0;
    }
    if (v > PDNS_FALLBACK_THRESHOLD_MAX) {
        v = PDNS_FALLBACK_THRESHOLD_MAX;
    }
    apr_thread_mutex_lock(m->lock);
    m->fallback_threshold = v;
    apr_thread_mutex_unlock(m->lock);
    PDNS_LOGI("set fallback threshold: %d", v);
}

/* ---------------- 核心调度 ---------------- */

int pdns_server_manager_max_total_retry_count(pdns_server_manager_t *m,
                                                   pdns_netstack_type_t stack,
                                                   bool enable_ipv6) {
    if (m == NULL) {
        return 0;
    }
    apr_thread_mutex_lock(m->lock);
    pdns_server_provider_t *primary = m->group[0];
    pdns_server_provider_t *backup  = m->group[1];
    int count     = m->group_count;
    int threshold = m->fallback_threshold;
    apr_thread_mutex_unlock(m->lock);

    if (count == 0) {
        return 0;
    }

    bool primary_has_active =
        pdns_provider_has_active_servers(primary, stack, enable_ipv6);

    if (count == 1) {
        return primary_has_active ? retry_count_of(m, primary) : 0;
    }

    bool backup_has_active =
        pdns_provider_has_active_servers(backup, stack, enable_ipv6);
    int backup_retry = backup_has_active ? retry_count_of(m, backup) : 0;

    if (primary_has_active) {
        /* 主用可用：主用最多尝试 threshold 次，之后交给备用 */
        return threshold + backup_retry;
    }
    /* 主用无活跃节点：不浪费尝试次数，全额给备用 */
    return backup_retry;
}

int pdns_server_manager_get_server_url_with_request_count(
        pdns_server_manager_t *m,
        int                        request_count,
        const char                *domain,
        const char                *type_str,
        const char                *request_id,
        pdns_netstack_type_t       stack,
        bool                       enable_ipv6,
        bool                       using_https,
        pdns_server_url_result_t  *out,
        pdns_server_provider_t **out_provider) {
    if (out_provider != NULL) {
        *out_provider = NULL;
    }
    if (m == NULL || out == NULL) {
        return 1;
    }

    apr_thread_mutex_lock(m->lock);
    pdns_server_provider_t *primary = m->group[0];
    pdns_server_provider_t *backup  = m->group[1];
    int count     = m->group_count;
    int threshold = m->fallback_threshold;
    apr_thread_mutex_unlock(m->lock);

    if (count == 0) {
        return 1;
    }

    /* 情况 1：只有一个 provider，直接使用，无降级决策 */
    if (count == 1) {
        int rc = pdns_provider_get_server_url_with_request_count(
            primary, request_count, stack, enable_ipv6, using_https, out);
        if (rc == 0 && out_provider != NULL) {
            *out_provider = primary;
        }
        return rc;
    }

    /* 情况 2：主用 + 备用 */
    int primary_rc = pdns_provider_get_server_url_with_request_count(
        primary, request_count, stack, enable_ipv6, using_https, out);

    if (primary_rc == 0) {
        /* 主用能给出有效 URL → 查本次请求是否已累计到降级阈值 */
        bool should_fallback = pdns_failure_tracker_should_fallback(
            m->failure_tracker, domain, type_str, request_id, threshold);
        if (!should_fallback) {
            if (out_provider != NULL) {
                *out_provider = primary;
            }
            return 0;
        }

        /* 已触发降级：request_count 扣掉主用已消耗的 threshold，
         * 使备用从自己的第 0 次开始（否则备用会跳过前几个优选节点直接切 HOST）。 */
        int fallback_request_count = request_count - threshold;
        if (fallback_request_count < 0) {
            fallback_request_count = 0;
        }
        int backup_rc = pdns_provider_get_server_url_with_request_count(
            backup, fallback_request_count, stack, enable_ipv6, using_https, out);
        if (backup_rc == 0) {
            PDNS_LOGI("fallback: domain=%s type=%s rid=%s -> %s (rc=%d->%d)",
                      domain ? domain : "-", type_str ? type_str : "-",
                      request_id ? request_id : "-", pdns_provider_name(backup),
                      request_count, fallback_request_count);
            if (out_provider != NULL) {
                *out_provider = backup;
            }
            return 0;
        }
        PDNS_LOGW("fallback triggered but backup %s has no available node",
                  pdns_provider_name(backup));
        return 1;
    }

    /* 主用给不出 URL（如当前网络栈下无匹配节点）→ 直连备用，不扣 request_count
     * （主用一次都没消耗，扣了会让备用重复用同一个节点） */
    int backup_rc = pdns_provider_get_server_url_with_request_count(
        backup, request_count, stack, enable_ipv6, using_https, out);
    if (backup_rc == 0) {
        PDNS_LOGI("primary %s unavailable, use backup %s directly",
                  pdns_provider_name(primary), pdns_provider_name(backup));
        if (out_provider != NULL) {
            *out_provider = backup;
        }
        return 0;
    }

    PDNS_LOGW("both primary and backup have no available node");
    return 1;
}

/* ---------------- 事件通知 ---------------- */

void pdns_server_manager_on_request_success(pdns_server_manager_t *m,
                                                const char *domain,
                                                const char *type_str,
                                                const char *request_id) {
    if (m == NULL) {
        return;
    }
    pdns_failure_tracker_record_success(m->failure_tracker, domain, type_str,
                                            request_id);
}

void pdns_server_manager_on_request_failure(pdns_server_manager_t *m,
                                                const char *domain,
                                                const char *type_str,
                                                const char *request_id) {
    if (m == NULL) {
        return;
    }
    pdns_failure_tracker_record_failure(m->failure_tracker, domain, type_str,
                                            request_id);
}

void pdns_server_manager_on_request_finish(pdns_server_manager_t *m,
                                               const char *domain,
                                               const char *type_str,
                                               const char *request_id) {
    if (m == NULL) {
        return;
    }
    pdns_failure_tracker_reset(m->failure_tracker, domain, type_str, request_id);
}

void pdns_server_manager_cleanup_expired(pdns_server_manager_t *m) {
    if (m == NULL) {
        return;
    }
    pdns_failure_tracker_cleanup_expired(m->failure_tracker);
}

/* ---------------- 熔断 ---------------- */

/*
 * 熔断计数的两个前置条件：
 *   1. 仅自建节点参与（节点的来源必须为自建）
 *   2. health_check_domain 非空（判空即 return）
 * 第 2 条不可省：若无探测域名却仍熔断，节点被摘除后就永远无法恢复。
 * @return 通过校验时返回自建的基类指针，否则 NULL。
 */
static pdns_base_provider_t *
circuit_break_target(pdns_server_manager_t *m,
                     pdns_server_provider_t *provider,
                     const char *node_ip) {
    if (m == NULL || provider == NULL || node_ip == NULL) {
        return NULL;
    }
    pdns_server_provider_t *fusion_prov =
        pdns_fusion_provider_as_provider(m->fusion_provider);
    if (provider != fusion_prov) {
        return NULL;   /* 前置 1：非自建节点不参与熔断 */
    }
    const char *domain =
        pdns_fusion_provider_get_health_check_domain(m->fusion_provider);
    if (domain == NULL || domain[0] == '\0') {
        return NULL;   /* 前置 2：无探测域名即熔断关闭 */
    }
    return pdns_fusion_provider_as_base(m->fusion_provider);
}

void pdns_server_manager_update_consecutive_success(pdns_server_manager_t *m,
                                                        pdns_server_provider_t *provider,
                                                        const char *node_ip) {
    pdns_base_provider_t *base = circuit_break_target(m, provider, node_ip);
    if (base == NULL) {
        return;
    }
    pdns_base_provider_record_node_success(base, node_ip);
}

void pdns_server_manager_update_consecutive_failure(pdns_server_manager_t *m,
                                                        pdns_server_provider_t *provider,
                                                        const char *node_ip) {
    pdns_base_provider_t *base = circuit_break_target(m, provider, node_ip);
    if (base == NULL) {
        return;
    }
    /* 达阈即置 is_alive=false，该节点随即从选点与 hasActiveServers 中消失 */
    pdns_base_provider_record_node_failure(base, node_ip);
}

int pdns_server_manager_run_health_check(pdns_server_manager_t *m,
                                             pdns_netstack_type_t stack,
                                             const char *session_id,
                                             int timeout_ms,
                                             bool using_https) {
    if (m == NULL) {
        return 0;
    }
    /* 前置条件的校验在 health_check_run 内部完成（provider 未启用 / 探测域名为空） */
    return pdns_health_check_run(m->fusion_provider, stack, session_id,
                                timeout_ms, using_https);
}

/* ---------------- 网络切换 ---------------- */

void pdns_server_manager_reset_srtt(pdns_server_manager_t *m) {
    if (m == NULL) {
        return;
    }
    pdns_base_provider_reset_srtt(
        pdns_public_provider_as_base(m->public_provider));
    pdns_base_provider_reset_srtt(
        pdns_fusion_provider_as_base(m->fusion_provider));
}
