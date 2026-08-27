/*
 * 黑白名单 ACL 管理实现 —— ZoneTree 后缀树 + 精确域名集 + 版本/TTL + isNormalResolver
 */
#include "pdns_acl.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_thread_mutex.h>
#include <apr_time.h>

#include "pdns_cjson.h"

#define PDNS_ACL_MAX_LABELS 32     /* 单域名最多 label 数 */
#define PDNS_ACL_LABEL_BUF  256    /* 域名工作缓冲 */
#define PDNS_ACL_DEFAULT_TTL 60    /* userConfTTL 默认值（秒） */

/* ZoneTree 节点：children 为 label→子节点 的 APR hash，is_end 标记某域名结束 */
typedef struct pdns_zone_node_s {
    apr_hash_t *children;
    bool        is_end;
} pdns_zone_node_t;

struct pdns_acl_s {
    apr_pool_t         *pool;       /* 长生命周期池（承载锁与自身） */
    apr_pool_t         *data_pool;  /* 名单数据池，完整更新时整体 clear 重建 */
    apr_thread_mutex_t *lock;
    pdns_zone_node_t   *b_zone;     /* 黑名单 zone 后缀树 */
    pdns_zone_node_t   *w_zone;     /* 白名单 zone 后缀树 */
    apr_hash_t         *b_domain;   /* 黑名单精确域名集（key=域名，value=哨兵） */
    apr_hash_t         *w_domain;   /* 白名单精确域名集 */
    long                version;    /* LOCAL_ACL_VERSION */
    int                 conf_ttl;   /* userConfTTL（秒） */
    apr_time_t          conf_time;  /* 上次成功更新时刻（微秒），0=从未 */
    int                 uhf;        /* 劫持上报开关 */
};

/* ---------------- 内部辅助 ---------------- */

/* 读取 pdns_cJSON 为整数：数字直接取，字符串 atoi，其余返回 def */
static int json_int(const pdns_cJSON *node, int def) {
    if (pdns_cJSON_IsNumber(node)) {
        return node->valueint;
    }
    if (pdns_cJSON_IsString(node) && node->valuestring != NULL) {
        return atoi(node->valuestring);
    }
    return def;
}

/* 标准化域名：去掉尾部所有 '.'，拷入 buf。返回 buf；空/无效返回 NULL。 */
static const char *normalize_domain(const char *d, char *buf, size_t bufsz) {
    if (d == NULL) {
        return NULL;
    }
    size_t l = strlen(d);
    while (l > 0 && d[l - 1] == '.') {
        l--;
    }
    if (l == 0) {
        return NULL;
    }
    if (l >= bufsz) {
        l = bufsz - 1;
    }
    memcpy(buf, d, l);
    buf[l] = '\0';
    return buf;
}

/* 按 '.' 切分域名为 label 数组（就地修改 buf），返回 label 数；跳过空 label。 */
static int split_labels(const char *domain, char *buf, size_t bufsz,
                        const char *labels[], int maxl) {
    if (domain == NULL) {
        return 0;
    }
    size_t dl = strlen(domain);
    if (dl >= bufsz) {
        dl = bufsz - 1;
    }
    memcpy(buf, domain, dl);
    buf[dl] = '\0';

    int   count = 0;
    char *start = buf;
    for (char *q = buf;; q++) {
        if (*q == '.' || *q == '\0') {
            char end = *q;
            *q = '\0';
            if (*start != '\0' && count < maxl) {
                labels[count++] = start;
            }
            if (end == '\0') {
                break;
            }
            start = q + 1;
        }
    }
    return count;
}

static pdns_zone_node_t *zone_node_new(apr_pool_t *pool) {
    pdns_zone_node_t *n = (pdns_zone_node_t *) apr_pcalloc(pool, sizeof(pdns_zone_node_t));
    n->children = apr_hash_make(pool);
    n->is_end   = false;
    return n;
}

/* 向后缀树插入域名：label 从右往左建，最左 label 处标记 is_end。 */
static void zone_add(apr_pool_t *pool, pdns_zone_node_t *root, const char *domain) {
    char        buf[PDNS_ACL_LABEL_BUF];
    const char *labels[PDNS_ACL_MAX_LABELS];
    int         n = split_labels(domain, buf, sizeof(buf), labels, PDNS_ACL_MAX_LABELS);
    if (n <= 0) {
        return;
    }
    pdns_zone_node_t *node = root;
    for (int i = n - 1; i >= 0; i--) {
        pdns_zone_node_t *child =
            (pdns_zone_node_t *) apr_hash_get(node->children, labels[i], APR_HASH_KEY_STRING);
        if (child == NULL) {
            child = zone_node_new(pool);
            char *key = apr_pstrdup(pool, labels[i]);   /* labels 指向局部 buf，须复制 */
            apr_hash_set(node->children, key, APR_HASH_KEY_STRING, child);
        }
        node = child;
        if (i == 0) {
            node->is_end = true;
        }
    }
}

/* 后缀匹配：label 从右往左遍历，途中遇 is_end 即命中。 */
static bool zone_contains(pdns_zone_node_t *root, const char *domain) {
    if (root == NULL) {
        return false;
    }
    char        buf[PDNS_ACL_LABEL_BUF];
    const char *labels[PDNS_ACL_MAX_LABELS];
    int         n = split_labels(domain, buf, sizeof(buf), labels, PDNS_ACL_MAX_LABELS);
    if (n <= 0) {
        return false;
    }
    pdns_zone_node_t *node = root;
    for (int i = n - 1; i >= 0; i--) {
        if (node->is_end) {
            return true;
        }
        pdns_zone_node_t *child =
            (pdns_zone_node_t *) apr_hash_get(node->children, labels[i], APR_HASH_KEY_STRING);
        if (child == NULL) {
            return false;
        }
        node = child;
    }
    return node->is_end;
}

static bool zone_is_empty(const pdns_zone_node_t *root) {
    return root == NULL || apr_hash_count(root->children) == 0;
}

/* 递归统计后缀树中的域名条目数（is_end 节点数），用于日志展示 */
static unsigned int zone_count(const pdns_zone_node_t *node) {
    if (node == NULL) {
        return 0;
    }
    unsigned int cnt = node->is_end ? 1u : 0u;
    for (apr_hash_index_t *hi = apr_hash_first(NULL, node->children);
         hi != NULL; hi = apr_hash_next(hi)) {
        void *child = NULL;
        apr_hash_this(hi, NULL, NULL, &child);
        cnt += zone_count((const pdns_zone_node_t *) child);
    }
    return cnt;
}

/* 递归还原后缀树域名并追加到 out（逗号分隔）。
 * 树按 label 从右往左建（TLD 在浅层），path[0..depth-1] 为根->当前节点的 label，
 * 还原时反向拼接得到完整域名。仅用于日志展示。 */
static void zone_collect(const pdns_zone_node_t *node, const char **path, int depth,
                         char *out, size_t out_size) {
    if (node == NULL) {
        return;
    }
    if (node->is_end && depth > 0) {
        size_t len = strlen(out);
        if (len > 0 && len + 1 < out_size) {
            out[len++] = ',';
            out[len]   = '\0';
        }
        for (int i = depth - 1; i >= 0; i--) {
            size_t l = strlen(out);
            if (l >= out_size - 1) {
                break;
            }
            snprintf(out + l, out_size - l, "%s%s", path[i], (i > 0 ? "." : ""));
        }
    }
    for (apr_hash_index_t *hi = apr_hash_first(NULL, node->children);
         hi != NULL; hi = apr_hash_next(hi)) {
        const void *key   = NULL;
        void       *child = NULL;
        apr_hash_this(hi, &key, NULL, &child);
        if (depth < PDNS_ACL_MAX_LABELS) {
            path[depth] = (const char *) key;
            zone_collect((const pdns_zone_node_t *) child, path, depth + 1, out, out_size);
        }
    }
}

/* 遍历精确域名 hash 的 key 并追加到 out（逗号分隔）。仅用于日志展示。 */
static void domain_collect(apr_hash_t *set, char *out, size_t out_size) {
    if (set == NULL) {
        return;
    }
    for (apr_hash_index_t *hi = apr_hash_first(NULL, set);
         hi != NULL; hi = apr_hash_next(hi)) {
        const void *key = NULL;
        apr_hash_this(hi, &key, NULL, NULL);
        size_t len = strlen(out);
        if (len > 0 && len + 1 < out_size) {
            out[len++] = ',';
            out[len]   = '\0';
        }
        len = strlen(out);
        if (len < out_size - 1) {
            snprintf(out + len, out_size - len, "%s", (const char *) key);
        }
    }
}

/* 将 JSON 字符串数组拼成逗号分隔串（服务端原始下发，未归一化）。仅用于日志展示。 */
static void json_array_collect(const pdns_cJSON *arr, char *out, size_t out_size) {
    if (!pdns_cJSON_IsArray(arr)) {
        return;
    }
    int n = pdns_cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        pdns_cJSON *item = pdns_cJSON_GetArrayItem(arr, i);
        if (!pdns_cJSON_IsString(item) || item->valuestring == NULL) {
            continue;
        }
        size_t len = strlen(out);
        if (len > 0 && len + 1 < out_size) {
            out[len++] = ',';
            out[len]   = '\0';
        }
        len = strlen(out);
        if (len < out_size - 1) {
            snprintf(out + len, out_size - len, "%s", item->valuestring);
        }
    }
}

/* 解析 JSON 字符串数组到后缀树（逐项标准化后 add） */
static void add_zone_array(apr_pool_t *pool, pdns_zone_node_t *tree, const pdns_cJSON *arr) {
    if (!pdns_cJSON_IsArray(arr)) {
        return;
    }
    int n = pdns_cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        pdns_cJSON *item = pdns_cJSON_GetArrayItem(arr, i);
        if (pdns_cJSON_IsString(item) && item->valuestring != NULL) {
            char        nb[PDNS_ACL_LABEL_BUF];
            const char *nd = normalize_domain(item->valuestring, nb, sizeof(nb));
            if (nd != NULL) {
                zone_add(pool, tree, nd);
            }
        }
    }
}

/* 解析 JSON 字符串数组到精确域名集（key=标准化域名，value=哨兵） */
static void add_domain_array(apr_pool_t *pool, apr_hash_t *set, const pdns_cJSON *arr) {
    if (!pdns_cJSON_IsArray(arr)) {
        return;
    }
    int n = pdns_cJSON_GetArraySize(arr);
    for (int i = 0; i < n; i++) {
        pdns_cJSON *item = pdns_cJSON_GetArrayItem(arr, i);
        if (pdns_cJSON_IsString(item) && item->valuestring != NULL) {
            char        nb[PDNS_ACL_LABEL_BUF];
            const char *nd = normalize_domain(item->valuestring, nb, sizeof(nb));
            if (nd != NULL) {
                char *key = apr_pstrdup(pool, nd);
                apr_hash_set(set, key, APR_HASH_KEY_STRING, (void *) 1);
            }
        }
    }
}

/* 重建四类名单容器（在 data_pool 上，调用前须已 clear） */
static void acl_reset_containers(pdns_acl_t *acl) {
    acl->b_zone   = zone_node_new(acl->data_pool);
    acl->w_zone   = zone_node_new(acl->data_pool);
    acl->b_domain = apr_hash_make(acl->data_pool);
    acl->w_domain = apr_hash_make(acl->data_pool);
}

/* ---------------- 对外（模块内）入口 ---------------- */

pdns_acl_t *pdns_acl_create(void) {
    pdns_acl_t *acl = (pdns_acl_t *) calloc(1, sizeof(pdns_acl_t));
    if (acl == NULL) {
        return NULL;
    }
    if (apr_pool_create(&acl->pool, NULL) != APR_SUCCESS) {
        free(acl);
        return NULL;
    }
    if (apr_pool_create(&acl->data_pool, acl->pool) != APR_SUCCESS) {
        apr_pool_destroy(acl->pool);
        free(acl);
        return NULL;
    }
    apr_thread_mutex_create(&acl->lock, APR_THREAD_MUTEX_DEFAULT, acl->pool);
    acl_reset_containers(acl);
    acl->version   = 0;
    acl->conf_ttl  = PDNS_ACL_DEFAULT_TTL;
    acl->conf_time = 0;
    acl->uhf       = 0;
    return acl;
}

void pdns_acl_destroy(pdns_acl_t *acl) {
    if (acl == NULL) {
        return;
    }
    if (acl->lock) {
        apr_thread_mutex_destroy(acl->lock);
    }
    if (acl->pool) {
        apr_pool_destroy(acl->pool);   /* data_pool 为其子池，一并释放 */
    }
    free(acl);
}

void pdns_acl_update_from_json(pdns_acl_t *acl, const char *plain_json) {
    if (acl == NULL || plain_json == NULL || plain_json[0] == '\0') {
        return;
    }
    pdns_cJSON *root = pdns_cJSON_Parse(plain_json);
    if (root == NULL) {
        return;
    }
    pdns_cJSON *jv = pdns_cJSON_GetObjectItem(root, "v");
    if (jv == NULL) {
        pdns_cJSON_Delete(root);
        return;
    }
    long v = pdns_cJSON_IsNumber(jv) ? (long) jv->valuedouble
                                : (pdns_cJSON_IsString(jv) && jv->valuestring ? atol(jv->valuestring) : 0);

    apr_thread_mutex_lock(acl->lock);
    long cur = acl->version;

    if (v < cur) {
        /* 版本落后：放弃 */
        apr_thread_mutex_unlock(acl->lock);
        PDNS_LOGD("acl update abandon: v=%ld < local=%ld", v, cur);
        pdns_cJSON_Delete(root);
        return;
    }
    if (v == cur) {
        /* 版本相同：仅刷新 TTL 与时间戳，不重建名单 */
        pdns_cJSON *jttl = pdns_cJSON_GetObjectItem(root, "ttl");
        if (jttl != NULL) {
            acl->conf_ttl = json_int(jttl, acl->conf_ttl);
        }
        acl->conf_time = apr_time_now();
        apr_thread_mutex_unlock(acl->lock);
        PDNS_LOGD("acl update ttl only: v=%ld", v);
        pdns_cJSON_Delete(root);
        return;
    }

    /* v > cur：完整重建名单 */
    apr_pool_clear(acl->data_pool);
    acl_reset_containers(acl);

    pdns_cJSON *acl_obj = pdns_cJSON_GetObjectItem(root, "acl");
    if (pdns_cJSON_IsObject(acl_obj)) {
        add_zone_array(acl->data_pool, acl->b_zone, pdns_cJSON_GetObjectItem(acl_obj, "bz"));
        add_domain_array(acl->data_pool, acl->b_domain, pdns_cJSON_GetObjectItem(acl_obj, "bd"));
        add_zone_array(acl->data_pool, acl->w_zone, pdns_cJSON_GetObjectItem(acl_obj, "wz"));
        add_domain_array(acl->data_pool, acl->w_domain, pdns_cJSON_GetObjectItem(acl_obj, "wd"));
    }

    acl->version = v;
    pdns_cJSON *jttl = pdns_cJSON_GetObjectItem(root, "ttl");
    if (jttl != NULL) {
        acl->conf_ttl = json_int(jttl, acl->conf_ttl);
    }
    pdns_cJSON *juhf = pdns_cJSON_GetObjectItem(root, "uhf");
    if (juhf != NULL) {
        acl->uhf = json_int(juhf, acl->uhf);
    }
    acl->conf_time = apr_time_now();
    apr_thread_mutex_unlock(acl->lock);

    PDNS_LOGI("acl update: v=%ld ttl=%d uhf=%d (bz=%u bd=%u wz=%u wd=%u)",
              v, acl->conf_ttl, acl->uhf, zone_count(acl->b_zone),
              apr_hash_count(acl->b_domain), zone_count(acl->w_zone),
              apr_hash_count(acl->w_domain));

    /* 明细1（服务端原始下发）：未归一化，含大小写/可能被丢弃的非法项 */
    char rbz[512] = {0}, rbd[512] = {0}, rwz[512] = {0}, rwd[512] = {0};
    if (pdns_cJSON_IsObject(acl_obj)) {
        json_array_collect(pdns_cJSON_GetObjectItem(acl_obj, "bz"), rbz, sizeof(rbz));
        json_array_collect(pdns_cJSON_GetObjectItem(acl_obj, "bd"), rbd, sizeof(rbd));
        json_array_collect(pdns_cJSON_GetObjectItem(acl_obj, "wz"), rwz, sizeof(rwz));
        json_array_collect(pdns_cJSON_GetObjectItem(acl_obj, "wd"), rwd, sizeof(rwd));
    }
    PDNS_LOGD("acl raw(server): bz=[%s] bd=[%s] wz=[%s] wd=[%s]", rbz, rbd, rwz, rwd);

    /* 明细2（归一化后生效状态）：实际用于匹配的域名列表 */
    char        bz_buf[512] = {0}, bd_buf[512] = {0}, wz_buf[512] = {0}, wd_buf[512] = {0};
    const char *zpath[PDNS_ACL_MAX_LABELS];
    zone_collect(acl->b_zone, zpath, 0, bz_buf, sizeof(bz_buf));
    domain_collect(acl->b_domain, bd_buf, sizeof(bd_buf));
    zone_collect(acl->w_zone, zpath, 0, wz_buf, sizeof(wz_buf));
    domain_collect(acl->w_domain, wd_buf, sizeof(wd_buf));
    PDNS_LOGD("acl parsed(effective): bz=[%s] bd=[%s] wz=[%s] wd=[%s]", bz_buf, bd_buf, wz_buf, wd_buf);
    pdns_cJSON_Delete(root);
}

/* 白名单检查（持锁调用）：白名单为空视为通过，否则命中任一项才通过 */
static bool check_white(pdns_acl_t *acl, const char *d) {
    bool has_zone = !zone_is_empty(acl->w_zone);
    bool has_dom  = acl->w_domain && apr_hash_count(acl->w_domain) > 0;
    if (!has_zone && !has_dom) {
        return true;
    }
    if (has_dom && apr_hash_get(acl->w_domain, d, APR_HASH_KEY_STRING) != NULL) {
        return true;
    }
    return has_zone && zone_contains(acl->w_zone, d);
}

/* 黑名单检查（持锁调用）：黑名单为空视为不匹配，否则命中任一项即拒绝 */
static bool check_black(pdns_acl_t *acl, const char *d) {
    bool has_zone = !zone_is_empty(acl->b_zone);
    bool has_dom  = acl->b_domain && apr_hash_count(acl->b_domain) > 0;
    if (!has_zone && !has_dom) {
        return false;
    }
    if (has_dom && apr_hash_get(acl->b_domain, d, APR_HASH_KEY_STRING) != NULL) {
        return true;
    }
    return has_zone && zone_contains(acl->b_zone, d);
}

bool pdns_acl_is_normal_resolver(pdns_acl_t *acl, const char *domain) {
    if (acl == NULL) {
        return true;   /* 无 ACL 管理器：默认允许 */
    }
    if (domain == NULL || domain[0] == '\0') {
        return false;  /* 空域名视为不可解析 */
    }
    char        nb[PDNS_ACL_LABEL_BUF];
    const char *d = normalize_domain(domain, nb, sizeof(nb));
    if (d == NULL) {
        return false;
    }
    apr_thread_mutex_lock(acl->lock);
    bool white_ok  = check_white(acl, d);
    bool black_hit = check_black(acl, d);
    apr_thread_mutex_unlock(acl->lock);

    if (!white_ok || black_hit) {
        return false;
    }
    return true;
}

bool pdns_acl_is_conf_expired(pdns_acl_t *acl) {
    if (acl == NULL) {
        return false;
    }
    apr_thread_mutex_lock(acl->lock);
    apr_time_t t   = acl->conf_time;
    int        ttl = acl->conf_ttl;
    apr_thread_mutex_unlock(acl->lock);
    if (t == 0) {
        return false;   /* 从未成功拉取：交由启动流程首拉，避免解析路径反复拉取 */
    }
    if (ttl <= 0) {
        ttl = PDNS_ACL_DEFAULT_TTL;
    }
    return apr_time_now() - t >= (apr_time_t) ttl * APR_USEC_PER_SEC;
}

void pdns_acl_touch_conf_time(pdns_acl_t *acl) {
    if (acl == NULL) {
        return;
    }
    apr_thread_mutex_lock(acl->lock);
    acl->conf_time = apr_time_now();
    apr_thread_mutex_unlock(acl->lock);
}

long pdns_acl_get_version(pdns_acl_t *acl) {
    if (acl == NULL) {
        return 0;
    }
    apr_thread_mutex_lock(acl->lock);
    long v = acl->version;
    apr_thread_mutex_unlock(acl->lock);
    return v;
}
