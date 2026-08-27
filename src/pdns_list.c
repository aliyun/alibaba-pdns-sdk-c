/*
 * 字符串链表实现 —— 域名列表（入参）与解析结果列表（出参）
 *
 * 两个对外类型共用 pdns_list_impl_t 一份底层实现，见 pdns_list.h 的说明。
 */
#include "pdns_list.h"

#include <stdlib.h>
#include <string.h>

/* ============================ 内部辅助 ============================ */

static char *dup_str(const char *s) {
    if (s == NULL) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char  *p = (char *) malloc(n);
    if (p != NULL) {
        memcpy(p, s, n);
    }
    return p;
}

static pdns_status_t status_of(int code, const char *msg) {
    pdns_status_t s;
    memset(&s, 0, sizeof(s));
    s.code = code;
    if (msg != NULL) {
        strncpy(s.error_msg, msg, PDNS_ERROR_MSG_LEN - 1);
    }
    return s;
}

/*
 * 把对外的 query_type 归约为地址族下标：0=IPv4，1=IPv6，-1=非单一地址族。
 * AUTO / BOTH 不对应具体族，由调用方自行处理（读取时另有回退规则）。
 */
static int family_index(pdns_query_type_t family) {
    if (family == PDNS_QUERY_IPV4) {
        return 0;
    }
    if (family == PDNS_QUERY_IPV6) {
        return 1;
    }
    return -1;
}

/* ============================ 底层链表操作 ============================ */

pdns_list_impl_t *pdns_list_impl_create(void) {
    return (pdns_list_impl_t *) calloc(1, sizeof(pdns_list_impl_t));
}

void pdns_list_impl_clear(pdns_list_impl_t *l) {
    if (l == NULL) {
        return;
    }
    pdns_list_node_t *node = l->head;
    while (node != NULL) {
        pdns_list_node_t *next = node->next;
        free(node->str);
        free(node);
        node = next;
    }
    l->head = NULL;
    l->tail = NULL;
    l->size = 0;
}

void pdns_list_impl_destroy(pdns_list_impl_t *l) {
    if (l == NULL) {
        return;
    }
    pdns_list_impl_clear(l);
    free(l);
}

int pdns_list_impl_add(pdns_list_impl_t *l, const char *s) {
    if (l == NULL || s == NULL) {
        return 1;
    }
    pdns_list_node_t *node = (pdns_list_node_t *) calloc(1, sizeof(pdns_list_node_t));
    if (node == NULL) {
        return 1;
    }
    node->str = dup_str(s);
    if (node->str == NULL) {
        free(node);
        return 1;
    }
    if (l->tail != NULL) {
        l->tail->next = node;
    } else {
        l->head = node;
    }
    l->tail = node;
    l->size++;
    return 0;
}

size_t pdns_list_impl_size(const pdns_list_impl_t *l) {
    return (l != NULL) ? l->size : 0;
}

const char *pdns_list_impl_get(const pdns_list_impl_t *l, size_t index) {
    if (l == NULL || index >= l->size) {
        return NULL;
    }
    const pdns_list_node_t *node = l->head;
    for (size_t i = 0; i < index && node != NULL; i++) {
        node = node->next;
    }
    return (node != NULL) ? node->str : NULL;
}

pdns_list_impl_t *pdns_list_impl_clone(const pdns_list_impl_t *src) {
    if (src == NULL) {
        return NULL;
    }
    pdns_list_impl_t *dst = pdns_list_impl_create();
    if (dst == NULL) {
        return NULL;
    }
    for (const pdns_list_node_t *node = src->head; node != NULL; node = node->next) {
        if (pdns_list_impl_add(dst, node->str) != 0) {
            pdns_list_impl_destroy(dst);
            return NULL;
        }
    }
    return dst;
}

/* ============================ 域名列表（对外） ============================ */

pdns_domain_list_t *pdns_domain_list_create(void) {
    return (pdns_domain_list_t *) calloc(1, sizeof(pdns_domain_list_t));
}

pdns_status_t pdns_domain_list_add(pdns_domain_list_t *list, const char *domain) {
    if (list == NULL || domain == NULL) {
        return status_of(1, "invalid argument");
    }
    if (pdns_list_impl_add(&list->impl, domain) != 0) {
        return status_of(1, "out of memory");
    }
    return status_of(PDNS_OK, NULL);
}

size_t pdns_domain_list_size(const pdns_domain_list_t *list) {
    return (list != NULL) ? pdns_list_impl_size(&list->impl) : 0;
}

const char *pdns_domain_list_get(const pdns_domain_list_t *list, size_t index) {
    return (list != NULL) ? pdns_list_impl_get(&list->impl, index) : NULL;
}

void pdns_domain_list_cleanup(pdns_domain_list_t *list) {
    if (list == NULL) {
        return;
    }
    pdns_list_impl_clear(&list->impl);
    free(list);
}

/* ============================ 解析结果列表 ============================ */

pdns_result_list_t *pdns_result_list_create(void) {
    /* calloc 归零即 source=PDNS_SOURCE_UNKNOWN / from_cache=false */
    return (pdns_result_list_t *) calloc(1, sizeof(pdns_result_list_t));
}

int pdns_result_list_add(pdns_result_list_t *r, const char *ip) {
    if (r == NULL) {
        return 1;
    }
    return pdns_list_impl_add(&r->impl, ip);
}

void pdns_result_list_clear_ips(pdns_result_list_t *r) {
    if (r != NULL) {
        pdns_list_impl_clear(&r->impl);
    }
}

pdns_result_list_t *pdns_result_list_clone(const pdns_result_list_t *src) {
    if (src == NULL) {
        return NULL;
    }
    pdns_result_list_t *dst = pdns_result_list_create();
    if (dst == NULL) {
        return NULL;
    }
    for (const pdns_list_node_t *node = src->impl.head; node != NULL; node = node->next) {
        if (pdns_result_list_add(dst, node->str) != 0) {
            pdns_result_list_cleanup(dst);
            return NULL;
        }
    }
    dst->meta_v4 = src->meta_v4;
    dst->meta_v6 = src->meta_v6;
    return dst;
}

void pdns_result_list_set_meta(pdns_result_list_t *r, pdns_query_type_t family,
                               pdns_source_t source, bool from_cache) {
    if (r == NULL) {
        return;
    }
    int idx = family_index(family);
    if (idx < 0) {
        return;   /* AUTO / BOTH 不对应具体族，忽略 */
    }
    pdns_result_meta_t *meta = (idx == 0) ? &r->meta_v4 : &r->meta_v6;
    meta->source     = source;
    meta->from_cache = from_cache;
}

const pdns_result_meta_t *pdns_result_list_meta(const pdns_result_list_t *r,
                                                pdns_query_type_t family) {
    if (r == NULL) {
        return NULL;
    }
    int idx = family_index(family);
    if (idx == 0) {
        return &r->meta_v4;
    }
    if (idx == 1) {
        return &r->meta_v6;
    }
    return NULL;
}

/*
 * AUTO / BOTH 的读取回退：返回「有结果的那一族」，两族都有则取 IPv4。
 * 这样使用方把自己发起查询时用的 query_type 原样传进来即可拿到正确值，
 * 无需关心 AUTO 在内部被网络栈归一成了哪一族。
 */
static const pdns_result_meta_t *meta_for_read(const pdns_result_list_t *r,
                                               pdns_query_type_t family) {
    if (r == NULL) {
        return NULL;
    }
    const pdns_result_meta_t *meta = pdns_result_list_meta(r, family);
    if (meta != NULL) {
        return meta;
    }
    if (r->meta_v4.source != PDNS_SOURCE_UNKNOWN) {
        return &r->meta_v4;
    }
    if (r->meta_v6.source != PDNS_SOURCE_UNKNOWN) {
        return &r->meta_v6;
    }
    return NULL;
}

size_t pdns_result_list_size(const pdns_result_list_t *results) {
    return (results != NULL) ? pdns_list_impl_size(&results->impl) : 0;
}

const char *pdns_result_list_get(const pdns_result_list_t *results, size_t index) {
    return (results != NULL) ? pdns_list_impl_get(&results->impl, index) : NULL;
}

void pdns_result_list_cleanup(pdns_result_list_t *results) {
    if (results == NULL) {
        return;
    }
    pdns_list_impl_clear(&results->impl);
    free(results);
}

pdns_source_t pdns_result_list_get_source(const pdns_result_list_t *results,
                                          pdns_query_type_t family) {
    const pdns_result_meta_t *meta = meta_for_read(results, family);
    return (meta != NULL) ? meta->source : PDNS_SOURCE_UNKNOWN;
}

bool pdns_result_list_is_from_cache(const pdns_result_list_t *results,
                                    pdns_query_type_t family) {
    const pdns_result_meta_t *meta = meta_for_read(results, family);
    return (meta != NULL) ? meta->from_cache : false;
}

/* ============================ 来源名称 ============================ */

const char *pdns_source_name(pdns_source_t source) {
    switch (source) {
        case PDNS_SOURCE_PUBLIC_DNS: return "PublicDNS";
        case PDNS_SOURCE_FUSION_DNS: return "FusionDNS";
        case PDNS_SOURCE_LOCAL_DNS:  return "LocalDNS";
        default:                     return "Unknown";
    }
}
