/*
 * 字符串链表（内部）—— 域名列表与解析结果列表的共同底座
 *
 * 对外暴露两个互不兼容的不透明类型（见 pdns_api.h）：
 *   - pdns_domain_list_t：使用方构造的域名列表（入参），可 create / add
 *   - pdns_result_list_t：SDK 返回的解析结果（出参），只读 + 携带来源元信息
 *
 * 两者共用本文件的 pdns_list_impl_t 作为首成员，增删遍历逻辑只写一份。
 * 之所以不让结果列表「继承」域名列表，是因为两者的对外能力是刻意分开的：
 * 结果列表不允许外部追加元素——否则插入的地址没有对应来源，会与元信息不一致。
 *
 * 注：本文件只声明「内部」部分（结构体定义与 impl 操作）；两个类型的公开
 * 接口（pdns_domain_list_* / pdns_result_list_* / pdns_source_name）声明在
 * pdns_api.h，但同样由 pdns_list.c 实现。
 *
 * 线程安全：链表本身不加锁，由持有者保证。
 */
#ifndef PDNS_LIST_H
#define PDNS_LIST_H

#include "pdns/pdns_api.h"

/* 链表节点 */
typedef struct pdns_list_node_s {
    char                    *str;
    struct pdns_list_node_s *next;
} pdns_list_node_t;

/* 底层链表实现体（两个对外类型的首成员） */
typedef struct {
    pdns_list_node_t *head;
    pdns_list_node_t *tail;
    size_t            size;
} pdns_list_impl_t;

/*
 * 单个地址族的结果元信息。
 * 按地址族而非按单个 IP 记录是无损的：同族的全部 IP 必然来自同一次解析
 * （缓存按地址族分键；一次网络解析的结果也全部来自同一个 provider）。
 */
typedef struct {
    pdns_source_t source;
    bool          from_cache;
} pdns_result_meta_t;

struct pdns_domain_list_s {
    pdns_list_impl_t impl;
};

struct pdns_result_list_s {
    pdns_list_impl_t   impl;
    pdns_result_meta_t meta_v4;
    pdns_result_meta_t meta_v6;
};

/* ---------------- 底层链表操作（SDK 内部通用字符串集合） ---------------- */

/* 创建空链表；失败返回 NULL */
pdns_list_impl_t *pdns_list_impl_create(void);

/* 释放全部节点并释放链表自身（NULL 安全） */
void pdns_list_impl_destroy(pdns_list_impl_t *l);

/* 释放全部节点但保留链表自身（复位为空表） */
void pdns_list_impl_clear(pdns_list_impl_t *l);

/* 追加一个字符串（内部拷贝）。0 成功，非 0 失败 */
int pdns_list_impl_add(pdns_list_impl_t *l, const char *s);

size_t      pdns_list_impl_size(const pdns_list_impl_t *l);
const char *pdns_list_impl_get(const pdns_list_impl_t *l, size_t index);

/* 深拷贝一份新链表；src 为 NULL 时返回 NULL */
pdns_list_impl_t *pdns_list_impl_clone(const pdns_list_impl_t *src);

/* ---------------- 解析结果列表的内部构造（不对外） ---------------- */

/*
 * 创建空结果列表。两族 meta 归零，即 source=UNKNOWN / from_cache=false
 * （零值落在「未知」这一安全侧，见 pdns_api.h 中 pdns_source_t 的说明）。
 */
pdns_result_list_t *pdns_result_list_create(void);

/* 追加一个 IP（内部拷贝）。0 成功，非 0 失败 */
int pdns_result_list_add(pdns_result_list_t *r, const char *ip);

/* 深拷贝（含两族 meta）；src 为 NULL 时返回 NULL */
pdns_result_list_t *pdns_result_list_clone(const pdns_result_list_t *src);

/* 清空 IP 但保留 meta（回源前丢弃缓存旧值等场景） */
void pdns_result_list_clear_ips(pdns_result_list_t *r);

/*
 * 设置指定地址族的 meta。
 * @param[in]  family  须为 PDNS_QUERY_IPV4 / PDNS_QUERY_IPV6；其余取值忽略本次调用
 *                     （AUTO 已由上层按网络栈归一，BOTH 已被拆成两次单族解析）
 */
void pdns_result_list_set_meta(pdns_result_list_t *r, pdns_query_type_t family,
                               pdns_source_t source, bool from_cache);

/* 取指定族 meta 的只读指针；family 非法或 r 为 NULL 时返回 NULL */
const pdns_result_meta_t *pdns_result_list_meta(const pdns_result_list_t *r,
                                                pdns_query_type_t family);

#endif /* PDNS_LIST_H */
