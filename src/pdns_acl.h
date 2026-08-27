/*
 * 黑白名单 ACL 管理模块（内部）
 *
 * 数据模型与解析流程：
 *   - 四类数据：黑名单 zone 后缀树(bz) / 黑名单精确域名(bd) / 白名单 zone 后缀树(wz) / 白名单精确域名(wd)
 *   - ZoneTree：域名按 label 从右往左构建/匹配，途中遇 isEnd 即命中（支持后缀通配）
 *   - 版本管理：v<local 放弃；v==local 仅更新 TTL；v>local 完整更新
 *   - userConfTTL 默认 60s，过期后触发重新拉取
 *   - isNormalResolver：白名单为空视为通过 && 黑名单为空视为不匹配
 * 线程安全：内部 APR 互斥量保护；配置数据置于可整体清空的子内存池。
 */
#ifndef PDNS_ACL_H
#define PDNS_ACL_H

#include "pdns/pdns_api.h"

typedef struct pdns_acl_s pdns_acl_t;

/* 创建 ACL 管理器（初始空名单：默认允许所有域名 HTTPDNS 解析） */
pdns_acl_t *pdns_acl_create(void);

void pdns_acl_destroy(pdns_acl_t *acl);

/*
 * 用解密后的明文 JSON 更新 ACL。
 * 明文结构：{"v":<版本>,"ttl":<秒>,"uhf":<int>,"acl":{"bz":[],"bd":[],"wz":[],"wd":[]}}
 * 版本管理：v<local 放弃；v==local 仅刷新 TTL 时间戳；v>local 完整重建名单。
 */
void pdns_acl_update_from_json(pdns_acl_t *acl, const char *plain_json);

/*
 * 是否允许对该域名走 HTTPDNS 解析。
 *   - 白名单（zone+domain）非空时必须命中，否则拒绝
 *   - 命中黑名单（zone+domain）则拒绝
 *   - 名单为空时默认允许
 * @return true=允许 HTTPDNS；false=拒绝（上层应降级 LocalDNS）。
 */
bool pdns_acl_is_normal_resolver(pdns_acl_t *acl, const char *domain);

/*
 * userConfTTL 是否过期。
 * 尚未成功拉取过（conf_time==0）返回 false（首拉由启动流程触发，避免解析路径反复拉取）。
 */
bool pdns_acl_is_conf_expired(pdns_acl_t *acl);

/* 仅刷新配置拉取时间戳（不改动名单），用于拉取失败时的重试节流。 */
void pdns_acl_touch_conf_time(pdns_acl_t *acl);

/* 取当前本地 ACL 版本号；0 表示尚未成功下发过。 */
long pdns_acl_get_version(pdns_acl_t *acl);

#endif /* PDNS_ACL_H */
