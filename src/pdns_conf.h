/*
 * 黑白名单配置拉取模块（内部）—— /conf 接口
 *
 * 配置拉取协议：
 *   - GET <base_url>/conf?uid={account}&v={sdkVer}&p={platform}&ak={akId}&ev=10000
 *     （无签名；base_url 与寻址方式均由传入的 provider 提供）
 *   - 响应外层 {"v":10000,"d":"<Base64URL 密文>"}，v 为加密版本标记
 *   - 用 accessKeySecret 对 d 做 Base64URL 解码 + RC4 解密得到明文 JSON，写入 ACL
 *
 * 本模块只保留一份实现，由它向 provider 索取寻址与鉴权，两个 provider 共用。
 *
 * 线程安全：应在后台线程执行（HTTP 阻塞）。
 */
#ifndef PDNS_CONF_H
#define PDNS_CONF_H

#include "pdns/pdns_api.h"
#include "pdns_acl.h"
#include "pdns_server_provider.h"
#include "pdns_netstack.h"

/*
 * 拉取一次黑白名单配置并更新 ACL。
 *
 * @param acl               ACL 管理器（解密后写入）。
 * @param provider          服务提供者（提供寻址与鉴权；按 request_count=0 选首优节点）。
 * @param stack             当前网络栈类型。
 * @param enable_ipv6       是否允许 IPv6 直连。
 * @param using_https       true=HTTPS，false=HTTP。
 * @param timeout_ms        请求超时（毫秒），<=0 用默认。
 * @return pdns_status_t，code=PDNS_OK 表示成功拉取并解密解析。
 */
pdns_status_t pdns_conf_fetch(pdns_acl_t *acl,
                              pdns_server_provider_t *provider,
                              pdns_netstack_type_t stack,
                              bool enable_ipv6,
                              bool using_https,
                              int timeout_ms);

#endif /* PDNS_CONF_H */
