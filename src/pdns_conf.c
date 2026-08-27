/*
 * 黑白名单配置拉取实现 —— /conf 请求 + RC4 解密 + 写入 ACL
 */
#include "pdns_conf.h"
#include "pdns_base_provider.h"
#include "pdns_const.h"
#include "pdns_rc4.h"
#include "pdns_http.h"
#include "pdns_log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "pdns_cjson.h"

#define PDNS_CONF_ENCRYPT_TYPE 10000      /* 加密版本标记 */

static pdns_status_t status_ok(void) {
    pdns_status_t s;
    memset(&s, 0, sizeof(s));
    s.code = PDNS_OK;
    return s;
}

static pdns_status_t status_err(int code, const char *msg) {
    pdns_status_t s;
    memset(&s, 0, sizeof(s));
    s.code = code;
    if (msg) {
        strncpy(s.error_msg, msg, PDNS_ERROR_MSG_LEN - 1);
    }
    return s;
}

pdns_status_t pdns_conf_fetch(pdns_acl_t *acl,
                              pdns_server_provider_t *provider,
                              pdns_netstack_type_t stack,
                              bool enable_ipv6,
                              bool using_https,
                              int timeout_ms) {
    if (acl == NULL || provider == NULL) {
        return status_err(1, "invalid argument");
    }

    /* 向 provider 索取服务端地址：request_count=0 即首选优节点
     * （公共 DNS 得到「域名 + 待注入 IP」，自建得到「节点+端口」的完整 base_url） */
    pdns_server_url_result_t url_res;
    memset(&url_res, 0, sizeof(url_res));
    if (pdns_provider_get_server_url_with_request_count(provider, 0, stack, enable_ipv6,
                                                        using_https, &url_res) != 0) {
        PDNS_LOGW("conf fetch skipped: %s has no available node",
                  pdns_provider_name(provider));
        pdns_acl_touch_conf_time(acl);   /* 无可用节点也节流，避免解析路径反复触发 */
        return status_err(2, "no available dns server");
    }

    pdns_base_provider_t *base = pdns_base_of(provider);
    const char *account_id        = pdns_base_provider_account_id(base);
    const char *access_key_id     = pdns_base_provider_access_key_id(base);
    const char *access_key_secret = pdns_base_provider_access_key_secret(base);

    char url[512];
    snprintf(url, sizeof(url), "%s/conf?uid=%s&v=%s&p=%s&ak=%s&ev=%d",
             url_res.base_url,
             account_id ? account_id : "", PDNS_SDK_VERSION, PDNS_PLATFORM,
             access_key_id ? access_key_id : "", PDNS_CONF_ENCRYPT_TYPE);

    pdns_http_request_t hreq;
    memset(&hreq, 0, sizeof(hreq));
    hreq.url              = url;
    hreq.resolve_host     = url_res.resolve_host;
    hreq.server_ip        = url_res.server_ip;   /* NULL 时不直连（HOST 兜底 / 自建） */
    hreq.using_https      = using_https;
    hreq.timeout_ms       = timeout_ms;
    hreq.skip_cert_verify = !url_res.verify_cert;

    const char *server_log = url_res.server_ip ? url_res.server_ip : url_res.base_url;

    pdns_http_response_t hresp;
    int rc = pdns_http_get(&hreq, &hresp);

    if (rc != 0 || hresp.body == NULL || hresp.http_code != 200) {
        PDNS_LOGW("conf fetch failed: source=%s server=%s http=%ld",
                  pdns_source_name(url_res.source), server_log, hresp.http_code);
        pdns_http_response_free(&hresp);
        pdns_acl_touch_conf_time(acl);   /* 失败节流：避免解析路径反复拉取 */
        return status_err(2, "conf http request failed");
    }

    /* 外层 {"v":10000,"d":"<Base64URL 密文>"}：v 为加密版本标记 */
    bool   ok   = false;
    pdns_cJSON *root = pdns_cJSON_Parse(hresp.body);
    if (root != NULL) {
        pdns_cJSON *jd = pdns_cJSON_GetObjectItem(root, "d");
        pdns_cJSON *jv = pdns_cJSON_GetObjectItem(root, "v");
        int    ev = pdns_cJSON_IsNumber(jv) ? jv->valueint
                                       : (pdns_cJSON_IsString(jv) && jv->valuestring ? atoi(jv->valuestring) : 0);
        if (pdns_cJSON_IsString(jd) && jd->valuestring != NULL && ev == PDNS_CONF_ENCRYPT_TYPE) {
            char *plain = pdns_rc4_decrypt_base64url(access_key_secret, jd->valuestring);
            if (plain != NULL) {
                pdns_acl_update_from_json(acl, plain);
                free(plain);
                ok = true;
            } else {
                PDNS_LOGW("conf decrypt failed");
            }
        } else {
            PDNS_LOGW("conf response invalid: ev=%d has_d=%d", ev, pdns_cJSON_IsString(jd));
        }
        pdns_cJSON_Delete(root);
    }

    pdns_http_response_free(&hresp);
    if (!ok) {
        pdns_acl_touch_conf_time(acl);   /* 解析失败也节流 */
        return status_err(3, "conf parse/decrypt failed");
    }
    return status_ok();
}
