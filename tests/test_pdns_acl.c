/*
 * 黑白名单 ACL 测试 —— ZoneTree 后缀匹配 + 精确域名 + 版本仲裁 + conf TTL
 *
 * 明文 JSON 结构（服务端 /conf 解密后）：
 *   {"v":版本,"ttl":秒,"uhf":int,"acl":{"bz":[],"bd":[],"wz":[],"wd":[]}}
 *   bz/wz = zone 后缀树，bd/wd = 精确域名集。
 * 判定规则：
 *   白名单非空时必须命中，命中黑名单则拒绝，名单皆空默认允许。
 * 注意：初始 version=0，故测试下发版本需 >= 1（v==local 只刷 TTL 不建名单）。
 */
#include "test_suite_list.h"
#include "pdns_acl.h"

#include <apr_time.h>

/* 初始状态（无任何名单）：所有域名都允许走 HTTPDNS */
void test_acl_empty_allows_all(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    CuAssertPtrNotNull(tc, acl);

    CuAssert(tc, "empty acl should allow", pdns_acl_is_normal_resolver(acl, "www.taobao.com"));
    CuAssert(tc, "empty acl should allow any", pdns_acl_is_normal_resolver(acl, "a.b.c.d.com"));
    CuAssertIntEquals_Msg(tc, "initial version should be 0", 0, (int) pdns_acl_get_version(acl));

    pdns_acl_destroy(acl);
}

/* 空域名视为不可解析 */
void test_acl_empty_domain_rejected(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    CuAssert(tc, "empty domain should be rejected", !pdns_acl_is_normal_resolver(acl, ""));
    CuAssert(tc, "NULL domain should be rejected", !pdns_acl_is_normal_resolver(acl, NULL));
    pdns_acl_destroy(acl);
}

/* acl 为 NULL 时默认允许（无管理器不应阻断解析） */
void test_acl_null_manager_allows(CuTest *tc) {
    CuAssert(tc, "NULL acl should allow", pdns_acl_is_normal_resolver(NULL, "www.taobao.com"));
}

/* 黑名单精确域名（bd）：只拦截完全相同的域名 */
void test_acl_black_domain_exact(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    pdns_acl_update_from_json(acl,
        "{\"v\":1,\"ttl\":60,\"acl\":{\"bd\":[\"block.example.com\"],\"bz\":[],\"wd\":[],\"wz\":[]}}");

    CuAssert(tc, "exact black domain should be rejected",
             !pdns_acl_is_normal_resolver(acl, "block.example.com"));
    CuAssert(tc, "sibling domain should be allowed",
             pdns_acl_is_normal_resolver(acl, "other.example.com"));
    CuAssert(tc, "subdomain of exact entry should be allowed",
             pdns_acl_is_normal_resolver(acl, "a.block.example.com"));

    pdns_acl_destroy(acl);
}

/* 黑名单 zone（bz）：后缀通配，自身与所有子域都被拦截 */
void test_acl_black_zone_suffix(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    pdns_acl_update_from_json(acl,
        "{\"v\":1,\"ttl\":60,\"acl\":{\"bz\":[\"bad.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");

    CuAssert(tc, "zone itself should be rejected", !pdns_acl_is_normal_resolver(acl, "bad.com"));
    CuAssert(tc, "subdomain should be rejected", !pdns_acl_is_normal_resolver(acl, "www.bad.com"));
    CuAssert(tc, "deep subdomain should be rejected",
             !pdns_acl_is_normal_resolver(acl, "a.b.c.bad.com"));
    CuAssert(tc, "similar-but-different domain should be allowed",
             pdns_acl_is_normal_resolver(acl, "notbad.com"));
    CuAssert(tc, "different tld should be allowed", pdns_acl_is_normal_resolver(acl, "bad.cn"));

    pdns_acl_destroy(acl);
}

/* 白名单非空时：只有命中白名单的域名才允许 */
void test_acl_white_list_restricts(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    pdns_acl_update_from_json(acl,
        "{\"v\":1,\"ttl\":60,\"acl\":{\"wz\":[\"good.com\"],\"wd\":[\"exact.org\"],"
        "\"bz\":[],\"bd\":[]}}");

    CuAssert(tc, "white zone should be allowed", pdns_acl_is_normal_resolver(acl, "www.good.com"));
    CuAssert(tc, "white zone itself should be allowed", pdns_acl_is_normal_resolver(acl, "good.com"));
    CuAssert(tc, "white exact domain should be allowed", pdns_acl_is_normal_resolver(acl, "exact.org"));
    CuAssert(tc, "non-whitelisted domain should be rejected",
             !pdns_acl_is_normal_resolver(acl, "www.other.com"));
    CuAssert(tc, "subdomain of white exact entry should be rejected",
             !pdns_acl_is_normal_resolver(acl, "a.exact.org"));

    pdns_acl_destroy(acl);
}

/* 同时命中白名单与黑名单时，黑名单优先（拒绝） */
void test_acl_black_takes_precedence(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    pdns_acl_update_from_json(acl,
        "{\"v\":1,\"ttl\":60,\"acl\":{\"wz\":[\"site.com\"],\"bz\":[\"deny.site.com\"],"
        "\"wd\":[],\"bd\":[]}}");

    CuAssert(tc, "white-only domain should be allowed",
             pdns_acl_is_normal_resolver(acl, "ok.site.com"));
    CuAssert(tc, "domain in both lists should be rejected",
             !pdns_acl_is_normal_resolver(acl, "deny.site.com"));
    CuAssert(tc, "subdomain of black zone should be rejected",
             !pdns_acl_is_normal_resolver(acl, "x.deny.site.com"));

    pdns_acl_destroy(acl);
}

/* 域名尾部的 '.' 应被标准化忽略 */
void test_acl_trailing_dot_normalized(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    pdns_acl_update_from_json(acl,
        "{\"v\":1,\"ttl\":60,\"acl\":{\"bz\":[\"bad.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");

    CuAssert(tc, "trailing dot should be normalized",
             !pdns_acl_is_normal_resolver(acl, "www.bad.com."));
    CuAssert(tc, "multiple trailing dots should be normalized",
             !pdns_acl_is_normal_resolver(acl, "www.bad.com..."));

    pdns_acl_destroy(acl);
}

/* 版本仲裁：v > local 完整重建名单 */
void test_acl_version_upgrade_rebuilds(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();

    pdns_acl_update_from_json(acl,
        "{\"v\":10,\"ttl\":60,\"acl\":{\"bz\":[\"old.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");
    CuAssertIntEquals_Msg(tc, "version should be updated", 10, (int) pdns_acl_get_version(acl));
    CuAssert(tc, "old.com should be blocked", !pdns_acl_is_normal_resolver(acl, "old.com"));

    /* 更高版本：名单被整体替换，old.com 不再受限，new.com 开始受限 */
    pdns_acl_update_from_json(acl,
        "{\"v\":11,\"ttl\":60,\"acl\":{\"bz\":[\"new.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");
    CuAssertIntEquals(tc, 11, (int) pdns_acl_get_version(acl));
    CuAssert(tc, "old entry should be cleared after rebuild",
             pdns_acl_is_normal_resolver(acl, "old.com"));
    CuAssert(tc, "new entry should take effect", !pdns_acl_is_normal_resolver(acl, "new.com"));

    pdns_acl_destroy(acl);
}

/* 版本仲裁：v < local 直接放弃，名单与版本均不变 */
void test_acl_version_downgrade_abandoned(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();

    pdns_acl_update_from_json(acl,
        "{\"v\":100,\"ttl\":60,\"acl\":{\"bz\":[\"keep.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");
    pdns_acl_update_from_json(acl,
        "{\"v\":99,\"ttl\":60,\"acl\":{\"bz\":[\"ignored.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");

    CuAssertIntEquals_Msg(tc, "version must not regress", 100, (int) pdns_acl_get_version(acl));
    CuAssert(tc, "existing list must be kept", !pdns_acl_is_normal_resolver(acl, "keep.com"));
    CuAssert(tc, "stale list must be ignored", pdns_acl_is_normal_resolver(acl, "ignored.com"));

    pdns_acl_destroy(acl);
}

/* 版本仲裁：v == local 仅刷新 TTL，不重建名单 */
void test_acl_same_version_refreshes_ttl_only(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();

    pdns_acl_update_from_json(acl,
        "{\"v\":5,\"ttl\":60,\"acl\":{\"bz\":[\"keep.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");
    /* 同版本但名单不同：名单应保持原样 */
    pdns_acl_update_from_json(acl,
        "{\"v\":5,\"ttl\":120,\"acl\":{\"bz\":[\"should-not-apply.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");

    CuAssertIntEquals(tc, 5, (int) pdns_acl_get_version(acl));
    CuAssert(tc, "list must remain unchanged on same version",
             !pdns_acl_is_normal_resolver(acl, "keep.com"));
    CuAssert(tc, "same-version list must not be applied",
             pdns_acl_is_normal_resolver(acl, "should-not-apply.com"));

    pdns_acl_destroy(acl);
}

/* 非法 / 缺字段 JSON 应被安全忽略，不得崩溃或误清名单 */
void test_acl_invalid_json_ignored(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();

    pdns_acl_update_from_json(acl,
        "{\"v\":3,\"ttl\":60,\"acl\":{\"bz\":[\"bad.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");

    pdns_acl_update_from_json(acl, "not a json");
    pdns_acl_update_from_json(acl, "{}");                       /* 缺 v，应放弃 */
    pdns_acl_update_from_json(acl, "{\"ttl\":60}");             /* 缺 v，应放弃 */
    pdns_acl_update_from_json(acl, "");
    pdns_acl_update_from_json(acl, NULL);
    pdns_acl_update_from_json(NULL, "{\"v\":9}");

    CuAssertIntEquals_Msg(tc, "version should stay", 3, (int) pdns_acl_get_version(acl));
    CuAssert(tc, "list should stay effective", !pdns_acl_is_normal_resolver(acl, "bad.com"));

    pdns_acl_destroy(acl);
}

/* v / ttl 以字符串形式下发时也应被正确解析 */
void test_acl_string_typed_fields(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();
    pdns_acl_update_from_json(acl,
        "{\"v\":\"42\",\"ttl\":\"60\",\"acl\":{\"bz\":[\"s.com\"],\"bd\":[],\"wd\":[],\"wz\":[]}}");

    CuAssertIntEquals_Msg(tc, "string version should be parsed", 42, (int) pdns_acl_get_version(acl));
    CuAssert(tc, "list from string-typed payload should work",
             !pdns_acl_is_normal_resolver(acl, "s.com"));

    pdns_acl_destroy(acl);
}

/* conf TTL：从未拉取过时不算过期；拉取后未到期不算过期；超时后算过期 */
void test_acl_conf_expire(CuTest *tc) {
    pdns_acl_t *acl = pdns_acl_create();

    CuAssert(tc, "never-fetched conf should not be treated as expired",
             !pdns_acl_is_conf_expired(acl));

    /* ttl=1 秒，便于快速验证过期 */
    pdns_acl_update_from_json(acl,
        "{\"v\":1,\"ttl\":1,\"acl\":{\"bz\":[],\"bd\":[],\"wd\":[],\"wz\":[]}}");
    CuAssert(tc, "freshly fetched conf should not be expired", !pdns_acl_is_conf_expired(acl));

    apr_sleep(1100 * 1000);   /* 1.1 秒 */
    CuAssert(tc, "conf should expire after ttl", pdns_acl_is_conf_expired(acl));

    /* touch 后重新计时（拉取失败时的重试节流） */
    pdns_acl_touch_conf_time(acl);
    CuAssert(tc, "touch should reset expire timer", !pdns_acl_is_conf_expired(acl));

    pdns_acl_destroy(acl);
}

/* NULL 防护 */
void test_acl_null_safety(CuTest *tc) {
    CuAssert(tc, "NULL acl not expired", !pdns_acl_is_conf_expired(NULL));
    CuAssertIntEquals(tc, 0, (int) pdns_acl_get_version(NULL));
    pdns_acl_touch_conf_time(NULL);
    pdns_acl_destroy(NULL);
}

void add_pdns_acl_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_acl_empty_allows_all);
    SUITE_ADD_TEST(suite, test_acl_empty_domain_rejected);
    SUITE_ADD_TEST(suite, test_acl_null_manager_allows);
    SUITE_ADD_TEST(suite, test_acl_black_domain_exact);
    SUITE_ADD_TEST(suite, test_acl_black_zone_suffix);
    SUITE_ADD_TEST(suite, test_acl_white_list_restricts);
    SUITE_ADD_TEST(suite, test_acl_black_takes_precedence);
    SUITE_ADD_TEST(suite, test_acl_trailing_dot_normalized);
    SUITE_ADD_TEST(suite, test_acl_version_upgrade_rebuilds);
    SUITE_ADD_TEST(suite, test_acl_version_downgrade_abandoned);
    SUITE_ADD_TEST(suite, test_acl_same_version_refreshes_ttl_only);
    SUITE_ADD_TEST(suite, test_acl_invalid_json_ignored);
    SUITE_ADD_TEST(suite, test_acl_string_typed_fields);
    SUITE_ADD_TEST(suite, test_acl_conf_expire);
    SUITE_ADD_TEST(suite, test_acl_null_safety);
}
