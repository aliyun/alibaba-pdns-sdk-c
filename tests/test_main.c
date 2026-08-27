/*
 * 测试入口
 *
 * 用法：
 *   pdns_test              运行全部已启用的测试
 *   pdns_test --offline    仅运行离线单元测试（跳过联网集成测试）
 *
 * 退出码：0=全部通过，1=存在失败（便于 CI 判定）。
 */
#include "test_suite_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <apr_general.h>

int main(int argc, char **argv) {
    bool offline_only = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--offline") == 0) {
            offline_only = true;
        }
    }

    /* 离线用例直接使用 cache / provider / manager / acl 等内部模块，这些模块依赖 APR
     * 内存池与互斥量，故此处先初始化 APR 运行时。联网用例内部调用的
     * pdns_sdk_init 会再次 apr_initialize，APR 内部按引用计数处理，可安全嵌套。 */
    if (apr_initialize() != APR_SUCCESS) {
        fprintf(stderr, "apr_initialize failed\n");
        return 1;
    }

    CuString *output = CuStringNew();
    CuSuite  *suite  = CuSuiteNew();

    /* ---------------- 离线单元测试 ---------------- */
    add_pdns_list_tests(suite);
    add_pdns_util_tests(suite);
    add_pdns_sign_tests(suite);
    add_pdns_rc4_tests(suite);
    add_pdns_idn_tests(suite);
    add_pdns_cache_tests(suite);
    add_pdns_acl_tests(suite);
    add_pdns_base_provider_tests(suite);
    add_pdns_fusion_provider_tests(suite);
    add_pdns_failure_tracker_tests(suite);
    add_pdns_server_manager_tests(suite);
    add_pdns_health_checker_tests(suite);
    add_pdns_netstack_tests(suite);
    add_pdns_speedtest_tests(suite);
    add_pdns_net_tests(suite);
    add_pdns_log_tests(suite);
    add_pdns_config_tests(suite);
    add_pdns_select_ip_tests(suite);

    /* ---------------- 联网集成测试 ---------------- */
#ifdef PDNS_TEST_NETWORK
    if (!offline_only) {
        add_pdns_api_tests(suite);
        add_pdns_thread_safe_tests(suite);
    } else {
        printf("[ SKIPPED  ] network integration tests (--offline)\n");
    }
#else
    (void) offline_only;
    printf("[ SKIPPED  ] network integration tests (built with PDNS_TEST_NETWORK=OFF)\n");
#endif

    printf("[==========] running %d test(s)\n", suite->count);
    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);

    CuStringDelete(output);
    int exit_code = suite->failCount > 0 ? 1 : 0;
    CuSuiteDelete(suite);
    apr_terminate();
    return exit_code;
}
