/*
 * 链表容器测试
 *
 * 对外链表已拆为两类：域名列表（入参，可 create/add）与解析结果列表（出参，只读）。
 * 本文件覆盖域名列表的公开 API；结果列表的构造属内部行为，其读取路径在
 * select_ip / api 等用例中覆盖。
 */
#include "test_suite_list.h"

/* 创建后应为空列表 */
void test_list_create_empty(CuTest *tc) {
    pdns_domain_list_t *list = pdns_domain_list_create();
    CuAssertPtrNotNull(tc, list);
    CuAssertIntEquals_Msg(tc, "new list should be empty", 0, (int) pdns_domain_list_size(list));
    CuAssertPtrEquals_Msg(tc, "get on empty list should be NULL", NULL,
                          (void *) pdns_domain_list_get(list, 0));
    pdns_domain_list_cleanup(list);
}

/* 追加与按序读取 */
void test_list_add_and_get(CuTest *tc) {
    pdns_domain_list_t *list = pdns_domain_list_create();
    CuAssertIntEquals(tc, PDNS_OK, pdns_domain_list_add(list, "a.example.com").code);
    CuAssertIntEquals(tc, PDNS_OK, pdns_domain_list_add(list, "b.example.com").code);
    CuAssertIntEquals(tc, PDNS_OK, pdns_domain_list_add(list, "c.example.com").code);

    CuAssertIntEquals(tc, 3, (int) pdns_domain_list_size(list));
    CuAssertStrEquals(tc, "a.example.com", pdns_domain_list_get(list, 0));
    CuAssertStrEquals(tc, "b.example.com", pdns_domain_list_get(list, 1));
    CuAssertStrEquals(tc, "c.example.com", pdns_domain_list_get(list, 2));
    pdns_domain_list_cleanup(list);
}

/* 越界索引返回 NULL，不得崩溃 */
void test_list_get_out_of_range(CuTest *tc) {
    pdns_domain_list_t *list = pdns_domain_list_create();
    pdns_domain_list_add(list, "a.example.com");
    CuAssertPtrEquals_Msg(tc, "index == size should be NULL", NULL, (void *) pdns_domain_list_get(list, 1));
    CuAssertPtrEquals_Msg(tc, "index >> size should be NULL", NULL, (void *) pdns_domain_list_get(list, 999));
    pdns_domain_list_cleanup(list);
}

/* 元素为内部拷贝：调用方缓冲被改写后，列表内容不受影响 */
void test_list_stores_copy(CuTest *tc) {
    char                buf[32];
    pdns_domain_list_t *list = pdns_domain_list_create();
    snprintf(buf, sizeof(buf), "keep.example.com");
    pdns_domain_list_add(list, buf);
    snprintf(buf, sizeof(buf), "OVERWRITTEN");
    CuAssertStrEquals_Msg(tc, "list must hold its own copy", "keep.example.com",
                          pdns_domain_list_get(list, 0));
    pdns_domain_list_cleanup(list);
}

/* 非法入参与空指针防护 */
void test_list_invalid_args(CuTest *tc) {
    pdns_domain_list_t *list = pdns_domain_list_create();
    CuAssert(tc, "add NULL str should fail", pdns_domain_list_add(list, NULL).code != PDNS_OK);
    CuAssert(tc, "add to NULL list should fail", pdns_domain_list_add(NULL, "a.com").code != PDNS_OK);
    CuAssertIntEquals_Msg(tc, "size(NULL) should be 0", 0, (int) pdns_domain_list_size(NULL));
    CuAssertPtrEquals_Msg(tc, "get(NULL) should be NULL", NULL, (void *) pdns_domain_list_get(NULL, 0));
    pdns_domain_list_cleanup(list);
    pdns_domain_list_cleanup(NULL);   /* 不得崩溃 */
}

/* 允许重复值 */
void test_list_allows_duplicates(CuTest *tc) {
    pdns_domain_list_t *list = pdns_domain_list_create();
    pdns_domain_list_add(list, "dup.example.com");
    pdns_domain_list_add(list, "dup.example.com");
    CuAssertIntEquals(tc, 2, (int) pdns_domain_list_size(list));
    pdns_domain_list_cleanup(list);
}

/* 空字符串是合法元素 */
void test_list_empty_string(CuTest *tc) {
    pdns_domain_list_t *list = pdns_domain_list_create();
    CuAssertIntEquals(tc, PDNS_OK, pdns_domain_list_add(list, "").code);
    CuAssertIntEquals(tc, 1, (int) pdns_domain_list_size(list));
    CuAssertStrEquals(tc, "", pdns_domain_list_get(list, 0));
    pdns_domain_list_cleanup(list);
}

/* 较大规模追加，验证无截断/丢失 */
void test_list_many_items(CuTest *tc) {
    pdns_domain_list_t *list = pdns_domain_list_create();
    char                buf[32];
    const int           n = 500;
    for (int i = 0; i < n; i++) {
        snprintf(buf, sizeof(buf), "h%d.example.com", i);
        pdns_domain_list_add(list, buf);
    }
    CuAssertIntEquals(tc, n, (int) pdns_domain_list_size(list));
    CuAssertStrEquals(tc, "h0.example.com", pdns_domain_list_get(list, 0));
    snprintf(buf, sizeof(buf), "h%d.example.com", n - 1);
    CuAssertStrEquals(tc, buf, pdns_domain_list_get(list, (size_t) n - 1));
    pdns_domain_list_cleanup(list);
}

void add_pdns_list_tests(CuSuite *suite) {
    SUITE_ADD_TEST(suite, test_list_create_empty);
    SUITE_ADD_TEST(suite, test_list_add_and_get);
    SUITE_ADD_TEST(suite, test_list_get_out_of_range);
    SUITE_ADD_TEST(suite, test_list_stores_copy);
    SUITE_ADD_TEST(suite, test_list_invalid_args);
    SUITE_ADD_TEST(suite, test_list_allows_duplicates);
    SUITE_ADD_TEST(suite, test_list_empty_string);
    SUITE_ADD_TEST(suite, test_list_many_items);
}
