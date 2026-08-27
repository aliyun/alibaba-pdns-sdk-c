# 单元测试（CuTest 框架，非 CTest 原生断言，但注册到 CTest 便于 ctest 驱动）
project(pdns_c_sdk_test LANGUAGES C)

# 联网集成测试开关：默认开启；CI 无外网时用 -DPDNS_TEST_NETWORK=OFF 关闭
option(PDNS_TEST_NETWORK "Build network integration tests" ON)

file(GLOB PDNS_TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

add_executable(pdns_test ${PDNS_TEST_SRC})

# 测试需访问 src/ 内部头（pdns_cache.h / pdns_acl.h 等），故直接链接静态库并加 src 包含目录
target_include_directories(pdns_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(pdns_test PRIVATE pdns_c_sdk_static)

if(PDNS_TEST_NETWORK)
    target_compile_definitions(pdns_test PRIVATE PDNS_TEST_NETWORK=1)
endif()

# math 库（CuTest 的 fabs）
if(UNIX)
    target_link_libraries(pdns_test PRIVATE m)
endif()

# ctest 注册：离线用例与全量用例分开，便于 CI 只跑离线部分
enable_testing()
add_test(NAME pdns_offline_test COMMAND pdns_test --offline)
if(PDNS_TEST_NETWORK)
    add_test(NAME pdns_all_test COMMAND pdns_test)
endif()

# 便捷 target：cmake --build . --target pdns_unit_test
add_custom_target(pdns_unit_test
    COMMAND pdns_test
    DEPENDS pdns_test
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running pdns unit tests...")
