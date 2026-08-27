add_executable(sync_resolve sync_resolve.c)
target_link_libraries(sync_resolve PRIVATE pdns_c_sdk_static)

add_executable(async_resolve async_resolve.c)
target_link_libraries(async_resolve PRIVATE pdns_c_sdk_static)

add_executable(preload_resolve preload_resolve.c)
target_link_libraries(preload_resolve PRIVATE pdns_c_sdk_static)

add_executable(keepalive_resolve keepalive_resolve.c)
target_link_libraries(keepalive_resolve PRIVATE pdns_c_sdk_static)

add_executable(fusion_resolve fusion_resolve.c)
target_link_libraries(fusion_resolve PRIVATE pdns_c_sdk_static)

# C++ / Qt 集成示例：SDK 本身是纯 C（顶层 project 只声明了 LANGUAGES C），
# 仅此示例需要 C++ 编译器，故在此按需启用，不影响主库的纯 C 定位。
enable_language(CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(cxx_integration cxx_integration.cpp)
# 示例直接调用 libcurl 演示 IP 直连访问业务，故显式声明该依赖
# （pdns_c_sdk_static 已 PUBLIC 链接 CURL::libcurl，此处显式写出以表达意图）
target_link_libraries(cxx_integration PRIVATE pdns_c_sdk_static CURL::libcurl)
