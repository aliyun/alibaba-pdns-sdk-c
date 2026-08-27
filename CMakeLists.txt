# 最低 3.13，约束来自两处（已实测：3.10 configure 失败，3.12 通过）：
#   3.12  FindCURL 开始提供 CURL::libcurl 导入目标（下方 PDNS_LINK_LIBS 使用）；
#         低于此版本报 “target was not found ... missing for an IMPORTED target”。
#   3.13  支持 cmake -S <src> -B <build>（README 与验证文档的构建命令使用）。
cmake_minimum_required(VERSION 3.13)

# vcpkg 工具链（Windows 必需，其他平台可选）——必须在 project() 之前设置
if(DEFINED VCPKG_ROOT)
    set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "vcpkg toolchain file")
elseif(WIN32)
    message(FATAL_ERROR "Windows 平台必须指定 -DVCPKG_ROOT=<vcpkg 安装路径>")
endif()

# macOS 最低支持版本（必须在 project() 之前设置才生效）。
# 不显式固定时会取构建机的系统版本（如 15.0），导致产物无法在更低版本的
# 集成方机器上链接或运行——二进制交付必须固定此值。可用 -D 覆盖。
if(APPLE AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS version")
endif()

project(pdns_c_sdk LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# 是否构建动态库，默认开启（静态库始终构建，动态库默认同时产出）。
# 构建 universal（arm64;x86_64）静态库时应关闭本项：动态库在编译期需要
# 真实链接 curl/APR 等依赖，而包管理器安装的依赖通常只有当前架构，
# 无法满足 universal 链接；静态库不在编译期链接依赖，故不受此限。
option(PDNS_BUILD_SHARED "Build shared library (disable when packaging universal static lib)" ON)

# 输出目录：产物统一输出到 <BINARY_DIR>/build/<BuildType>/{lib,bin}
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build/${CMAKE_BUILD_TYPE}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build/${CMAKE_BUILD_TYPE}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build/${CMAKE_BUILD_TYPE}/bin)

# 编译选项
if(UNIX)
    add_compile_options(-Wall -fPIC)
elseif(WIN32)
    add_compile_options(/W3)
endif()

# ---------------- 依赖查找 ----------------
# 注：不依赖 OpenSSL。SHA-256 已内置于 pdns_sign.c（FIPS 180-4），
# RC4 内置于 pdns_rc4.c，故加密相关无第三方依赖。
# 此举使静态交付时约减小 4~5MB，并避免与宿主程序自带的 libcrypto
# 共存两份全局状态（版本不一致时可致崩溃）。
# cJSON 已内嵌（见下方 PDNS_TP_CJSON），无需外部查找。
find_package(CURL REQUIRED)

# APR / apr-util：vcpkg / macOS(brew) / Linux(apr-config) 三种查找方式
if(DEFINED VCPKG_ROOT)
    find_path(APR_INCLUDE_DIR NAMES apr.h PATH_SUFFIXES apr-1)
    find_path(APU_INCLUDE_DIR NAMES apu.h PATH_SUFFIXES apr-1)
    if(WIN32)
        find_library(APR_LIBRARIES NAMES libapr-1 apr-1)
        find_library(APU_LIBRARIES NAMES libaprutil-1 aprutil-1)
    else()
        find_library(APR_LIBRARIES NAMES apr-1)
        find_library(APU_LIBRARIES NAMES aprutil-1)
    endif()
elseif(APPLE)
    execute_process(COMMAND brew --prefix apr
        OUTPUT_VARIABLE APR_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND brew --prefix apr-util
        OUTPUT_VARIABLE APU_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APR_PREFIX}/bin/apr-1-config --includedir
        OUTPUT_VARIABLE APR_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APR_PREFIX}/bin/apr-1-config --link-ld
        OUTPUT_VARIABLE APR_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APU_PREFIX}/bin/apu-1-config --includedir
        OUTPUT_VARIABLE APU_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APU_PREFIX}/bin/apu-1-config --link-ld
        OUTPUT_VARIABLE APU_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
    find_program(APR_CONFIG NAMES apr-1-config apr-config
        PATHS /usr/bin /usr/local/bin /usr/local/apr/bin)
    find_program(APU_CONFIG NAMES apu-1-config apu-config
        PATHS /usr/bin /usr/local/bin /usr/local/apr/bin)
    execute_process(COMMAND ${APR_CONFIG} --includedir
        OUTPUT_VARIABLE APR_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APR_CONFIG} --link-ld
        OUTPUT_VARIABLE APR_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APU_CONFIG} --includedir
        OUTPUT_VARIABLE APU_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APU_CONFIG} --link-ld
        OUTPUT_VARIABLE APU_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

# apr-config --link-ld 输出可能带首尾空格，需 STRIP，否则触发 CMP0004 链接错误
if(APR_LIBRARIES)
    string(STRIP "${APR_LIBRARIES}" APR_LIBRARIES)
endif()
if(APU_LIBRARIES)
    string(STRIP "${APU_LIBRARIES}" APU_LIBRARIES)
endif()

message(STATUS "APR_INCLUDE_DIR = ${APR_INCLUDE_DIR}")
message(STATUS "APU_INCLUDE_DIR = ${APU_INCLUDE_DIR}")
message(STATUS "APR_LIBRARIES   = ${APR_LIBRARIES}")
message(STATUS "APU_LIBRARIES   = ${APU_LIBRARIES}")

# ---------------- 头文件目录 ----------------
set(PDNS_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${APR_INCLUDE_DIR}
    ${APU_INCLUDE_DIR})

# ---------------- 源文件 ----------------
file(GLOB PDNS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# 内嵌第三方：cJSON v1.7.18（符号已改名 pdns_cJSON_*，与集成方环境中的 cJSON 完全隔离）。
# 内嵌原因：cJSON 结构体布局公开且本 SDK 直接访问字段，编译期头文件与链接期库必须同源；
# 外置依赖时若集成方环境版本不同，存在 ABI 风险；改名后则无符号冲突、无版本依赖。
set(PDNS_TP_CJSON "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson/pdns_cjson.c")

# 内嵌 cJSON 符号不得从动态库导出（否则集成方可误用内部实现，将来升级 cJSON 会被锁死）：
# 符号已改名 pdns_cJSON_*（与集成方环境隔离）；动态库默认全隐藏（见下方
# C_VISIBILITY_PRESET），此处仅保留 Windows 的 dllexport 关闭开关。
set_source_files_properties(${PDNS_TP_CJSON} PROPERTIES
    COMPILE_DEFINITIONS "PDNS_CJSON_HIDE_SYMBOLS")

set(PDNS_LINK_LIBS CURL::libcurl ${APU_LIBRARIES} ${APR_LIBRARIES})

# Windows 平台：枚举网卡需链接 iphlpapi/ws2_32
if(WIN32)
    list(APPEND PDNS_LINK_LIBS iphlpapi ws2_32)
endif()

# Linux 平台：静态链接 APR 时需显式补 -ldl。
# APR-util 的可选模块（DBD / crypto / LDAP）内部通过 dlopen 动态加载，
# 故 libapr/libaprutil 引用了 dlopen/dlsym 符号；而 glibc 2.34 之前这些符号位于
# 独立的 libdl，不补会报 undefined reference to `dlopen`。
# macOS 的 dlopen 已在 libSystem 内，无需单独链接，故排除 APPLE。
# （本 SDK 自身不调用 dlopen，此为 APR 的传递性依赖。）
if(UNIX AND NOT APPLE)
    list(APPEND PDNS_LINK_LIBS dl)
endif()

# 静态库（二进制交付首选：不记录任何依赖绝对路径，依赖由集成方链接时解析）
add_library(pdns_c_sdk_static STATIC ${PDNS_SRC} ${PDNS_TP_CJSON})
target_include_directories(pdns_c_sdk_static PUBLIC ${PDNS_INCLUDE_DIRS})
# 内嵌 cJSON 头文件仅供库内部编译使用，不随 PUBLIC 暴露给集成方
target_include_directories(pdns_c_sdk_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson)
target_link_libraries(pdns_c_sdk_static PUBLIC ${PDNS_LINK_LIBS})

# 动态库
if(PDNS_BUILD_SHARED)
    add_library(pdns_c_sdk SHARED ${PDNS_SRC} ${PDNS_TP_CJSON})
    target_include_directories(pdns_c_sdk PUBLIC ${PDNS_INCLUDE_DIRS})
    target_include_directories(pdns_c_sdk PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson)
    target_link_libraries(pdns_c_sdk PUBLIC ${PDNS_LINK_LIBS})

    # 符号导出控制：默认全隐藏，仅 pdns_api.h 中带 PDNS_API 标记的公开 API 导出。
    # 防止内部实现（密钥、RC4、缓存、provider 等）被集成方误用而锁死 ABI。
    set_target_properties(pdns_c_sdk PROPERTIES
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
    target_compile_definitions(pdns_c_sdk PRIVATE PDNS_BUILDING_SHARED)
endif()
# 禁止动态库残留未定义符号。
# ld 默认允许 .so 存在未解析符号（设计意图是留给运行时由宿主提供），
# 这会把"静态库链接顺序错误"之类的问题推迟到集成方 dlopen/启动时才报
#   symbol lookup error: undefined symbol: apr_thread_cond_create
# 加上 --no-undefined 后，同样的问题在本地编译期就会失败，便于及早发现。
# macOS 的 ld64 对 dylib 默认即为 -undefined error，无需显式设置。
if(UNIX AND NOT APPLE)
    set_target_properties(pdns_c_sdk PROPERTIES LINK_FLAGS "-Wl,--no-undefined")
endif()


# ---------------- 安装 ----------------
install(TARGETS pdns_c_sdk_static ARCHIVE DESTINATION lib)
if(PDNS_BUILD_SHARED)
    install(TARGETS pdns_c_sdk
            LIBRARY DESTINATION lib
            RUNTIME DESTINATION bin)
endif()
install(DIRECTORY include/pdns DESTINATION include)

# ---------------- 示例 ----------------
# 构建 universal 静态库时应关闭示例（示例为可执行文件，需真实链接单架构依赖）
option(PDNS_BUILD_EXAMPLES "Build examples" ON)
if(PDNS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ---------------- 单元测试 ----------------
# 同示例：universal 静态库打包时应关闭（测试可执行文件需真实链接单架构依赖）
option(PDNS_BUILD_TESTS "Build unit tests" ON)
if(PDNS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
