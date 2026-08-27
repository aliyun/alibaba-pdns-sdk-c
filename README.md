# 阿里云 移动解析HTTPDNS C SDK

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)

## 关于
阿里云 移动解析HTTPDNS C SDK 是面向桌面端（Linux / macOS / Windows）的跨平台 C 语言 HTTPDNS SDK，用于替代系统 LocalDNS，
解决 DNS 劫持、解析慢、跨网调度不准等问题。

## 快速开始

```c
#include <stdio.h>
#include <pdns/pdns_api.h>

int main(void) {
    pdns_sdk_init();                                        /* 1. 全局初始化 */

    pdns_client_t *client = pdns_client_create();           /* 2. 创建实例 */
    pdns_client_init_public_dns(client,
        "your_account_id", "your_access_key_id", "your_access_key_secret");
    pdns_client_start(client);                              /* 3. 启动 */

    pdns_result_list_t *results = NULL;                     /* 4. 解析 */
    pdns_status_t st = pdns_resolve_sync(client, "www.taobao.com",
                                         PDNS_QUERY_AUTO, &results);
    if (pdns_status_is_ok(&st)) {
        for (size_t i = 0; i < pdns_result_list_size(results); i++)
            printf("IP: %s\n", pdns_result_list_get(results, i));
        pdns_result_list_cleanup(results);
    } else {
        printf("resolve failed: %s\n", st.error_msg);
    }

    pdns_client_cleanup(client);                            /* 5. 清理 */
    pdns_sdk_cleanup();
    return 0;
}
```

> 鉴权参数（`account_id` / `access_key_id` / `access_key_secret`）从阿里云控制台获取，
> 详见[移动解析 HTTPDNS 产品文档](https://dnsnext.console.aliyun.com/pdnsDoh)。

## 平台支持

| 平台 | 架构 | 编译器 | 已验证环境 |
|------|------|--------|-----------|
| macOS | arm64 / x86_64（可合并 universal 包） | Xcode clang | macOS 15（arm64） |
| Linux | x86_64 / ARM64 | gcc 4.8 及以上 | glibc ≥ 2.17（CentOS 7 基线，gcc 4.8.5） |
| Windows | x86 / x64 | Visual Studio 2019+（MSVC） | — |

## 安装依赖

### 1. 构建工具

| 工具 | 版本要求 | 说明 |
|------|---------|------|
| git | 较新版本即可 | 拉取源码 |
| CMake | ≥ 3.13 | 构建系统 |
| C 编译器 | gcc 4.8+ / clang / MSVC 2019+ | C99 |

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y git cmake gcc

# Aliyun Linux / CentOS Stream / Fedora
sudo yum check-update && sudo yum install -y git cmake gcc

# CentOS 7（官方源无 cmake3，需 EPEL）
sudo yum install -y epel-release && sudo yum install -y git cmake3 gcc

# macOS（需先安装 Homebrew）
brew install git cmake
```

> Windows：下载安装 [Git](https://git-scm.com/)，下载安装 [Visual Studio](https://visualstudio.microsoft.com/)
> （工作负载勾选「使用 C++ 的桌面开发」，自带 CMake 与 MSVC）。

### 2. 第三方库

| 依赖 | 版本要求 | 用途 |
|------|---------|------|
| libcurl | ≥ 7.21.3（macOS/Linux）；≥ 7.71.0（Windows） | HTTP/HTTPS 请求 |
| APR / APR-util | ≥ 1.5.2 | 内存池、线程池、跨平台屏蔽 |
| cJSON | 内嵌，无需安装 | JSON 解析 |

> cJSON 已内嵌进 SDK（`third_party/cjson`，符号改名 `pdns_cJSON_*`），
> 与宿主程序自带的 cJSON 无符号冲突，也无需任何安装步骤。
>
> HTTP/2 为默认开启的可选能力：编译环境 libcurl ≥ 7.43.0 时自动通过 ALPN 协商启用
> （失败自动回落 HTTP/1.1）；旧版 libcurl（如 CentOS 7 自带 7.29.0）自动走 HTTP/1.1，
> 构建运行不受影响。可用 `pdns_client_set_enable_http2` 显式关闭。

**方式 A：vcpkg（推荐，Windows 必需）**

```bash
# macOS / Linux
./vcpkg install apr apr-util curl[openssl,http2]
# Windows（PowerShell）
.\vcpkg.exe install apr apr-util curl[openssl,http2]
```

> `curl[openssl,http2]` 的方括号是 vcpkg 的 feature 选择：`openssl` 指定 libcurl 的
> TLS 后端（HTTPS 必需），`http2` 启用 HTTP/2 支持。SDK 自身不链接 OpenSSL
> （SHA-256 已内置实现），OpenSSL 仅作为 libcurl 的传递性依赖。
>
> 跨平台编译（如 Windows x64 环境编译 x86 库）需指定 triplet，例如：
> `./vcpkg.exe install apr:x86-windows apr-util:x86-windows curl[openssl,http2]:x86-windows`

**方式 B：系统包管理器**

```bash
# Ubuntu / Debian
sudo apt install -y libcurl4-openssl-dev libapr1-dev libaprutil1-dev

# Aliyun Linux / CentOS Stream / Fedora
sudo yum install -y libcurl-devel apr-devel apr-util-devel

# OpenSUSE
sudo zypper install -y libcurl-devel libapr1-devel libapr-util1-devel

# macOS
brew install curl apr apr-util
```

> Windows 手动安装：分别下载 curl / apr / apr-util 官方包，并将头文件与库目录
> 加入工程配置；推荐直接使用 vcpkg 方式。

## 构建

在**项目根目录**（CMakeLists.txt 所在目录）依次执行以下两条命令：

```bash
# 第一步：配置。检测依赖环境，在 build/ 目录下生成工程文件
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# 第二步：编译。产物输出到 build/build/Release/ 下
cmake --build build
```

> 参数说明：`-S .` 指定源码目录（当前目录）；`-B build` 指定工程生成目录（中间文件
> 与产物都在 `build/` 内，源码目录不被污染）；`-DCMAKE_BUILD_TYPE=Release` 编译优化版。
>
> 若依赖通过 vcpkg 安装，在第一步追加 `-DVCPKG_ROOT=<vcpkg 安装路径>`：
> `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVCPKG_ROOT=<vcpkg 安装路径>`

产物位置（假设构建目录名为 build）：

| 平台 | 库文件 | 示例程序 |
|------|--------|---------|
| Linux / macOS | `build/build/Release/lib/libpdns_c_sdk_static.a` | `build/build/Release/bin/` |
| Windows | `build/build/Release/lib/pdns_c_sdk_static.lib` | `build/build/Release/bin/` |

> 动态库默认与静态库同时构建（`libpdns_c_sdk.so` / `.dylib` / `.dll`）；如只需静态库
> （如打包 universal 包），在第一步追加 `-DPDNS_BUILD_SHARED=OFF`。
>
> Windows 也可直接用 Visual Studio（工作负载勾选「使用 C++ 的桌面开发」）
> 打开本 CMake 工程，在 CMake 设置中配置 `-DVCPKG_ROOT=<vcpkg 安装路径>` 后直接生成。

## API 概览

完整 API 见 [include/pdns/pdns_api.h](include/pdns/pdns_api.h)（唯一对外头文件），按职责分组：

| 分组 | 接口 |
|------|------|
| 生命周期 | `pdns_sdk_init` `pdns_sdk_cleanup` `pdns_client_create` `pdns_client_start` `pdns_client_cleanup` |
| 服务配置 | `pdns_client_init_public_dns`（公共 DNS）`pdns_client_init_fusion_dns`（自建 DNS）`pdns_client_set_fallback_threshold` `pdns_client_set_fusion_certificate_validation` |
| 解析 | `pdns_resolve_sync`（同步）`pdns_resolve_async`（异步回调）`pdns_resolve_sync_from_cache`（缓存优先） |
| 预解析/保活 | `pdns_client_add_pre_load_domains` `pdns_client_set_keep_alive_domains` `pdns_domain_list_create/add/get/size/cleanup` |
| 结果 | `pdns_result_list_size/get/get_source/is_from_cache/cleanup` `pdns_select_ip_randomly` `pdns_select_ip_first` |
| 配置 | `pdns_client_set_timeout` `...enable_cache` `...enable_speed_test` `...speed_port` `...enable_localdns` `...enable_ipv6` `...max/min_ttl_cache` `...max_cache_size` `...max_concurrent_resolve_count` `...enable_http2` 等 |
| 网络 | `pdns_set_enable_network_change` `pdns_on_network_changed` |
| 日志 | `pdns_log_set_enable` `pdns_log_set_level` `pdns_log_set_logger` |
| 其他 | `pdns_version` `pdns_status_is_ok` `pdns_source_name` `pdns_client_get_session_id` |

约定：函数统一 `pdns_` 前缀，宏/枚举统一 `PDNS_` 前缀；头文件已 `extern "C"` 包裹，
C++（Qt）可直接调用。

## 示例

| 示例 | 演示内容 |
|------|---------|
| [sync_resolve](examples/sync_resolve.c) | 同步解析、缓存读取、黑白名单拦截、双栈 BOTH |
| [async_resolve](examples/async_resolve.c) | 异步解析与回调 |
| [preload_resolve](examples/preload_resolve.c) | 批量预解析 |
| [keepalive_resolve](examples/keepalive_resolve.c) | 保活域名（TTL×75% 刷新） |
| [fusion_resolve](examples/fusion_resolve.c) | 自建 DNS：单公共 / 单自建 / 主备组合与降级链路 |
| [cxx_integration](examples/cxx_integration.cpp) | C++/Qt 集成：RAII 封装、IP 直连 + SNI 校验、多 IP failover |

```bash
./build/build/Release/bin/sync_resolve www.taobao.com v4
./build/build/Release/bin/async_resolve www.taobao.com both
```

> 拿到 IP 之后怎么用：通过 libcurl `CURLOPT_RESOLVE` 注入 `host:port:ip`，
> TCP 连到 HTTPDNS 返回的 IP，TLS 握手与证书校验仍按**域名**进行。
> 完整做法见 [cxx_integration](examples/cxx_integration.cpp)。

## 测试

测试基于 CuTest（单文件框架，仅置于 `tests/`），离线用例无需联网，联网用例打真实服务：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target pdns_test

./build/build/Debug/bin/pdns_test            # 全部用例
./build/build/Debug/bin/pdns_test --offline  # 仅离线用例（无外网环境）
```

也可用 CTest 驱动（已注册 `pdns_offline_test` 与 `pdns_all_test`）：

```bash
cd build && ctest --output-on-failure
```
