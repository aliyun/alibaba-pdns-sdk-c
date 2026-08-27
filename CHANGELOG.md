# Changelog

## 版本号：1.0.0 日期：2026-08-26

### 变更内容

**平台支持**
- macOS / Linux / Windows 三平台，CMake 构建

**核心解析**
- 同步解析（`pdns_resolve_sync`）、异步解析（`pdns_resolve_async`）、缓存优先解析（`pdns_resolve_sync_from_cache`）
- IPv4 / IPv6 / 双栈（BOTH）/ 自动（AUTO）
- HTTPS 传输 + SNI 证书校验
- HTTP/2 支持（默认开启，编译期自动检测，旧版 libcurl 自动回落 HTTP/1.1）

**缓存**
- LRU + TTL 本地缓存（含否定缓存、不可变缓存），缓存命中零网络开销

**容灾与降级**
- HTTPDNS 多次失败自动降级系统 LocalDNS
- 黑白名单 ACL（服务端下发、RC4 解密、双路径自动刷新）

**IP 测速排序**
- 基于 TCP connect RTT，支持 v4/v6 混排

**预解析与保活**
- 批量预解析、保活域名（TTL×75% 自动刷新）

**网络能力**
- 网络切换感知（自动检测并刷新）
- EDNS Client Subnet（ECS）

**自建 DNS 支持**
- 公共 DNS Provider + 自建 DNS Provider
- 主备调度 + 失败降级 + 熔断恢复

**其他**
- 线程安全，客户端实例可多线程共享
- 分级日志 + 自定义回调注入