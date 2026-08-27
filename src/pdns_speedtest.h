/*
 * IP 测速模块（内部）—— TCP connect RTT 测量
 *
 * 测速方案：非阻塞 connect + select，超时 3 秒，每 IP 仅测 1 次，
 *   握手成功立即 close（正常四次挥手发 FIN）。
 * 不做 ICMP（部分平台已禁用；Linux 权限不通用）。
 */
#ifndef PDNS_SPEEDTEST_H
#define PDNS_SPEEDTEST_H

/*
 * 对单个 IP:port 执行一次 TCP connect 测速。
 * @return RTT 毫秒（成功，必然 < 3000）；超时/失败返回 PDNS_RTT_TIMEOUT(9999)。
 */
float pdns_speedtest_tcp(const char *ip, int port);

#endif /* PDNS_SPEEDTEST_H */
