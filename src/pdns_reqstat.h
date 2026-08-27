/*
 * 请求级统计头状态（内部）—— c / ne / se
 *
 * 发起 /resolve 请求时携带三个统计头（key = ip_host_qtype），供服务端调度优化：
 *   - c ：上次该 IP 解析该域名测得的 RTT（毫秒）
 *   - ne：该 IP 累计网络错误数
 *   - se：该 IP 上次服务器错误（5xx/401）标记
 * 生命周期：请求成功存 RTT、清 ne；网络错误 ne+1；服务器错误 se+1；
 * 构造请求头时读取并清零（发送一次后重置）。
 *
 * 采用进程级单例，线程安全（APR 互斥量）。
 */
#ifndef PDNS_REQSTAT_H
#define PDNS_REQSTAT_H

/* 初始化 / 销毁（由 pdns_sdk_init / pdns_sdk_cleanup 调用） */
void pdns_reqstat_init(void);
void pdns_reqstat_cleanup(void);

/*
 * 读取并消费该 (ip, host, qtype) 的 c/ne/se，用于构造本次请求头。
 * 读后清零。out_* 值 <=0 表示该头无需设置。
 */
void pdns_reqstat_take(const char *ip, const char *host, const char *qtype,
                       int *out_rtt_ms, int *out_ne, int *out_se);

/* 请求成功：记录本次 RTT（钳到 max_rtt_ms，<=0 不钳）供下次 c 头，并清零 ne。 */
void pdns_reqstat_on_success(const char *ip, const char *host, const char *qtype,
                             long rtt_ms, long max_rtt_ms);

/* 网络错误（传输失败）：ne 计数 +1。 */
void pdns_reqstat_on_net_error(const char *ip, const char *host, const char *qtype);

/* 服务器错误（HTTP 5xx / 401）：se 计数 +1。 */
void pdns_reqstat_on_server_error(const char *ip, const char *host, const char *qtype);

#endif /* PDNS_REQSTAT_H */
