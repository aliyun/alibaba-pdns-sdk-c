/*
 * 通用工具实现 —— 请求级追踪 ID 生成
 *
 * 格式：{platform}_{16位设备前缀hex}_{16位计数器hex}
 *   - platform：cwindows / cmac / clinux（SDK 前缀）
 *   - 设备前缀：取操作系统稳定设备标识后 16 位小写 hex，进程内生成一次、跨重启不变
 *     （macOS gethostuuid / Linux /etc/machine-id / Windows 注册表 MachineGuid）；
 *      取不到时 fallback 随机 UUID（此时跨重启会变，仅兑底）
 *   - 计数器：初值 = 毫秒时间戳 << 20，自增，%016x
 */
#include "pdns_util.h"
#include "pdns_log.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_time.h>
#include <apr_uuid.h>
#include <apr_general.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <time.h>
#include <uuid/uuid.h>
#endif

/* PDNS_PLATFORM 定义在 pdns_const.h */
#include "pdns_const.h"

static apr_pool_t         *g_pool = NULL;
static apr_thread_mutex_t *g_lock = NULL;
static char                g_device_prefix[17] = {0};   /* 16 hex + '\0' */
static apr_int64_t         g_counter = 0;

/* 从任意字符串提取小写 hex 字符，取后 16 位写入 g_device_prefix（不足前补 0） */
static void set_prefix_from_string(const char *raw) {
    char hex[128];
    int  n = 0;
    for (int i = 0; raw[i] != '\0' && n < (int) sizeof(hex) - 1; i++) {
        if (isxdigit((unsigned char) raw[i])) {
            hex[n++] = (char) tolower((unsigned char) raw[i]);
        }
    }
    if (n >= 16) {
        memcpy(g_device_prefix, hex + n - 16, 16);
    } else {
        int pad = 16 - n;
        memset(g_device_prefix, '0', (size_t) pad);
        memcpy(g_device_prefix + pad, hex, (size_t) n);
    }
    g_device_prefix[16] = '\0';
}

/* 读取操作系统稳定设备标识（跨重启不变）。成功写入 buf 返回 true。
 *   - Windows：HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
 *   - macOS  ：gethostuuid（硬件 UUID）
 *   - Linux  ：/etc/machine-id（或 /var/lib/dbus/machine-id） */
static bool read_platform_device_id(char *buf, size_t buflen) {
#if defined(_WIN32)
    DWORD sz = (DWORD) buflen;
    LONG  rc = RegGetValueA(HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Microsoft\\Cryptography",
                            "MachineGuid",
                            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                            NULL, buf, &sz);
    return rc == ERROR_SUCCESS && buf[0] != '\0';
#elif defined(__APPLE__)
    uuid_t          id;
    struct timespec ts = {0, 0};
    if (gethostuuid(id, &ts) == 0) {
        uuid_unparse(id, buf);   /* buf 需 >= 37 字节 */
        return buf[0] != '\0';
    }
    return false;
#else
    const char *paths[] = {"/etc/machine-id", "/var/lib/dbus/machine-id"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        FILE *f = fopen(paths[i], "r");
        if (f != NULL) {
            char *r = fgets(buf, (int) buflen, f);
            fclose(f);
            if (r != NULL && buf[0] != '\0') {
                return true;
            }
        }
    }
    return false;
#endif
}

/* 生成 16 位设备前缀：优先取平台稳定设备标识，
 * 跨重启不变；取不到才 fallback 随机 UUID（此时跨重启会变，仅兑底）。 */
static void gen_device_prefix(void) {
    char raw[128] = {0};
    if (read_platform_device_id(raw, sizeof(raw)) && raw[0] != '\0') {
        set_prefix_from_string(raw);
        return;
    }
    /* fallback：随机 UUID（跨重启会变，记警告） */
    apr_uuid_t uuid;
    apr_uuid_get(&uuid);
    char formatted[APR_UUID_FORMATTED_LENGTH + 1];
    apr_uuid_format(formatted, &uuid);
    set_prefix_from_string(formatted);
    PDNS_LOGW("device prefix: platform device id unavailable, "
              "fallback to random UUID (not stable across restarts)");
}

void pdns_util_init(void) {
    if (g_lock != NULL) {
        return;
    }
    if (apr_pool_create(&g_pool, NULL) == APR_SUCCESS) {
        apr_thread_mutex_create(&g_lock, APR_THREAD_MUTEX_DEFAULT, g_pool);
    }
    gen_device_prefix();
    /* 计数器初值 = 毫秒时间戳 << 20 */
    g_counter = (apr_int64_t) (apr_time_now() / 1000) << 20;
}

void pdns_util_cleanup(void) {
    if (g_lock != NULL) {
        apr_thread_mutex_destroy(g_lock);
        g_lock = NULL;
    }
    if (g_pool != NULL) {
        apr_pool_destroy(g_pool);
        g_pool = NULL;
    }
}

void pdns_gen_request_id(char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    /* 防御：未 init 时懒生成设备前缀 */
    if (g_device_prefix[0] == '\0') {
        gen_device_prefix();
    }

    apr_int64_t c;
    if (g_lock != NULL) {
        apr_thread_mutex_lock(g_lock);
    }
    c = ++g_counter;
    if (g_lock != NULL) {
        apr_thread_mutex_unlock(g_lock);
    }

    snprintf(out, out_len, "%s_%s_%016llx",
             PDNS_PLATFORM, g_device_prefix, (unsigned long long) c);
}

void pdns_gen_session_id(char *out, size_t out_len) {
    /* 12 位 A-Za-z0-9 随机串 */
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if (out == NULL || out_len < 13) {
        if (out != NULL && out_len > 0) {
            out[0] = '\0';
        }
        return;
    }
    unsigned char rnd[12];
    if (apr_generate_random_bytes(rnd, sizeof(rnd)) != APR_SUCCESS) {
        /* 兜底：系统随机源不可用时用时间+地址扰动 */
        apr_uint64_t seed = (apr_uint64_t) apr_time_now() ^ (apr_uint64_t) (uintptr_t) out;
        for (int i = 0; i < 12; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            rnd[i] = (unsigned char) (seed >> 33);
        }
    }
    for (int i = 0; i < 12; i++) {
        out[i] = alphabet[rnd[i] % (sizeof(alphabet) - 1)];
    }
    out[12] = '\0';
}
