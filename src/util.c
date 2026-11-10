/* hashmap - util helpers implementation
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#define _POSIX_C_SOURCE 200809L

#include "util.h"

#include <signal.h>
#include <stdio.h>
#include <time.h>

_Atomic int hm_stop = 0;

static _Atomic int hm_tick = 0;

static void on_sig(int sig)
{
    (void)sig;
    atomic_store(&hm_stop, 1);
}

/* volatile flag touched by handlers to prove the handler ran when debugging */
void hm_sig_keepalive(void)
{
    atomic_fetch_add(&hm_tick, 1);
}

void hm_sig_setup(void)
{
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_sig;
    sa.sa_flags = 0;
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
}

double hm_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void hm_fmt_u64(uint64_t v, char *buf, size_t n)
{
    char tmp[32];
    size_t i = 0;
    size_t o = 0;

    if (v == 0) {
        if (n > 0)
            buf[0] = '\0';
        return;
    }
    while (v) {
        tmp[i++] = (char)('0' + (v % 10));
        v /= 10;
        if (i % 4 == 3 && v)
            tmp[i++] = ',';
    }
    while (i > 0 && o < n - 1)
        buf[o++] = tmp[--i];
    buf[o] = '\0';
}

void hm_fmt_rate(double hps, char *buf, size_t n)
{
    if (hps >= 1e9)
        snprintf(buf, n, "%.2f GH/s", hps / 1e9);
    else if (hps >= 1e6)
        snprintf(buf, n, "%.2f MH/s", hps / 1e6);
    else if (hps >= 1e3)
        snprintf(buf, n, "%.2f kH/s", hps / 1e3);
    else
        snprintf(buf, n, "%.2f H/s", hps);
}
