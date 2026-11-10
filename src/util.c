/* hashmap - util helpers implementation
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "util.h"

_Atomic int hm_stop = 0;

const char *hm_optarg = NULL;
int hm_optind = 1;

/* ------------------------------------------------------------------ */
/* signals                                                             */
/* ------------------------------------------------------------------ */

static void on_sig(int sig)
{
    (void)sig;
    atomic_store(&hm_stop, 1);
}

void hm_sig_setup(void)
{
#if defined(_WIN32)
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
#else
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_sig;
    sa.sa_flags = 0;
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
#endif
}

/* ------------------------------------------------------------------ */
/* timing / formatting                                                 */
/* ------------------------------------------------------------------ */

double hm_now(void)
{
#if defined(_WIN32)
    return (double)clock() / (double)CLOCKS_PER_SEC;
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

void hm_sleep_ms(unsigned ms)
{
#if defined(_WIN32)
    Sleep(ms);
#else
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1) {
        /* interrupted: finish the remaining time */
    }
#endif
}

int hm_fsync(FILE *f)
{
#if defined(_WIN32)
    return _commit(_fileno(f));
#else
    return fsync(fileno(f));
#endif
}

int hm_cpu_count(void)
{
#if defined(_WIN32)
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
#if defined(_SC_NPROCESSORS_ONLN)
    long n = sysconf(_SC_NPROCESSORS_ONLN);

    if (n > 0)
        return (int)n;
#endif
    return 4;
#endif
}

void hm_fmt_u64(uint64_t v, char *buf, size_t n)
{
    char tmp[32];
    size_t i = 0;
    size_t o = 0;

    if (v == 0) {
        if (n > 0)
            snprintf(buf, n, "0");
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

/* ------------------------------------------------------------------ */
/* portable getopt_long                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    int val;
    const char *arg;
} hm_tok_t;

typedef struct {
    hm_tok_t *toks;
    int ntok;
    int cur;
    char **optslots; /* argv entries consumed by options (in order) */
    int noptslots;
    char **nonopt;
    int nnonopt;
    int built;
} hm_getopt_t;

static hm_getopt_t g_go;

static void go_free(void)
{
    free(g_go.toks);
    free(g_go.optslots);
    free(g_go.nonopt);
    memset(&g_go, 0, sizeof(g_go));
}

/* find a short option in the option string; returns 1 when it takes an arg */
static int short_takes_arg(const char *shortopts, char c)
{
    const char *p = strchr(shortopts, c);

    if (p == NULL)
        return -1;
    if (p[1] == ':')
        return 1;
    return 0;
}

static void go_push_opt(char *entry)
{
    g_go.optslots[g_go.noptslots++] = entry;
}

static void go_push_tok(int val, const char *arg)
{
    g_go.toks[g_go.ntok].val = val;
    g_go.toks[g_go.ntok].arg = arg;
    g_go.ntok++;
}

static void go_build(int argc, char **argv, const char *shortopts,
                     const hm_longopt_t *longopts)
{
    int cap = argc + 1;

    g_go.toks = calloc((size_t)cap, sizeof(hm_tok_t));
    g_go.optslots = calloc((size_t)cap, sizeof(char *));
    g_go.nonopt = calloc((size_t)cap, sizeof(char *));
    if (g_go.toks == NULL || g_go.optslots == NULL || g_go.nonopt == NULL) {
        go_free();
        return;
    }

    int i = 1;
    int no_more_opts = 0;

    while (i < argc) {
        char *arg = argv[i];

        if (no_more_opts || arg[0] != '-' || arg[1] == '\0') {
            g_go.nonopt[g_go.nnonopt++] = arg;
            i++;
            continue;
        }
        if (arg[1] == '-' && arg[2] == '\0') { /* "--" ends the options */
            no_more_opts = 1;
            i++;
            continue;
        }
        if (arg[1] == '-') { /* long option */
            char name[128];
            const char *eq = strchr(arg + 2, '=');
            size_t nlen = (eq != NULL) ? (size_t)(eq - (arg + 2))
                                       : strlen(arg + 2);
            const char *value = (eq != NULL) ? eq + 1 : NULL;
            const hm_longopt_t *hit = NULL;

            if (nlen >= sizeof(name))
                nlen = sizeof(name) - 1;
            memcpy(name, arg + 2, nlen);
            name[nlen] = '\0';

            if (longopts != NULL) {
                for (const hm_longopt_t *lo = longopts; lo->name != NULL; lo++) {
                    if (strcmp(lo->name, name) == 0) {
                        hit = lo;
                        break;
                    }
                }
            }
            if (hit == NULL) {
                go_push_tok('?', arg);
                go_push_opt(arg);
                i++;
                continue;
            }
            go_push_opt(arg);
            if (hit->has_arg && value == NULL) {
                if (i + 1 < argc) {
                    value = argv[i + 1];
                    go_push_opt(argv[i + 1]);
                    i++;
                } else {
                    go_push_tok('?', NULL);
                    i++;
                    continue;
                }
            }
            go_push_tok(hit->val, (hit->has_arg) ? value : NULL);
            i++;
            continue;
        }
        /* short option cluster */
        {
            const char *p = arg + 1;

            go_push_opt(arg);
            while (*p != '\0') {
                int takes = short_takes_arg(shortopts, *p);

                if (takes < 0) {
                    go_push_tok('?', arg);
                    p++;
                    continue;
                }
                if (takes == 1) {
                    const char *value = NULL;

                    if (p[1] != '\0') {
                        value = p + 1;
                    } else if (i + 1 < argc) {
                        value = argv[i + 1];
                        go_push_opt(argv[i + 1]);
                        i++;
                    } else {
                        go_push_tok('?', NULL);
                        p++;
                        continue;
                    }
                    go_push_tok(*p, value);
                    break; /* the rest of the cluster was the argument */
                }
                go_push_tok(*p, NULL);
                p++;
            }
            i++;
        }
    }

    /* permute argv: options first, positional arguments behind them
     * (getopt convention), hm_optind points at the first positional */
    {
        int w = 1;

        for (int k = 0; k < g_go.noptslots; k++)
            argv[w++] = g_go.optslots[k];
        for (int k = 0; k < g_go.nnonopt; k++)
            argv[w++] = g_go.nonopt[k];
        for (int k = w; k < argc; k++)
            argv[k] = NULL;
    }
    hm_optind = 1 + g_go.noptslots;
    g_go.built = 1;
}

int hm_getopt_long(int argc, char **argv, const char *shortopts,
                   const hm_longopt_t *longopts)
{
    if (!g_go.built) {
        go_build(argc, argv, shortopts, longopts);
        if (!g_go.built)
            return -1;
    }
    if (g_go.cur >= g_go.ntok)
        return -1;
    hm_optarg = g_go.toks[g_go.cur].arg;
    int v = g_go.toks[g_go.cur].val;

    g_go.cur++;
    return v;
}

void hm_getopt_reset(void)
{
    go_free();
    hm_optind = 1;
    hm_optarg = NULL;
}
