/* hashmap - digest mode: hash strings/files with md5/sha1/sha256
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "engine.h"
#include "hashmap.h"
#include "util.h"

int hm_mode_digest(int argc, char **argv)
{
    static const hm_longopt_t lopts[] = {
        { "algo", 1, 'a' },
        { "input", 1, 'i' },
        { "file", 1, 'f' },
        { "salt", 1, 's' },
        { "salt-pos", 1, 'p' },
        { "help", 0, 'h' },
        { NULL, 0, 0 }
    };
    hm_algo_t alg = HM_ALG_MD5;
    const char *input = NULL;
    const char *file = NULL;
    char salt[HM_MAX_SALT + 1];
    int salt_len = 0;
    int salt_pre = 1;
    int opt;

    while ((opt = hm_getopt_long(argc, argv, "a:i:f:s:p:h", lopts)) != -1) {
        switch (opt) {
        case 'a':
            if (hm_algo_parse(hm_optarg, &alg) < 0) {
                fprintf(stderr, "[-] unknown algo '%s'\n", hm_optarg);
                return 2;
            }
            break;
        case 'i':
            input = hm_optarg;
            break;
        case 'f':
            file = hm_optarg;
            break;
        case 's':
            salt_len = (int)strlen(hm_optarg);
            if (salt_len > HM_MAX_SALT) {
                fprintf(stderr, "[-] salt too long (max %d)\n", HM_MAX_SALT);
                return 2;
            }
            memcpy(salt, hm_optarg, (size_t)salt_len);
            break;
        case 'p':
            if (strcmp(hm_optarg, "pre") == 0)
                salt_pre = 1;
            else if (strcmp(hm_optarg, "post") == 0)
                salt_pre = 0;
            else {
                fprintf(stderr, "[-] salt-pos must be pre|post\n");
                return 2;
            }
            break;
        case 'h':
            hm_usage_digest();
            return 0;
        default:
            fprintf(stderr, "[-] unknown option\n");
            hm_usage_digest();
            return 2;
        }
    }

    if (input == NULL && file == NULL) {
        fprintf(stderr, "[-] digest needs -i <string> or -f <file>\n");
        return 2;
    }
    if ((input != NULL) + (file != NULL) > 1) {
        fprintf(stderr, "[-] use either -i or -f, not both\n");
        return 2;
    }

    if (input != NULL) {
        uint8_t dg[32];
        size_t ol;
        char hex[65];
        size_t tl = strlen(input);
        size_t total = tl + (size_t)salt_len;
        char *buf = malloc(total + 1);

        if (buf == NULL) {
            fprintf(stderr, "[-] out of memory\n");
            return 1;
        }
        size_t host = 0;

        if (strcmp(input, "-") == 0) {
            /* hash every line from stdin */
            char *line = malloc(65536);
            uint8_t *hbuf;

            if (line == NULL) {
                free(buf);
                fprintf(stderr, "[-] out of memory\n");
                return 1;
            }
            hbuf = malloc(65536 + (size_t)salt_len + 1);
            if (hbuf == NULL) {
                free(line);
                free(buf);
                fprintf(stderr, "[-] out of memory\n");
                return 1;
            }
            while (fgets(line, 65536, stdin) != NULL) {
                char *nl = strpbrk(line, "\r\n");
                size_t n;

                if (nl != NULL)
                    *nl = '\0';
                n = strlen(line);
                host = 0;
                if (salt_len > 0 && salt_pre) {
                    memcpy(hbuf, salt, (size_t)salt_len);
                    host = (size_t)salt_len;
                }
                memcpy(hbuf + host, line, n);
                host += n;
                if (salt_len > 0 && !salt_pre) {
                    memcpy(hbuf + host, salt, (size_t)salt_len);
                    host += (size_t)salt_len;
                }
                hm_hash(alg, (const uint8_t *)hbuf, host, dg, &ol);
                hm_to_hex(dg, ol, hex);
                printf("%s:%s\n", hex, line);
            }
            free(hbuf);
            free(line);
            free(buf);
            return 0;
        }

        if (salt_len > 0 && salt_pre) {
            memcpy(buf, salt, (size_t)salt_len);
            host += (size_t)salt_len;
        }
        memcpy(buf + host, input, tl);
        host += tl;
        if (salt_len > 0 && !salt_pre) {
            memcpy(buf + host, salt, (size_t)salt_len);
            host += (size_t)salt_len;
        }
        hm_hash(alg, (const uint8_t *)buf, host, dg, &ol);
        free(buf);
        hm_to_hex(dg, ol, hex);
        printf("%s\n", hex);
        return 0;
    }

    /* file mode: stream-hash the whole file */
    {
        FILE *f = fopen(file, "rb");

        if (f == NULL) {
            fprintf(stderr, "[-] cannot open %s: %s\n", file,
                    strerror(errno));
            return 1;
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (sz < 0) {
            fprintf(stderr, "[-] ftell failed on %s\n", file);
            fclose(f);
            return 1;
        }
        size_t bufn = (size_t)sz + (size_t)salt_len + 1;
        uint8_t *buf = malloc(bufn);

        if (buf == NULL) {
            fprintf(stderr, "[-] out of memory\n");
            fclose(f);
            return 1;
        }
        size_t host = 0;
        if (salt_len > 0 && salt_pre) {
            memcpy(buf, salt, (size_t)salt_len);
            host = (size_t)salt_len;
        }
        if (sz > 0 && fread(buf + host, 1, (size_t)sz, f) != (size_t)sz) {
            fprintf(stderr, "[-] read failed on %s\n", file);
            free(buf);
            fclose(f);
            return 1;
        }
        host += (size_t)sz;
        if (salt_len > 0 && !salt_pre) {
            memcpy(buf + host, salt, (size_t)salt_len);
            host += (size_t)salt_len;
        }
        fclose(f);

        uint8_t dg[32];
        size_t ol;
        char hex[65];

        hm_hash(alg, buf, host, dg, &ol);
        free(buf);
        hm_to_hex(dg, ol, hex);
        printf("%s\n", hex);
    }
    return 0;
}
