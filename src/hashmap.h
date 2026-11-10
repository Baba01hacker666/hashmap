/* hashmap - shared project header
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#ifndef HASHMAP_H
#define HASHMAP_H

#define HM_VERSION "0.2.0"

#define HM_MAX_TARGETS 4096
#define HM_MAX_SALT 32
#define HM_MAX_PWLEN 32
#define HM_MAX_CS 256
#define HM_MAX_PLAIN (HM_MAX_SALT * 2 + HM_MAX_PWLEN + 1)
#define HM_MAX_STATE_PATH 512

/* a hash target / generic opaque digest */
typedef struct {
    uint8_t bytes[32];
    char hex[65];
} hm_target_t;

/* mode entry points (each parses its own argv tail) */
int hm_mode_digest(int argc, char **argv);
int hm_mode_brute(int argc, char **argv);
int hm_mode_map(int argc, char **argv);
int hm_mode_search(int argc, char **argv);
void hm_usage_all(const char *prog);

#endif /* HASHMAP_H */
