/* hashmap - bcrypt implementation
 *
 * A self contained implementation of the OpenBSD bcrypt scheme ($2a$, $2b$,
 * $2y$), ported from the OpenBSD reference implementation so the tool stays
 * dependency free.
 *
 * A bcrypt hash carries its own random salt, so it cannot be put into a
 * plain digest map. What works:
 *   - verify candidates against a bcrypt hash (the salt comes from the hash)
 *   - precompute with a *fixed* salt, then look the hash up in that map
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bcrypt.h"
#include "bf_tables.h"

#define HM_BCRYPT_MAXSALT 16
#define HM_BCRYPT_WORDS 6
#define HM_BCRYPT_MINLOGROUNDS 4
#define HM_BCRYPT_MAXLOGROUNDS 16
#define HM_BCRYPT_KEY_MAX 72

typedef struct {
    uint32_t P[18];
    uint32_t S[4][256];
} bf_ctx_t;

/* ------------------------------------------------------------------ */
/* blowfish core                                                       */
/* ------------------------------------------------------------------ */

#define HM_ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t bf_F(const uint32_t *s, uint32_t x)
{
    return ((s[((x >> 24) & 0xff)] + s[0x100 + ((x >> 16) & 0xff)]) ^
            s[0x200 + ((x >> 8) & 0xff)]) +
           s[0x300 + (x & 0xff)];
}

static void bf_encipher(const bf_ctx_t *c, uint32_t *xl, uint32_t *xr)
{
    const uint32_t *s = &c->S[0][0];
    const uint32_t *p = c->P;
    uint32_t xl_ = *xl;
    uint32_t xr_ = *xr;

    xl_ ^= p[0];
    for (int n = 1; n <= 16; n++) {
        if (n & 1)
            xr_ ^= bf_F(s, xl_) ^ p[n];
        else
            xl_ ^= bf_F(s, xr_) ^ p[n];
    }
    *xl = xr_ ^ p[17];
    *xr = xl_;
}

/* read 4 bytes from a stream as a big endian word (wrapping around) */
static uint32_t bf_stream2word(const uint8_t *data, uint16_t databytes,
                                uint16_t *current)
{
    uint32_t temp = 0;
    uint16_t j = *current;

    for (uint8_t i = 0; i < 4; i++, j++) {
        if (j >= databytes)
            j = 0;
        temp = (temp << 8) | data[j];
    }
    *current = j;
    return temp;
}

/* the plain blowfish key schedule */
static void bf_expand0state(bf_ctx_t *c, const uint8_t *key, uint16_t keybytes)
{
    uint16_t i;
    uint16_t j = 0;
    uint32_t datal = 0;
    uint32_t datar = 0;

    for (i = 0; i < 18; i++)
        c->P[i] ^= bf_stream2word(key, keybytes, &j);

    for (i = 0; i < 18; i += 2) {
        bf_encipher(c, &datal, &datar);
        c->P[i] = datal;
        c->P[i + 1] = datar;
    }
    for (int box = 0; box < 4; box++) {
        for (uint16_t k = 0; k < 256; k += 2) {
            bf_encipher(c, &datal, &datar);
            c->S[box][k] = datal;
            c->S[box][k + 1] = datar;
        }
    }
}

/* the salted key schedule: the salt is mixed into the enciphered blocks */
static void bf_expandstate(bf_ctx_t *c, const uint8_t *data,
                           uint16_t databytes, const uint8_t *key,
                           uint16_t keybytes)
{
    uint16_t i;
    uint16_t j = 0;
    uint32_t datal = 0;
    uint32_t datar = 0;

    for (i = 0; i < 18; i++)
        c->P[i] ^= bf_stream2word(key, keybytes, &j);

    j = 0;
    for (i = 0; i < 18; i += 2) {
        datal ^= bf_stream2word(data, databytes, &j);
        datar ^= bf_stream2word(data, databytes, &j);
        bf_encipher(c, &datal, &datar);
        c->P[i] = datal;
        c->P[i + 1] = datar;
    }
    for (int box = 0; box < 4; box++) {
        for (uint16_t k = 0; k < 256; k += 2) {
            datal ^= bf_stream2word(data, databytes, &j);
            datar ^= bf_stream2word(data, databytes, &j);
            bf_encipher(c, &datal, &datar);
            c->S[box][k] = datal;
            c->S[box][k + 1] = datar;
        }
    }
}

/* ------------------------------------------------------------------ */
/* bcrypt base64 (its own alphabet)                                     */
/* ------------------------------------------------------------------ */

static const char HM_BC64[] =
    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static int hm_bc64_value(char c)
{
    for (int i = 0; i < 64; i++) {
        if (HM_BC64[i] == c)
            return i;
    }
    return -1;
}

static void hm_bc64_encode(char *out, const uint8_t *data, size_t len)
{
    const uint8_t *p = data;
    const uint8_t *end = data + len;
    uint8_t c1;
    uint8_t c2;

    while (p < end) {
        c1 = *p++;
        *out++ = HM_BC64[(c1 >> 2) & 0x3f];
        c1 = (uint8_t)((c1 & 0x03) << 4);
        if (p >= end) {
            *out++ = HM_BC64[c1 & 0x3f];
            break;
        }
        c2 = *p++;
        c1 |= (uint8_t)((c2 >> 4) & 0x0f);
        *out++ = HM_BC64[c1 & 0x3f];
        c1 = (uint8_t)((c2 & 0x0f) << 2);
        if (p >= end) {
            *out++ = HM_BC64[c1 & 0x3f];
            break;
        }
        c2 = *p++;
        c1 |= (uint8_t)((c2 >> 6) & 0x03);
        *out++ = HM_BC64[c1 & 0x3f];
        *out++ = HM_BC64[c2 & 0x3f];
    }
    *out = '\0';
}

/* decode exactly len bytes from the base64 string */
static int hm_bc64_decode(uint8_t *out, size_t len, const char *in)
{
    uint8_t *bp = out;
    uint8_t *end = out + len;

    while (bp < end) {
        int c1 = hm_bc64_value(in[0]);
        int c2 = hm_bc64_value(in[1]);

        if (c1 < 0 || c2 < 0)
            return -1;
        *bp++ = (uint8_t)((c1 << 2) | ((c2 & 0x30) >> 4));
        if (bp >= end)
            break;
        {
            int c3 = hm_bc64_value(in[2]);

            if (c3 < 0)
                return -1;
            *bp++ = (uint8_t)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2));
            if (bp >= end)
                break;
            {
                int c4 = hm_bc64_value(in[3]);

                if (c4 < 0)
                    return -1;
                *bp++ = (uint8_t)(((c3 & 0x03) << 6) | c4);
            }
        }
        in += 4;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* the bcrypt hash itself                                               */
/* ------------------------------------------------------------------ */

/* the magic is 24 bytes; the array holds the NUL as well */
static const uint8_t HM_BCRYPT_MAGIC[25] = "OrpheanBeholderScryDoubt";

/* parse "$2b$12$<22 salt><31 digest>" - returns 0 on success */
static int bcrypt_parse(const char *hash, char *minor, int *cost,
                        const char **body)
{
    size_t len;

    if (hash == NULL || hash[0] != '$')
        return -1;
    len = strlen(hash);
    if (len < 7)
        return -1;
    if (hash[1] != '2')
        return -1;
    *minor = hash[2];
    if (*minor != 'a' && *minor != 'b' && *minor != 'y')
        return -1;
    if (hash[3] != '$' || hash[4] < '0' || hash[4] > '9' || hash[5] < '0' ||
        hash[5] > '9' || hash[6] != '$')
        return -1;
    *cost = (hash[4] - '0') * 10 + (hash[5] - '0');
    if (*cost < HM_BCRYPT_MINLOGROUNDS || *cost > HM_BCRYPT_MAXLOGROUNDS)
        return -1;
    *body = hash + 7;
    return 0;
}

int hm_bcrypt(const char *password, const char *setting, char *out,
              size_t outlen)
{
    char minor;
    int cost;
    const char *body;
    uint8_t csalt[HM_BCRYPT_MAXSALT];
    uint8_t ciphertext[4 * HM_BCRYPT_WORDS];
    uint32_t cdata[HM_BCRYPT_WORDS];
    bf_ctx_t state;
    size_t key_len;
    uint16_t j = 0;
    char salt22[24];
    char digest31[32];

    if (password == NULL || setting == NULL || out == NULL)
        return -1;
    if (bcrypt_parse(setting, &minor, &cost, &body) < 0)
        return -1;
    if (strlen(body) < 22)
        return -1;

    memcpy(salt22, body, 22);
    salt22[22] = '\0';
    if (hm_bc64_decode(csalt, HM_BCRYPT_MAXSALT, salt22) < 0)
        return -1;

    /* the key: the password plus a NUL, at most 72 characters */
    key_len = strlen(password);
    if (minor == 'a') {
        key_len += 1; /* the old variant wraps at 255 */
    } else {
        if (key_len > HM_BCRYPT_KEY_MAX)
            key_len = HM_BCRYPT_KEY_MAX;
        key_len++; /* include the NUL */
    }

    memcpy(state.P, HM_BF_P, sizeof(state.P));
    memcpy(state.S[0], HM_BF_S0, sizeof(state.S[0]));
    memcpy(state.S[1], HM_BF_S1, sizeof(state.S[1]));
    memcpy(state.S[2], HM_BF_S2, sizeof(state.S[2]));
    memcpy(state.S[3], HM_BF_S3, sizeof(state.S[3]));

    bf_expandstate(&state, csalt, HM_BCRYPT_MAXSALT,
                   (const uint8_t *)password, (uint16_t)key_len);
    {
        uint32_t rounds = 1u << cost;

        for (uint32_t k = 0; k < rounds; k++) {
            bf_expand0state(&state, (const uint8_t *)password,
                            (uint16_t)key_len);
            bf_expand0state(&state, csalt, HM_BCRYPT_MAXSALT);
        }
    }

    memcpy(ciphertext, HM_BCRYPT_MAGIC, 24);
    j = 0;
    for (int i = 0; i < HM_BCRYPT_WORDS; i++)
        cdata[i] = bf_stream2word(ciphertext, (uint16_t)(4 * HM_BCRYPT_WORDS),
                                  &j);

    for (int k = 0; k < 64; k++) {
        for (int i = 0; i < HM_BCRYPT_WORDS; i += 2) {
            uint32_t l = cdata[i];
            uint32_t r = cdata[i + 1];

            bf_encipher(&state, &l, &r);
            cdata[i] = l;
            cdata[i + 1] = r;
        }
    }

    for (int i = 0; i < HM_BCRYPT_WORDS; i++) {
        ciphertext[4 * i + 3] = (uint8_t)(cdata[i] & 0xff);
        cdata[i] >>= 8;
        ciphertext[4 * i + 2] = (uint8_t)(cdata[i] & 0xff);
        cdata[i] >>= 8;
        ciphertext[4 * i + 1] = (uint8_t)(cdata[i] & 0xff);
        cdata[i] >>= 8;
        ciphertext[4 * i + 0] = (uint8_t)(cdata[i] & 0xff);
    }

    hm_bc64_encode(digest31, ciphertext, 4 * HM_BCRYPT_WORDS - 1);

    if (outlen < 61)
        return -1;
    snprintf(out, outlen, "$2%c$%02d$%s%s", minor, cost, salt22, digest31);
    return 0;
}

int hm_bcrypt_digest(const char *hash, unsigned char out[23])
{
    char minor;
    int cost;
    const char *body;

    if (hash == NULL)
        return -1;
    if (bcrypt_parse(hash, &minor, &cost, &body) < 0)
        return -1;
    if (strlen(body) < 22 + 31)
        return -1;
    return hm_bc64_decode(out, 23, body + 22);
}

int hm_bcrypt_salt(const char *hash, char out[23])
{
    char minor;
    int cost;
    const char *body;

    if (hash == NULL)
        return -1;
    if (bcrypt_parse(hash, &minor, &cost, &body) < 0)
        return -1;
    if (strlen(body) < 22)
        return -1;
    memcpy(out, body, 22);
    out[22] = '\0';
    return 0;
}
