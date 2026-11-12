/* hashmap - main: mode dispatch
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#include "compat.h"

#include <stdio.h>
#include <string.h>

#include "engine.h"
#include "hashmap.h"
#include "util.h"

const char *hm_prog = "hashmap";

void hm_usage_all(const char *prog)
{
    printf(
        "hashmap v%s - fast multi-threaded hash toolkit\n"
        "\n"
        "usage: %s <mode> [options]\n"
        "\n"
        "modes:\n"
        "  digest   hash a string or a file            (md5, sha1, sha256)\n"
        "  brute    crack MD5 hashes by brute force     (resumable)\n"
        "  map      build a digest->plaintext map file  (resumable)\n"
        "  search   look hashes up inside a map file\n"
        "  wordlist match target hashes against a wordlist\n"
        "\n"
        "flags (same meaning in every mode):\n"
        "  -H, --hash <md5hex>      a hash value (repeatable)\n"
        "  -F, --hash-file <file>   file of hashes, one per line\n"
        "  -o, --out <file>         output file\n"
        "  -c, --charset <spec>     charset, repeatable (default: digits)\n"
        "      --min <n>            minimum length (default: 1)\n"
        "      --max <n>            maximum length (default: 6)\n"
        "  -t, --threads <n>        worker threads (default: all cores)\n"
        "  -a, --algo <md5|sha256>  digest algorithm (default: md5, or taken\n"
        "                           from the hash length: 32 hex = md5,\n"
        "                           64 hex = sha256)\n"
        "      --truncate <n>       store only n digest bytes in a map\n"
        "                           (16 keeps a sha256 map as small as md5)\n"
        "      --bcrypt             map mode: bcrypt digests for a fixed salt\n"
        "      --bcrypt-cost <n>    the cost of that bcrypt map (default 12)\n"
        "  -s, --salt <str>         salt applied to every candidate\n"
        "  -p, --salt-pos <pre|post>   salt placement (default: pre)\n"
        "      --state <file>       state file: pause/resume a long run\n"
        "      --fresh              ignore and delete an existing state file\n"
        "  -h, --help               help for the mode\n"
        "  -v, --version            print version\n"
        "\n"
        "examples:\n"
        "  %s digest -i hello\n"
        "  %s brute -H 202cb962ac59075b964b07152d234b70 -c lower+digits\n"
        "  %s map -o digs.hmmap -c digits --max 4\n"
        "  %s search -H 202cb962ac59075b964b07152d234b70 digs.hmmap\n"
        "\n"
        "more: docs/usage.md, docs/resume.md, docs/workflows.md\n",
        HM_VERSION, prog, prog, prog, prog, prog);
}

void hm_usage_digest(void)
{
    printf(
        "usage: %s digest [options]\n"
        "\n"
        "hash a string or a file.\n"
        "\n"
        "  -a, --algo <md5|sha1|sha256>   algorithm (default: md5)\n"
        "  -i, --input <string>           string to hash ('-' = every stdin line)\n"
        "  -f, --file <file>              hash the whole file\n"
        "  -s, --salt <string>            salt the input\n"
        "  -p, --salt-pos <pre|post>      salt placement (default: pre)\n"
        "  -h, --help                     this help\n"
        "\n"
        "examples:\n"
        "  %s digest -i hello\n"
        "  %s digest -a sha256 -i hello -s pepsi -p post\n"
        "  %s digest -f data.bin\n"
        "  printf 'a\\nb\\n' | %s digest -i -\n",
        hm_prog, hm_prog, hm_prog, hm_prog, hm_prog);
}

void hm_usage_brute(void)
{
    printf(
        "usage: %s brute -H <md5hex> | -F <file> [options]\n"
        "\n"
        "crack MD5 hashes by brute force over a keyspace.\n"
        "\n"
        "  -H, --hash <md5hex>        target hash (repeatable)\n"
        "  -F, --hash-file <file>     file of hashes, one per line ('#' comments)\n"
        "  -o, --out <file>           append cracked results to this file\n"
        "  -c, --charset <spec>       charset, repeatable (default: digits)\n"
        "      --min <n>              minimum length (default: 1)\n"
        "      --max <n>              maximum length (default: 6)\n"
        "  -t, --threads <n>          worker threads (default: all cores)\n"
        "  -a, --algo <md5|sha256>    digest algorithm (default: taken from\n"
        "                             the hash length: 32 hex = md5,\n"
        "                             64 hex = sha256)\n"
        "  -s, --salt <string>        salt applied to every candidate\n"
        "  -p, --salt-pos <pre|post>  salt placement (default: pre)\n"
        "      --state <file>         state file: pause and resume a long run\n"
        "      --fresh                ignore and delete an existing state file\n"
        "  -h, --help                 this help\n"
        "\n"
        "charset: digits lower upper alpha alnum hexlower hexupper special\n"
        "         symbols all full default - joined with '+' or literal chars,\n"
        "         repeatable (the specs are unioned)\n"
        "\n"
        "examples:\n"
        "  %s brute -H 202cb962ac59075b964b07152d234b70\n"
        "  %s brute -H <hash> -c lower+digits --max 6 -t 8\n"
        "  %s brute -H <hash> -c lower -c digits --max 6\n"
        "  %s brute -F targets.txt -c alnum --max 5 --state run.state\n"
        "  %s brute -H <hash> -s mycompany -p pre\n",
        hm_prog, hm_prog, hm_prog, hm_prog, hm_prog, hm_prog);
}

void hm_usage_map(void)
{
    printf(
        "usage: %s map -o <out.hmmap> [options]\n"
        "\n"
        "build a map file of a whole keyspace: one record per candidate,\n"
        "holding its MD5 digest and its plaintext.\n"
        "\n"
        "  -o, --out <file>           map file to write (required)\n"
        "  -c, --charset <spec>       charset, repeatable (default: digits)\n"
        "      --min <n>              minimum length (default: 1)\n"
        "      --max <n>              maximum length (default: 6)\n"
        "  -t, --threads <n>          worker threads (default: all cores)\n"
        "  -a, --algo <md5|sha256>    digest algorithm (default: taken from\n"
        "                             the hash length: 32 hex = md5,\n"
        "                             64 hex = sha256)\n"
        "  -s, --salt <string>        salt applied to every candidate\n"
        "  -p, --salt-pos <pre|post>  salt placement (default: pre)\n"
        "      --state <file>         state file (default: hashmap-map.state)\n"
        "      --bcrypt               bcrypt digests for the salt of --salt\n"
        "      --bcrypt-cost <n>      the cost of that map (default 12)\n"
        "      --fresh                ignore and delete an existing state file\n"
        "  -h, --help                 this help\n"
        "\n"
        "charset: digits lower upper alpha alnum hexlower hexupper special\n"
        "         symbols all full default - joined with '+' or literal chars,\n"
        "         repeatable (the specs are unioned)\n"
        "\n"
        "examples:\n"
        "  %s map -o digs.hmmap -c digits --min 1 --max 4\n"
        "  %s map -o digs.hmmap -c alnum --max 5 --state map.state\n",
        hm_prog, hm_prog, hm_prog);
}

void hm_usage_search(void)
{
    printf(
        "usage: %s search -H <md5hex> [-F <file>] <map.hmmap>...\n"
        "\n"
        "look hashes up inside the map files written by '%s map'.\n"
        "several files and/or a directory of *.hmmap files can be given.\n"
        "\n"
        "  -H, --hash <md5hex>        hash to look up (repeatable)\n"
        "  -F, --hash-file <file>     file of hashes, one per line\n"
        "  -h, --help                 this help\n"
        "\n"
        "examples:\n"
        "  %s search -H 202cb962ac59075b964b07152d234b70 digs.hmmap\n"
        "  %s search -F targets.txt /path/to/maps/\n",
        hm_prog, hm_prog, hm_prog, hm_prog);
}

void hm_usage_wordlist(void)
{
    printf(
        "usage: %s wordlist -H <md5hex> -w <wordlist> [options]\n"
        "\n"
        "match target hashes against the candidates of a wordlist.\n"
        "\n"
        "  -H, --hash <md5hex>        hash to look for (repeatable)\n"
        "  -F, --hash-file <file>     file of hashes, one per line\n"
        "  -w, --wordlist <file>      wordlist, one candidate per line\n"
        "  -o, --out <file>           append the cracked results to this file\n"
        "  -s, --salt <string>        salt applied to every candidate\n"
        "  -p, --salt-pos <pre|post>  salt placement (default: pre)\n"
        "  -t, --threads <n>          worker threads (default: all cores)\n"
        "  -f, --first                stop at the first hit\n"
        "  -h, --help                 this help\n"
        "\n"
        "examples:\n"
        "  %s wordlist -H <md5hex> -w wordlists/common.txt\n"
        "  %s wordlist -F targets.txt -w big.txt -o cracked.txt --first\n",
        hm_prog, hm_prog, hm_prog);
}

int main(int argc, char **argv)
{
    if (argc > 0 && argv[0] != NULL)
        hm_prog = argv[0];

    /* SIGINT/SIGTERM => graceful stop + state save */
    hm_sig_setup();

    if (argc < 2) {
        hm_usage_all(hm_prog);
        return 2;
    }
    const char *mode = argv[1];

    if (strcmp(mode, "-h") == 0 || strcmp(mode, "--help") == 0 ||
        strcmp(mode, "help") == 0) {
        hm_usage_all(hm_prog);
        return 0;
    }
    if (strcmp(mode, "-v") == 0 || strcmp(mode, "--version") == 0) {
        printf("hashmap v%s\n", HM_VERSION);
        return 0;
    }

    /* modes parse their own argv tail */
    int rc;
    if (strcmp(mode, "digest") == 0)
        rc = hm_mode_digest(argc - 1, argv + 1);
    else if (strcmp(mode, "brute") == 0)
        rc = hm_mode_brute(argc - 1, argv + 1);
    else if (strcmp(mode, "map") == 0)
        rc = hm_mode_map(argc - 1, argv + 1);
    else if (strcmp(mode, "search") == 0)
        rc = hm_mode_search(argc - 1, argv + 1);
    else if (strcmp(mode, "wordlist") == 0)
        rc = hm_mode_wordlist(argc - 1, argv + 1);
    else {
        fprintf(stderr,
                "[-] unknown mode '%s' (modes: digest, brute, map, search, "
                "wordlist)\n",
                mode);
        fprintf(stderr, "[-] run '%s --help' for usage\n", hm_prog);
        return 2;
    }
    return rc;
}
