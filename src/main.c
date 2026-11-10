/* hashmap - main: mode dispatch
 *
 * MIT License - Copyright (c) 2026 baba01hacker666
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "engine.h"
#include "hashmap.h"
#include "util.h"

void hm_usage_all(const char *prog)
{
    printf(
        "hashmap v%s - fast multi-threaded hash toolkit\n"
        "\n"
        "usage:\n"
        "  %s digest -a <md5|sha1|sha256> -i <string> [options]\n"
        "  %s brute  -H <md5hex> [options]\n"
        "  %s map    -o <out.hmmap> [options]\n"
        "  %s search -H <md5hex> [-f hashfile] <map.hmmap>\n"
        "\n"
        "digest options:\n"
        "  -a, --algo <md5|sha1|sha256>  hash algo (default md5)\n"
        "  -i, --input <string>          string to hash ('-' = stdin lines)\n"
        "  -f, --file <file>             hash whole file\n"
        "  -s, --salt <string>           salt the input\n"
        "  -p, --salt-pos <pre|post>     salt placement (default pre)\n"
        "\n"
        "brute/map options:\n"
        "  -H, --hash <md5hex>           target hash, repeat (brute only)\n"
        "  -f, --file <file>             file of MD5 hashes (brute only)\n"
        "  -c, --charset <spec>          builtins: digits lower upper alpha\n"
        "                                alnum hexlower hexupper special all,\n"
        "                                combinable with '+' or literal chars\n"
        "                                (default digits)\n"
        "      --min <n>                 min length (default 1)\n"
        "      --max <n>                 max length (default 6)\n"
        "  -t, --threads <n>             worker threads (default: all cores)\n"
        "  -s, --salt <string>           salt applied to every candidate\n"
        "  -p, --salt-pos <pre|post>     salt placement (default pre)\n"
        "  -o, --out <file>              brute: append results to file\n"
        "                                map: map file to write (required)\n"
        "      --state <file>            resume/state file (default: none)\n"
        "      --fresh                   ignore/discard any existing state\n"
        "  -h, --help                    this help\n"
        "  -v, --version                 print version\n"
        "\n"
        "search options:\n"
        "  -H, --hash <md5hex>           hash to look up, repeat\n"
        "  -f, --file <file>             file of MD5 hashes to look up\n"
        "\n"
        "examples:\n"
        "  %s digest -i hello\n"
        "  %s digest -a sha256 -f data.bin\n"
        "  %s brute -H 900150983cd24fb0d6963f7d28e17f72\n"
        "  %s brute -f targets.txt -c lower+digits --max 6\n"
        "  %s brute -H <hash> --state run.state -t 8\n"
        "  %s map -o digs.hmmap -c digits --min 1 --max 4\n"
        "  %s search -H 900150983cd24fb0d6963f7d28e17f72 digs.hmmap\n",
        HM_VERSION, prog, prog, prog, prog, prog, prog, prog, prog, prog,
        prog, prog);
}

static void usage_only(const char *prog)
{
    hm_usage_all(prog);
}

int main(int argc, char **argv)
{
    const char *prog = argv[0] != NULL ? argv[0] : "hashmap";

    /* SIGINT/SIGTERM => graceful stop + state save */
    hm_sig_setup();

    if (argc < 2) {
        usage_only(prog);
        return 2;
    }
    const char *mode = argv[1];

    if (strcmp(mode, "-h") == 0 || strcmp(mode, "--help") == 0) {
        usage_only(prog);
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
    else {
        fprintf(stderr,
                "[-] unknown mode '%s' (use digest|brute|map|search, see "
                "--help)\n",
                mode);
        return 2;
    }
    return rc;
}
