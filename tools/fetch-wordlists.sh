#!/usr/bin/env bash
# hashmap - fetch and combine password wordlists
#
#   tools/fetch-wordlists.sh --fast    top lists only (~2M candidates, quick)
#   tools/fetch-wordlists.sh --full    everything incl. RockYou (~14M+)
#   tools/fetch-wordlists.sh --full --out wordlists/combined.txt
#
# The lists come from SecLists (MIT). They are downloaded here, not committed:
# the repository stays small and the lists stay up to date.
#
# The result is deduplicated (byte exact, LC_ALL=C) and sorted, so the
# wordlist mode never hashes the same candidate twice.

set -euo pipefail

SECLISTS="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
OUT="wordlists/combined.txt"
CACHE="${CACHE_DIR:-$HOME/.cache/hashmap/wordlists}"
PROFILE="fast"
KEEP_CACHE=1

# name<TAB>url (tarballs are extracted, .gz files are decompressed)
SOURCES_FAST=(
"top-10k|Passwords/Common-Credentials/10k-most-common.txt"
"top-100k|Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
"probable-12000|Passwords/Common-Credentials/probable-v2_top-12000.txt"
"xato-1000000|Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt"
"darkweb-top-10000|Passwords/Common-Credentials/darkweb2017_top-10000.txt"
"pwdb-top-100000|Passwords/Common-Credentials/Pwdb_top-100000.txt"
"years|Passwords/Common-Credentials/1900-2020.txt"
"months|Passwords/months.txt"
"seasons|Passwords/seasons.txt"
"openwall-top|Passwords/openwall.net-all.txt"
)

SOURCES_FULL=(
"rockyou|Passwords/Leaked-Databases/rockyou.txt.tar.gz"
"xato-10m|Passwords/Common-Credentials/xato-net-10-million-passwords.txt"
"pwdb-10m|Passwords/Common-Credentials/Pwdb_top-10000000.txt"
"darkc0de|Passwords/darkc0de.txt"
"myspace|Passwords/Leaked-Databases/myspace.txt"
"phpbb|Passwords/Leaked-Databases/phpbb.txt"
"honeynet|Passwords/Leaked-Databases/honeynet.txt"
"adobe100|Passwords/Leaked-Databases/adobe100.txt"
"hotmail|Passwords/Leaked-Databases/hotmail.txt"
"singles|Passwords/Leaked-Databases/singles.org.txt"
"elitehacker|Passwords/Leaked-Databases/elitehacker.txt"
"carders|Passwords/Leaked-Databases/carders.cc.txt"
"fortinet|Passwords/Leaked-Databases/fortinet-2021_passwords.txt"
"twitter-banned|Passwords/Leaked-Databases/twitter-banned.txt"
"youporn2012|Passwords/Leaked-Databases/youporn2012.txt"
"alleged-gmail|Passwords/Leaked-Databases/alleged-gmail-passwords.txt"
"000webhost|Passwords/Leaked-Databases/000webhost.txt"
"md5decryptor|Passwords/Leaked-Databases/md5decryptor-uk.txt"
)

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --fast) PROFILE="fast" ;;
        --full) PROFILE="full" ;;
        --out) shift; OUT="$1" ;;
        --cache) shift; CACHE="$1" ;;
        --no-cache) KEEP_CACHE=0 ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$PROFILE" = "full" ]; then
    SOURCES=("${SOURCES_FULL[@]}" "${SOURCES_FAST[@]}")
else
    SOURCES=("${SOURCES_FAST[@]}")
fi

mkdir -p "$CACHE" "$(dirname "$OUT")"
TMP="$CACHE/.work.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

fetch() {
    local name="$1" path="$2"
    local dest="$CACHE/$name"
    local url="$SECLISTS/$path"

    if [ -s "$dest" ]; then
        echo "  cached  $name ($(du -h "$dest" | cut -f1))"
        return 0
    fi
    printf '  fetch   %-22s ' "$name"
    if ! curl -sSL --fail --retry 3 --retry-delay 2 --connect-timeout 20 \
            --max-time 1800 -o "$dest.part" "$url"; then
        echo "FAILED"
        rm -f "$dest.part"
        return 1
    fi
    mv "$dest.part" "$dest"
    echo "$(du -h "$dest" | cut -f1)"
}

echo "== hashmap wordlist fetch ($PROFILE) =="
RAW="$TMP/raw.txt"
: > "$RAW"
ok=0
fail=0

for entry in "${SOURCES[@]}"; do
    name="${entry%%|*}"
    path="${entry#*|}"
    if ! fetch "$name" "$path"; then
        fail=$((fail + 1))
        continue
    fi
    case "$name" in
        *rockyou*|*tar.gz)
            if tar -xzf "$CACHE/$name" -C "$TMP" 2>/dev/null; then
                f=$(find "$TMP" -maxdepth 2 -name 'rockyou*' -type f | head -1)
                [ -n "$f" ] && cat "$f" >> "$RAW"
            else
                echo "  (extract failed: $name)"
                fail=$((fail + 1))
            fi
            ;;
        *)
            cat "$CACHE/$name" >> "$RAW"
            ;;
    esac
    ok=$((ok + 1))
done

echo "== combining =="
# strip CR, drop empty lines, keep byte-exact content, then dedupe.
# grep -a: the lists contain non-UTF8 bytes, without it grep stops early.
raw_lines=$(wc -l < "$RAW")
LC_ALL=C tr -d '\r' < "$RAW" \
    | grep -a -v '^$' \
    | LC_ALL=C sort -u \
    > "$OUT"
uniq_lines=$(wc -l < "$OUT")

size=$(du -h "$OUT" | cut -f1)
echo "sources fetched : $ok (failed: $fail)"
echo "raw lines       : $raw_lines"
echo "unique lines    : $uniq_lines"
echo "removed dupes   : $((raw_lines - uniq_lines))"
echo "output          : $OUT ($size)"

if [ "$KEEP_CACHE" -eq 0 ]; then
    rm -rf "$CACHE"
    echo "cache cleared   : $CACHE"
fi
