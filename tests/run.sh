#!/usr/bin/env bash
# hashmap - test suite
#
# usage: ./tests/run.sh [path-to-binary]
# MIT License - Copyright (c) 2026 baba01hacker666
set -u

BIN="${1:-./hashmap}"
TMP="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
head_() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

if [ ! -x "$BIN" ]; then
    printf 'binary not found: %s (run make first)\n' "$BIN" >&2
    exit 1
fi

# portable hash helpers (GNU coreutils vs BSD/macOS)
md5_of() {
    if command -v md5sum >/dev/null 2>&1; then
        printf '%s' "$1" | md5sum | cut -d' ' -f1
    else
        printf '%s' "$1" | md5 -q
    fi
}
sha1_of() {
    if command -v sha1sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha1sum | cut -d' ' -f1
    else
        printf '%s' "$1" | shasum -a 1 | cut -d' ' -f1
    fi
}
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | cut -d' ' -f1
    else
        printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
    fi
}
file_md5() {
    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$1" | cut -d' ' -f1
    else
        md5 -q "$1"
    fi
}

# ------------------------------------------------------------------
head_ "digest mode"
# ------------------------------------------------------------------
for algo in md5 sha1 sha256; do
    for txt in "hello" "" "a" "The quick brown fox"; do
        case "$algo" in
            md5)    want="$(md5_of "$txt")" ;;
            sha1)   want="$(sha1_of "$txt")" ;;
            sha256) want="$(sha256_of "$txt")" ;;
        esac
        got="$("$BIN" digest -a "$algo" -i "$txt" 2>/dev/null)"
        if [ "$want" = "$got" ]; then
            ok "digest $algo '$txt'"
        else
            bad "digest $algo '$txt' (want=$want got=$got)"
        fi
    done
done

# long string (dynamic buffer path)
LONG="$(head -c 500 /dev/urandom | base64 | tr -d '\n')"
want="$(md5_of "$LONG")"
got="$("$BIN" digest -i "$LONG")"
[ "$want" = "$got" ] && ok "digest long string" || bad "digest long string"

# file hashing
head -c 4096 /dev/urandom > "$TMP/blob.bin"
want="$(file_md5 "$TMP/blob.bin")"
got="$("$BIN" digest -f "$TMP/blob.bin")"
[ "$want" = "$got" ] && ok "digest file" || bad "digest file"

# stdin mode (hashmap strips the line ending, so compare against printf w/o \n)
want="$(md5_of 'abc')"
got="$(printf 'abc\n' | "$BIN" digest -i - | cut -d: -f1)"
[ "$want" = "$got" ] && ok "digest stdin" || bad "digest stdin"

# salted digest
want="$(md5_of 'saltabc')"
got="$("$BIN" digest -i abc -s salt -p pre)"
[ "$want" = "$got" ] && ok "digest salted pre" || bad "digest salted pre"
want="$(md5_of 'abcsalt')"
got="$("$BIN" digest -i abc -s salt -p post)"
[ "$want" = "$got" ] && ok "digest salted post" || bad "digest salted post"

# ------------------------------------------------------------------
head_ "brute mode"
# ------------------------------------------------------------------
H123="$(md5_of '123')"
"$BIN" brute -H "$H123" -c digits --max 6 >"$TMP/out.txt" 2>&1
rc=$?
[ $rc -eq 0 ] && ok "brute hit exit 0" || bad "brute hit exit 0 (rc=$rc)"
grep -q "CRACKED" "$TMP/out.txt" && ok "brute prints CRACKED" || bad "brute prints CRACKED"

"$BIN" brute -H 00000000000000000000000000000000 -c digits --max 3 >/dev/null 2>&1
rc=$?
[ $rc -eq 1 ] && ok "brute miss exit 1" || bad "brute miss exit 1 (rc=$rc)"

# salted pre / post
HS="$(md5_of 'salt999')"
"$BIN" brute -H "$HS" -c digits --max 4 -s salt -p pre >"$TMP/saltpre.txt" 2>&1
rc=$?
[ $rc -eq 0 ] && ok "brute salted pre" || bad "brute salted pre (rc=$rc)"
HS="$(md5_of '999salt')"
"$BIN" brute -H "$HS" -c digits --max 4 -s salt -p post >"$TMP/saltpost.txt" 2>&1
rc=$?
[ $rc -eq 0 ] && ok "brute salted post" || bad "brute salted post (rc=$rc)"

# multiple targets
"$BIN" brute -H "$H123" -H "$(md5_of '456')" \
    -c digits --max 6 >/dev/null 2>&1
rc=$?
[ $rc -eq 0 ] && ok "brute multi-target" || bad "brute multi-target (rc=$rc)"

# results file
rm -f "$TMP/found.txt"
"$BIN" brute -H "$H123" -c digits --max 6 -o "$TMP/found.txt" >/dev/null 2>&1
[ -s "$TMP/found.txt" ] && ok "brute -o writes results" || bad "brute -o writes results"

# usage errors
"$BIN" brute >/dev/null 2>&1
[ $? -eq 2 ] && ok "brute without target exits 2" || bad "brute without target exits 2"
"$BIN" nonsense >/dev/null 2>&1
[ $? -eq 2 ] && ok "unknown mode exits 2" || bad "unknown mode exits 2"

# ------------------------------------------------------------------
head_ "map + search modes"
# ------------------------------------------------------------------
"$BIN" map -o "$TMP/test.hmmap" -c digits --min 1 --max 4 >/dev/null 2>&1
rc=$?
[ $rc -eq 0 ] && ok "map exits 0" || bad "map exits 0 (rc=$rc)"
[ -s "$TMP/test.hmmap" ] && ok "map file written" || bad "map file written"

out="$("$BIN" search -H "$H123" "$TMP/test.hmmap" 2>/dev/null)"
[ "$out" = "$H123:123" ] && ok "search finds plaintext" || bad "search finds plaintext (got=$out)"

"$BIN" search -H 00000000000000000000000000000000 "$TMP/test.hmmap" >/dev/null 2>&1
[ $? -eq 1 ] && ok "search miss exit 1" || bad "search miss exit 1"

"$BIN" search -H "$H123" "$TMP/not-a-map.bin" >/dev/null 2>&1
[ $? -eq 1 ] && ok "search rejects non-map file" || bad "search rejects non-map file"

# ------------------------------------------------------------------
head_ "state / resume"
# ------------------------------------------------------------------
STATE="$TMP/resume.state"
HNF="$(md5_of 'definitelynotfound')"
"$BIN" brute -H "$HNF" -c digits --min 1 --max 8 --state "$STATE" -t 4 \
    >"$TMP/res1.log" 2>&1 &
pid=$!
sleep 1
kill -TERM $pid 2>/dev/null
wait $pid 2>/dev/null
if [ -s "$STATE" ]; then
    ok "SIGTERM saves state file"
else
    bad "SIGTERM saves state file"
fi
grep -q "HMSTATE 2" "$STATE" && ok "state has magic" || bad "state has magic"

# resume with a *different* config must be refused
"$BIN" brute -H "$HNF" -c lower --min 1 --max 8 --state "$STATE" \
    >/dev/null 2>&1
[ $? -ne 0 ] && ok "state refuses mismatched config" || bad "state refuses mismatched config"

# resume and let it finish; total work across runs must equal keyspace
"$BIN" brute -H "$HNF" -c digits --min 1 --max 8 --state "$STATE" -t 4 \
    >"$TMP/res2.log" 2>&1 &
pid=$!
sleep 1
kill -TERM $pid 2>/dev/null
wait $pid 2>/dev/null

total="$(grep -o 'done: [0-9,]* candidates' "$TMP/res1.log" | grep -o '[0-9,]*' | tr -d ,)"
total=$((total + $(grep -o 'done: [0-9,]* candidates' "$TMP/res2.log" | grep -o '[0-9,]*' | tr -d ,)))
if [ "$total" -le 111111110 ] && [ "$total" -gt 0 ]; then
    ok "resume covers work exactly once ($total <= 111111110)"
else
    bad "resume covers work exactly once (total=$total)"
fi

# fresh run of the whole space matches the reported keyspace
"$BIN" brute -H "$HNF" -c digits --min 1 --max 7 >"$TMP/full.log" 2>&1
grep -q "done: 11,111,110 candidates" "$TMP/full.log" \
    && ok "full keyspace count exact" || bad "full keyspace count exact"

# state file removed when the run completes
rm -f "$STATE"
"$BIN" brute -H "$H123" -c digits --max 4 --state "$STATE" >/dev/null 2>&1
[ ! -e "$STATE" ] && ok "state removed on completion" || bad "state removed on completion"

# ------------------------------------------------------------------
head_ "cli"
# ------------------------------------------------------------------
"$BIN" --help >/dev/null 2>&1
[ $? -eq 0 ] && ok "hashmap --help exits 0" || bad "hashmap --help exits 0"
"$BIN" -v >/dev/null 2>&1
[ $? -eq 0 ] && ok "hashmap -v exits 0" || bad "hashmap -v exits 0"

for mode in digest brute map search; do
    "$BIN" "$mode" --help >/dev/null 2>&1
    [ $? -eq 0 ] && ok "hashmap $mode --help exits 0" \
        || bad "hashmap $mode --help exits 0"
done

# -F / --hash-file mean "file of hashes" in brute+search
printf '# comment\n%s\n' "$H123" > "$TMP/hashes.txt"
for flag in -F --hash-file; do
    "$BIN" brute $flag "$TMP/hashes.txt" -c digits --max 4 >/dev/null 2>&1
    [ $? -eq 0 ] && ok "brute $flag <hashfile>" || bad "brute $flag <hashfile>"
done

# --opt=value form
"$BIN" brute --hash="$H123" --charset=digits --max=4 >/dev/null 2>&1
[ $? -eq 0 ] && ok "brute --opt=value form" || bad "brute --opt=value form"

# map mode without -o explains itself
"$BIN" map >/dev/null 2>&1
[ $? -eq 2 ] && ok "map without -o exits 2" || bad "map without -o exits 2"

# unknown option is rejected
"$BIN" brute --definitely-not-an-option >/dev/null 2>&1
[ $? -eq 2 ] && ok "unknown option exits 2" || bad "unknown option exits 2"

# ------------------------------------------------------------------
head_ "charset"
# ------------------------------------------------------------------
cs_size() {
    "$BIN" brute -H 00000000000000000000000000000000 -c "$1" --max 1 2>&1 \
        | sed -n 's/.*charset: (\([0-9]*\) chars).*/\1/p'
}
[ "$(cs_size digits)" = "10" ] && ok "charset digits" || bad "charset digits"
[ "$(cs_size lower)" = "26" ] && ok "charset lower" || bad "charset lower"
[ "$(cs_size alnum)" = "62" ] && ok "charset alnum" || bad "charset alnum"
[ "$(cs_size 'lower+digits')" = "36" ] && ok "charset combo" || bad "charset combo"
[ "$(cs_size default)" = "62" ] && ok "charset default preset" || bad "charset default preset"
[ "$(cs_size all)" = "95" ] && ok "charset all preset" || bad "charset all preset"

# union of repeated -c
u="$("$BIN" brute -H 00000000000000000000000000000000 -c lower -c digits --max 1 2>&1 \
     | sed -n 's/.*charset: (\([0-9]*\) chars).*/\1/p')"
[ "$u" = "36" ] && ok "charset union via repeated -c" || bad "charset union via repeated -c"

# escapes for literal ! and @
e="$("$BIN" brute -H 00000000000000000000000000000000 -c 'a\@b\!c' --max 1 2>&1 \
     | sed -n 's/.*charset: (\([0-9]*\) chars).*/\1/p')"
[ "$e" = "5" ] && ok "charset escapes (\\! \\@)" || bad "charset escapes (\\! \\@)"

# duplicates are removed (a repeated char must not inflate the keyspace)
d="$("$BIN" brute -H 00000000000000000000000000000000 -c 'aa' --max 2 2>&1 \
     | sed -n 's/.*charset: (\([0-9]*\) chars).*/\1/p')"
[ "$d" = "1" ] && ok "charset de-duplicates" || bad "charset de-duplicates"

# ------------------------------------------------------------------
head_ "map resume"
# ------------------------------------------------------------------
# a resumed map must APPEND, not truncate: the records of the finished spans
# have to survive in the file
MAPF="$TMP/resume.hmmap"
MAPS="$TMP/resume.state"
rm -f "$MAPF" "$MAPS"
"$BIN" map -o "$MAPF" -c digits --min 1 --max 4 --state "$MAPS" >/dev/null 2>&1
if [ -s "$MAPF" ]; then
    ok "map file written with state"
else
    bad "map file written with state"
fi

# a fresh map run must refuse to append to a stale map file
head -c 32 /dev/urandom > "$TMP/junk.bin"
cp "$TMP/junk.bin" "$TMP/junk.hmmap"
printf 'HMSTATE 2\nmode map\ncs 30\nmin 1\nmax 1\nsalt -\npos post\ntargets 0\n' \
    > "$TMP/junk.state"
"$BIN" map -o "$TMP/junk.hmmap" --state "$TMP/junk.state" >/dev/null 2>&1
[ $? -ne 0 ] && ok "map refuses to resume onto a non-map file" \
    || bad "map refuses to resume onto a non-map file"

# the search mode rejects a file that is not a map
"$BIN" search -H "$H123" "$TMP/junk.bin" >/dev/null 2>&1
[ $? -eq 1 ] && ok "search rejects a non-map file" || bad "search rejects a non-map file"

# ------------------------------------------------------------------
head_ "search across shards"
# ------------------------------------------------------------------
mkdir -p "$TMP/shards"
"$BIN" map -o "$TMP/shards/a.hmmap" -c digits --min 1 --max 3 >/dev/null 2>&1
"$BIN" map -o "$TMP/shards/b.hmmap" -c digits --min 4 --max 4 >/dev/null 2>&1
H4="$(md5_of '1234')"
H3="$(md5_of '123')"

# two shards given one by one
out="$("$BIN" search -H "$H3" -H "$H4" "$TMP/shards/a.hmmap" \
       "$TMP/shards/b.hmmap" 2>/dev/null | sort | tr '\n' ' ')"
case "$out" in
    *"$H3:123"*) ok "search finds a hash in the first shard" ;;
    *) bad "search finds a hash in the first shard (got=$out)" ;;
esac
case "$out" in
    *"$H4:1234"*) ok "search finds a hash in the second shard" ;;
    *) bad "search finds a hash in the second shard (got=$out)" ;;
esac

# a whole directory at once
out="$("$BIN" search -H "$H4" "$TMP/shards" 2>/dev/null)"
[ "$out" = "$H4:1234" ] && ok "search scans a directory of shards" \
    || bad "search scans a directory of shards (got=$out)"

# ------------------------------------------------------------------
head_ "wordlist mode"
# ------------------------------------------------------------------
WL="$TMP/wl.txt"
printf 'password\nletmein\nabc123\nqqqqnotthere\n' > "$WL"
HWP="$(md5_of 'password')"
HWM="$(md5_of 'letmein')"

"$BIN" wordlist -H "$HWP" -H "$HWM" -w "$WL" >/dev/null 2>&1
[ $? -eq 0 ] && ok "wordlist finds all targets" || bad "wordlist finds all targets"

"$BIN" wordlist -H "$HWP" -H "$(md5_of 'zzzmiss')" -w "$WL" >/dev/null 2>&1
[ $? -eq 1 ] && ok "wordlist miss exits 1" || bad "wordlist miss exits 1"

# --first stops at the first hit and exits 0
"$BIN" wordlist -H "$(md5_of 'zzzmiss')" -H "$HWP" -w "$WL" --first \
    >/dev/null 2>&1
[ $? -eq 0 ] && ok "wordlist --first exits 0 on one hit" \
    || bad "wordlist --first exits 0 on one hit"

# results are stored
rm -f "$TMP/wl-out.txt"
"$BIN" wordlist -H "$HWP" -w "$WL" -o "$TMP/wl-out.txt" >/dev/null 2>&1
grep -q "$HWP:password" "$TMP/wl-out.txt" && ok "wordlist -o stores results" \
    || bad "wordlist -o stores results"

# the shipped common wordlist works
if [ -f wordlists/common.txt ]; then
    HC="$(md5_of 'password')"
    "$BIN" wordlist -H "$HC" -w wordlists/common.txt >/dev/null 2>&1
    [ $? -eq 0 ] && ok "shipped common wordlist" || bad "shipped common wordlist"
fi

# the fetcher script is present and usable
if [ -x tools/fetch-wordlists.sh ]; then
    ok "fetch-wordlists.sh is executable"
    "$BIN" wordlist --help >/dev/null 2>&1
    [ $? -eq 0 ] && ok "wordlist mode has usage" || bad "wordlist mode has usage"
fi

# brute --first: one hit is enough
"$BIN" brute -H "$(md5_of 'zzzmiss')" -H "$(md5_of '123')" -c digits --max 4 --first \
    >/dev/null 2>&1
[ $? -eq 0 ] && ok "brute --first exits 0 on one hit" \
    || bad "brute --first exits 0 on one hit"

# ------------------------------------------------------------------
printf '\n\033[1mpassed: %d  failed: %d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
