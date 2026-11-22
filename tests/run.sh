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
# This space is intentionally far too large to finish before SIGTERM, even on
# fast CI runners. Wait for the first progress update (which is flushed) before
# signalling so that the process has installed its handler and begun work.
interrupt_run() {
    local log="$1" pid ready=0
    "$BIN" brute -H "$HNF" -c digits --min 1 --max 12 --state "$STATE" -t 4 \
        >"$log" 2>&1 &
    pid=$!
    for _ in {1..100}; do
        if grep -q 'tried' "$log"; then
            ready=1
            break
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -TERM "$pid" 2>/dev/null || ready=0
    wait "$pid" 2>/dev/null
    [ "$ready" -eq 1 ]
}

if interrupt_run "$TMP/res1.log" && [ -s "$STATE" ]; then
    ok "SIGTERM saves state file"
    grep -q "HMSTATE 2" "$STATE" && ok "state has magic" || bad "state has magic"

    # A short mismatched configuration prevents a missing/broken state from
    # accidentally starting an effectively unbounded fresh search.
    "$BIN" brute -H "$HNF" -c lower --min 1 --max 1 --state "$STATE" -t 1 \
        >/dev/null 2>&1
    [ $? -ne 0 ] && ok "state refuses mismatched config" || bad "state refuses mismatched config"

    if interrupt_run "$TMP/res2.log" && [ -s "$STATE" ] &&
       grep -q 'resumed from state' "$TMP/res2.log"; then
        first="$(grep -o 'done: [0-9,]* candidates' "$TMP/res1.log" | grep -o '[0-9,]*' | tr -d ,)"
        second="$(grep -o 'done: [0-9,]* candidates' "$TMP/res2.log" | grep -o '[0-9,]*' | tr -d ,)"
        if [ -n "$first" ] && [ -n "$second" ] &&
           [ "$((first + second))" -le 1111111111110 ] &&
           [ "$((first + second))" -gt 0 ]; then
            ok "resume continues interrupted work"
        else
            bad "resume continues interrupted work"
        fi
    else
        bad "resume continues interrupted work"
    fi
else
    bad "SIGTERM saves state file"
    bad "state has magic"
    bad "state refuses mismatched config"
    bad "resume continues interrupted work"
fi

# fresh run of the whole space matches the reported keyspace
"$BIN" brute -H "$HNF" -c digits --min 1 --max 7 -t 4 >"$TMP/full.log" 2>&1
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
head_ "map from a wordlist"
# ------------------------------------------------------------------
printf 'password\nletmein\nabc123\n' > "$TMP/src.txt"
"$BIN" map -o "$TMP/wl.hmmap" --wordlist "$TMP/src.txt" \
    --state "$TMP/wl.state" >/dev/null 2>&1
[ -s "$TMP/wl.hmmap" ] && ok "map from a wordlist is written" \
    || bad "map from a wordlist is written"
HWP="$(md5_of 'password')"
out="$("$BIN" search -H "$HWP" "$TMP/wl.hmmap" 2>/dev/null)"
[ "$out" = "$HWP:password" ] && ok "the wordlist map is searchable" \
    || bad "the wordlist map is searchable (got=$out)"
"$BIN" search -H "$(md5_of 'zzzmiss')" "$TMP/wl.hmmap" >/dev/null 2>&1
[ $? -eq 1 ] && ok "the wordlist map misses unknown hashes" \
    || bad "the wordlist map misses unknown hashes"

# a wordlist map can be resumed
rm -f "$TMP/wl2.hmmap" "$TMP/wl2.state"
"$BIN" map -o "$TMP/wl2.hmmap" --wordlist "$TMP/src.txt" \
    --state "$TMP/wl2.state" >/dev/null 2>&1
[ ! -e "$TMP/wl2.state" ] && ok "the wordlist map state is removed when done" \
    || bad "the wordlist map state is removed when done"

# long candidates must not corrupt the map (the search has to accept them)
LONG="$(printf 'x%.0s' $(seq 1 90))"
printf 'short\n%s\n' "$LONG" > "$TMP/long.txt"
"$BIN" map -o "$TMP/long.hmmap" --wordlist "$TMP/long.txt" >/dev/null 2>&1
HL="$(printf '%s' "$LONG" | md5sum | cut -d' ' -f1)"
out="$("$BIN" search -H "$HL" "$TMP/long.hmmap" 2>/dev/null)"
[ "$out" = "$HL:$LONG" ] && ok "the wordlist map handles long candidates" \
    || bad "the wordlist map handles long candidates (got=$out)"

# the wordlist source is rejected outside map mode
"$BIN" brute -H "$HWP" --wordlist "$TMP/src.txt" >/dev/null 2>&1
[ $? -eq 2 ] && ok "--wordlist is rejected in brute mode" \
    || bad "--wordlist is rejected in brute mode"

# ------------------------------------------------------------------
head_ "sha256 support"
# ------------------------------------------------------------------
S256="$(sha256_of 'password')"
S256_2="$(sha256_of '123')"

# brute: the algorithm follows the hash length (64 hex = sha256)
"$BIN" brute -H "$S256_2" -c digits --max 4 >/dev/null 2>&1
[ $? -eq 0 ] && ok "brute cracks a sha256 hash" || bad "brute cracks a sha256 hash"

# wordlist mode with sha256
"$BIN" wordlist -H "$S256" -w "$TMP/wl.txt" >/dev/null 2>&1
[ $? -eq 0 ] && ok "wordlist cracks a sha256 hash" || bad "wordlist cracks a sha256 hash"

# a sha256 map
"$BIN" map -o "$TMP/s256.hmmap" --wordlist "$TMP/wl.txt" --algo sha256 \
    >/dev/null 2>&1
out="$("$BIN" search -H "$S256" "$TMP/s256.hmmap" 2>/dev/null)"
[ "$out" = "$S256:password" ] && ok "a sha256 map is searchable" \
    || bad "a sha256 map is searchable (got=$out)"

# a truncated sha256 map: the same size as an md5 map, still searchable
"$BIN" map -o "$TMP/s256t.hmmap" --wordlist "$TMP/wl.txt" --algo sha256 \
    --truncate 16 >/dev/null 2>&1
out="$("$BIN" search -H "$S256" "$TMP/s256t.hmmap" 2>/dev/null)"
[ "$out" = "$S256:password" ] && ok "a truncated sha256 map is searchable" \
    || bad "a truncated sha256 map is searchable (got=$out)"
sm=$(wc -c < "$TMP/s256.hmmap")
st=$(wc -c < "$TMP/s256t.hmmap")
[ "$st" -lt "$sm" ] && ok "truncation shrinks the map ($st < $sm bytes)" \
    || bad "truncation shrinks the map ($st vs $sm bytes)"

# mixed hash lengths are refused
"$BIN" brute -H "$H123" -H "$S256" -c digits --max 2 >/dev/null 2>&1
[ $? -eq 2 ] && ok "mixed hash lengths are refused" || bad "mixed hash lengths are refused"

# ------------------------------------------------------------------
head_ "bcrypt"
# ------------------------------------------------------------------
# a known bcrypt hash of 'password' (cost 6, salt DCq7YPn5Rq63x1Lad4cll.)
BC_HASH='$2b$06$DCq7YPn5Rq63x1Lad4cll.kD3zZ845LsvMekyowTQk2VNmbDdQsWO'
BC_SALT='DCq7YPn5Rq63x1Lad4cll.'

printf 'password\nletmein\nabc123\n' > "$TMP/bc.txt"
"$BIN" wordlist -H "$BC_HASH" -w "$TMP/bc.txt" >/dev/null 2>&1
[ $? -eq 0 ] && ok "bcrypt: the wordlist finds the password" \
    || bad "bcrypt: the wordlist finds the password"

# the same hash loaded from a file (-F) must work too
printf '%s\n' "$BC_HASH" > "$TMP/bc-hashes.txt"
"$BIN" wordlist -F "$TMP/bc-hashes.txt" -w "$TMP/bc.txt" >/dev/null 2>&1
[ $? -eq 0 ] && ok "bcrypt: the wordlist finds the password from a hash file" \
    || bad "bcrypt: the wordlist finds the password from a hash file"

# a bcrypt map with a fixed salt, then a lookup in it
"$BIN" map -o "$TMP/bc.hmmap" --wordlist "$TMP/bc.txt" --bcrypt \
    --salt "$BC_SALT" --bcrypt-cost 6 >/dev/null 2>&1
out="$("$BIN" search -H "$BC_HASH" "$TMP/bc.hmmap" 2>/dev/null)"
case "$out" in
    *":password") ok "bcrypt: the map lookup finds the password" ;;
    *) bad "bcrypt: the map lookup finds the password (got=$out)" ;;
esac

# a hash with another salt must not match the map
BC_OTHER='$2b$06$If6bvum7QjO3b5EvQ5aSxS.Dt3mpH9ZZx4VEtb3Xhdzd6xOqmpCrpi'
"$BIN" search -H "$BC_OTHER" "$TMP/bc.hmmap" >/dev/null 2>&1
[ $? -ne 0 ] && ok "bcrypt: a different salt does not match" \
    || bad "bcrypt: a different salt does not match"

# brute force against a bcrypt hash (small space, low cost)
BC_TEST='$2b$04$DCq7YPn5Rq63x1Lad4cll.Fg1U403/BHS4qgV12/Ne2EXGwnxTDPm'
"$BIN" brute -H "$BC_TEST" -c digits --max 3 >/dev/null 2>&1
[ $? -eq 0 ] && ok "bcrypt: brute force works" || bad "bcrypt: brute force works"

# --archive: map output packed by the hashmap-archive companion (v2 default)
ARCH="$PWD/hashmap-archive"
if [ -x "$ARCH" ]; then
    HM_ARCHIVE="$ARCH" "$BIN" map -o "$TMP/arch.hmar" -c digits \
        --min 1 --max 2 --archive --state "$TMP/arch.state" >/dev/null 2>&1
    if [ $? -eq 0 ] && [ -f "$TMP/arch.hmar" ] && [ ! -e "$TMP/arch.hmar.hmmap.tmp" ]; then
        "$ARCH" unpack "$TMP/arch.hmar" "$TMP/arch.hmmap" 2>/dev/null
        out=$("$BIN" search -H "$(md5_of 42)" "$TMP/arch.hmmap" 2>/dev/null)
        case "$out" in
            *":42") ok "archive: map --archive packs via the companion" ;;
            *) bad "archive: map --archive packs via the companion (got=$out)" ;;
        esac
    else
        bad "archive: map --archive packs via the companion"
    fi

    # the archive itself is searchable without unpacking it
    out=$("$BIN" search -H "$(md5_of 42)" "$TMP/arch.hmar" 2>/dev/null)
    case "$out" in
        *":42") ok "archive: search decodes .hmar directly" ;;
        *) bad "archive: search decodes .hmar directly (got=$out)" ;;
    esac

    # the parallel decoder and the checksum-free fast path agree
    out=$("$BIN" search -t 4 -H "$(md5_of 42)" "$TMP/arch.hmar" 2>/dev/null)
    case "$out" in
        *":42") ok "archive: search decodes .hmar with worker threads" ;;
        *) bad "archive: search decodes .hmar with worker threads (got=$out)" ;;
    esac
    out=$("$BIN" search --no-verify -H "$(md5_of 42)" "$TMP/arch.hmar" 2>/dev/null)
    case "$out" in
        *":42") ok "archive: --no-verify still finds the row" ;;
        *) bad "archive: --no-verify still finds the row (got=$out)" ;;
    esac

    # HMARCH1 archives are readable too
    if "$ARCH" pack --legacy "$TMP/arch.hmmap" "$TMP/legacy.hmar" 2>/dev/null; then
        out=$("$BIN" search -H "$(md5_of 42)" "$TMP/legacy.hmar" 2>/dev/null)
        case "$out" in
            *":42") ok "archive: search reads HMARCH1 archives" ;;
            *) bad "archive: search reads HMARCH1 archives (got=$out)" ;;
        esac
    else
        bad "archive: search reads HMARCH1 archives (pack failed)"
    fi

    # a bcrypt archive keeps its literal digests and its salt check
    if "$ARCH" pack "$TMP/bc.hmmap" "$TMP/bc.hmar" 2>/dev/null; then
        out=$("$BIN" search -H "$BC_HASH" "$TMP/bc.hmar" 2>/dev/null)
        case "$out" in
            *":password") ok "archive: bcrypt digests decode from .hmar" ;;
            *) bad "archive: bcrypt digests decode from .hmar (got=$out)" ;;
        esac
        "$BIN" search -H "$BC_OTHER" "$TMP/bc.hmar" >/dev/null 2>&1
        [ $? -ne 0 ] && ok "archive: bcrypt salt mismatch is refused" \
            || bad "archive: bcrypt salt mismatch is refused"
    else
        bad "archive: bcrypt digests decode from .hmar (pack failed)"
    fi

    # a damaged archive is rejected by the checksum
    cp "$TMP/arch.hmar" "$TMP/damaged.hmar"
    printf '\377' | dd of="$TMP/damaged.hmar" bs=1 seek=40 conv=notrunc status=none
    "$BIN" search -H "$(md5_of 42)" "$TMP/damaged.hmar" >/dev/null 2>&1
    [ $? -ne 0 ] && ok "archive: a damaged archive is rejected" \
        || bad "archive: a damaged archive is rejected"
    # an existing archive destination is never overwritten
    HM_ARCHIVE="$ARCH" "$BIN" map -o "$TMP/arch.hmar" -c digits \
        --max 2 --archive --state "$TMP/arch2.state" >/dev/null 2>&1
    [ $? -ne 0 ] && ok "archive: an existing .hmar is never overwritten" \
        || bad "archive: an existing .hmar is never overwritten"
    # a missing companion fails but keeps the complete plain map
    HM_ARCHIVE=/nonexistent "$BIN" map -o "$TMP/nope.hmar" -c digits --max 2 \
        --archive --state "$TMP/nope.state" >/dev/null 2>&1
    [ $? -ne 0 ] && [ -f "$TMP/nope.hmar.hmmap.tmp" ] \
        && ok "archive: missing companion keeps the plain map" \
        || bad "archive: missing companion keeps the plain map"
else
    printf '  \033[33mSKIP\033[0m archive tests: ./hashmap-archive not built\n'
fi


# ------------------------------------------------------------------
head_ "indexed multi-target matching"
# ------------------------------------------------------------------
A="$(md5_of 0)"; B="$(md5_of 1)"; C="$(md5_of 2)"; D="$(md5_of 3)"
printf '0\n1\n2\n3\n' >"$TMP/multi-words.txt"
"$BIN" brute -H "$A" -H "$A" -H "$B" -H "$C" -H "$D" -c digits \
    --min 1 --max 1 -t 2 >"$TMP/multi-brute.txt" 2>&1
[ $? -eq 0 ] && [ "$(grep -c CRACKED "$TMP/multi-brute.txt")" -eq 5 ] \
    && ok "brute: indexed targets including duplicates" \
    || bad "brute: indexed targets including duplicates"
"$BIN" wordlist -H "$A" -H "$A" -H "$B" -H "$C" -H "$D" \
    -w "$TMP/multi-words.txt" -t 2 >"$TMP/multi-wordlist.txt" 2>&1
[ $? -eq 0 ] && [ "$(grep -c CRACKED "$TMP/multi-wordlist.txt")" -eq 5 ] \
    && ok "wordlist: indexed targets including duplicates" \
    || bad "wordlist: indexed targets including duplicates"

# ------------------------------------------------------------------
head_ "CPU and accelerator detection"
# ------------------------------------------------------------------
# the cpu mode reports the machine and the kernels picked for it
out="$("$BIN" cpu 2>/dev/null)"
echo "$out" | grep -q "^features:" && ok "cpu: features are reported" \
    || bad "cpu: features are reported"
echo "$out" | grep -qE "^kernels:  md5 (4|8|16)-lane" \
    && ok "cpu: the md5 kernel width is reported" \
    || bad "cpu: the md5 kernel width is reported"
echo "$out" | grep -q "^tuned:" && ok "cpu: autotune reports a choice" \
    || bad "cpu: autotune reports a choice"
echo "$out" | grep -q "^accelerator backend: none" && ok "accelerator: backend availability is reported" \
    || bad "accelerator: backend availability is reported"
HM_CPU=off "$BIN" cpu | grep -q '^kernels:  md5 4-lane, sha256 4-lane' \
    && ok "cpu: off selects baseline" || bad "cpu: off selects baseline"
HM_CPU=avx2 "$BIN" cpu | grep -qE '^kernels:  md5 (4|8)-lane, sha256 (4|8)-lane' \
    && ok "cpu: avx2 limits width" || bad "cpu: avx2 limits width"

# every dispatch mode must still crack the same hash
for mode in off avx2 avx512; do
    HM_CPU=$mode "$BIN" brute -H 202cb962ac59075b964b07152d234b70 -c digits \
        --min 3 --max 3 >/dev/null 2>&1
    [ $? -eq 0 ] && ok "cpu: HM_CPU=$mode cracks" \
        || bad "cpu: HM_CPU=$mode cracks"
done

# ------------------------------------------------------------------
printf '\n\033[1mpassed: %d  failed: %d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
