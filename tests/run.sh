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

# ------------------------------------------------------------------
head_ "digest mode"
# ------------------------------------------------------------------
for algo in md5 sha1 sha256; do
    for txt in "hello" "" "a" "The quick brown fox"; do
        want="$(printf '%s' "$txt" | ${algo}sum | cut -d' ' -f1)"
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
want="$(printf '%s' "$LONG" | md5sum | cut -d' ' -f1)"
got="$("$BIN" digest -i "$LONG")"
[ "$want" = "$got" ] && ok "digest long string" || bad "digest long string"

# file hashing
head -c 4096 /dev/urandom > "$TMP/blob.bin"
want="$(md5sum "$TMP/blob.bin" | cut -d' ' -f1)"
got="$("$BIN" digest -f "$TMP/blob.bin")"
[ "$want" = "$got" ] && ok "digest file" || bad "digest file"

# stdin mode (hashmap strips the line ending, so compare against printf w/o \n)
want="$(printf 'abc' | md5sum | cut -d' ' -f1)"
got="$(printf 'abc\n' | "$BIN" digest -i - | cut -d: -f1)"
[ "$want" = "$got" ] && ok "digest stdin" || bad "digest stdin"

# salted digest
want="$(printf 'saltabc' | md5sum | cut -d' ' -f1)"
got="$("$BIN" digest -i abc -s salt -p pre)"
[ "$want" = "$got" ] && ok "digest salted pre" || bad "digest salted pre"
want="$(printf 'abcsalt' | md5sum | cut -d' ' -f1)"
got="$("$BIN" digest -i abc -s salt -p post)"
[ "$want" = "$got" ] && ok "digest salted post" || bad "digest salted post"

# ------------------------------------------------------------------
head_ "brute mode"
# ------------------------------------------------------------------
H123="$(printf '123' | md5sum | cut -d' ' -f1)"
"$BIN" brute -H "$H123" -c digits --max 6 >"$TMP/out.txt" 2>&1
rc=$?
[ $rc -eq 0 ] && ok "brute hit exit 0" || bad "brute hit exit 0 (rc=$rc)"
grep -q "CRACKED" "$TMP/out.txt" && ok "brute prints CRACKED" || bad "brute prints CRACKED"

"$BIN" brute -H 00000000000000000000000000000000 -c digits --max 3 >/dev/null 2>&1
rc=$?
[ $rc -eq 1 ] && ok "brute miss exit 1" || bad "brute miss exit 1 (rc=$rc)"

# salted pre / post
HS="$(printf 'salt999' | md5sum | cut -d' ' -f1)"
"$BIN" brute -H "$HS" -c digits --max 4 -s salt -p pre >"$TMP/saltpre.txt" 2>&1
rc=$?
[ $rc -eq 0 ] && ok "brute salted pre" || bad "brute salted pre (rc=$rc)"
HS="$(printf '999salt' | md5sum | cut -d' ' -f1)"
"$BIN" brute -H "$HS" -c digits --max 4 -s salt -p post >"$TMP/saltpost.txt" 2>&1
rc=$?
[ $rc -eq 0 ] && ok "brute salted post" || bad "brute salted post (rc=$rc)"

# multiple targets
"$BIN" brute -H "$H123" -H "$(printf '456' | md5sum | cut -d' ' -f1)" \
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
HNF="$(printf 'definitelynotfound' | md5sum | cut -d' ' -f1)"
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
printf '\n\033[1mpassed: %d  failed: %d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
