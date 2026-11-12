# bcrypt

bcrypt is salted by design: every hash carries its own random salt, so there
is no global "hash space" to precompute. That is why a plain digest map does
not work for it — and why it is slow to attack.

The tool supports bcrypt in three ways, all built on a **self contained
implementation** (no libcrypt, no OpenSSL — the Blowfish tables are generated
from the hex digits of pi):

## 1. Verify candidates against a hash

The salt comes from the hash itself, so this is exactly what a real system
does:

```sh
hashmap wordlist -H '$2b$12$DCq7YPn5Rq63x1Lad4cll.kD3...' -w wordlists/common.txt
# [+] CRACKED  $2b$12$DCq7YPn5Rq63x1Lad4cll.kD3...  ->  password
```

A list of bcrypt hashes works too — every hash is checked with **its own
salt**, which is what real password dumps need:

```sh
hashmap wordlist -F hashes.txt -w wordlists/combined.txt -o cracked.txt
```

Brute force over a keyspace works as well:

```sh
hashmap brute -H '$2b$12$...' -c lower+digits --max 6
```

(That is slow on purpose — a cost of 12 means 4096 key schedule rounds per
candidate.)

## 2. The hashmap for bcrypt: a fixed salt

The trick that makes bcrypt precomputable: use a **fixed salt** for the whole
map. Then every candidate has a stable digest and the map works like any
other:

```sh
hashmap map -o bcrypt.hmmap --wordlist wordlists/combined.txt \
    --bcrypt --salt DCq7YPn5Rq63x1Lad4cll. --bcrypt-cost 12

hashmap search -H '$2b$12$DCq7YPn5Rq63x1Lad4cll.kD3...' bcrypt.hmmap
```

The map header stores the setting (`salt $2b$12$DCq7YPn5Rq63x1Lad4cll.`), and
the search refuses a hash that uses a different salt or cost — because it
would not match anyway.

This is the same trick hashcat uses for its "blowfish" tables with a fixed
salt. The cost: one map per salt, and the map is only valid for hashes that
were created with that exact salt.

## 3. What the map holds

A bcrypt map record is the raw 23 byte digest (the base64 part of the hash),
so a record is 23 + 1 + len bytes — a bit larger than an MD5 record, smaller
than a full SHA-256 one.

## Cost and speed

bcrypt is intentionally slow: a cost of 12 needs 4096 rounds of the
expensive key schedule per candidate. On 8 cores that is roughly a few
thousand candidates per second — which is why the map approach (build once,
look up many times) is the sensible one.

## Implementation

`src/bcrypt.c` is a port of the OpenBSD implementation:

- Blowfish with the P-array and the four S-boxes from the hex digits of pi
  (`src/bf_tables.h`, generated)
- the salted "expensive key schedule" of EksBlowfish
- the 192 bit magic `OrpheanBeholderScryDoubt`, encrypted 64 times
- bcrypt's own base64 alphabet

Verified against Python's `bcrypt` module (25/25 random cases, `$2a$`, `$2b$`
and `$2y$`, costs 4-10, keys with high bytes and long keys).
