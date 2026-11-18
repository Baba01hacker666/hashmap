#include "rsm.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>
#include <limits>
#include <openssl/sha.h>
#include <queue>
#include <stdexcept>
#include <utility>

namespace rsm {
namespace {

using View = std::string_view;
using Size = std::size_t;
using U64 = std::uint64_t;
constexpr View magic = "RSM1";
constexpr Size cache_width = 32;
constexpr Size max_ef_width = 64;
constexpr Size max_token = 24;
constexpr unsigned max_tokens = 96;
constexpr unsigned symbols = 256 + max_tokens;
constexpr Size size_max = std::numeric_limits<Size>::max();
static_assert(SHA256_DIGEST_LENGTH == cache_width);
static_assert(sizeof(Size) <= sizeof(U64));

[[noreturn]] void fail(const char* msg) { throw std::runtime_error(msg); }

Size add(Size a, Size b) {
    if (b > size_max - a) fail("size overflow");
    return a + b;
}
Size mul(Size a, Size b) {
    if (a && b > size_max / a) fail("size overflow");
    return a * b;
}
Size to_size(U64 n) {
    if (n > size_max) fail("size out of range");
    return static_cast<Size>(n);
}
constexpr Size ceil_bytes(Size nbits) { return nbits / 8 + (nbits % 8 != 0); }
constexpr unsigned octet(char c) { return static_cast<unsigned char>(c); }
constexpr unsigned mask(unsigned width) { return (1U << width) - 1; }  // width <= 8

bool key_less(View a, View b) {
    const Size n = std::min(a.size(), b.size());
    const int cmp = n ? std::memcmp(a.data(), b.data(), n) : 0;
    return cmp < 0 || (cmp == 0 && a.size() < b.size());
}

void put_byte(Bytes& out, unsigned value) { out.push_back(static_cast<char>(value)); }
void put_var(Bytes& out, U64 x) {
    while (x >= 128) {
        put_byte(out, 128U | static_cast<unsigned>(x & 127));
        x >>= 7;
    }
    put_byte(out, static_cast<unsigned>(x));
}
unsigned var_size(U64 x) {
    unsigned n = 1;
    while (x >= 128) { x >>= 7; ++n; }
    return n;
}
void put_frame(Bytes& out, View lane) {
    put_var(out, lane.size());
    out.append(lane);
}
void set_flag(Bytes& bitmap, Size i) {
    bitmap[i / 8] = static_cast<char>(octet(bitmap[i / 8]) | (1U << (i % 8)));
}
bool flag(View bitmap, Size i) { return (octet(bitmap[i / 8]) & (1U << (i % 8))) != 0; }

class Reader {
public:
    explicit Reader(View data) : data_(data) {}
    View take(Size n) {
        if (n > data_.size()) fail("truncated frame");
        View result = data_.substr(0, n);
        data_.remove_prefix(n);
        return result;
    }
    unsigned byte() { return octet(take(1).front()); }
    U64 var() {
        U64 value = 0;
        for (unsigned shift = 0; shift <= 63; shift += 7) {
            const unsigned b = byte();
            if (shift == 63 && (b & 127U) > 1) fail("invalid varint");
            value |= static_cast<U64>(b & 127U) << shift;
            if (b < 128) {
                if (shift && !b) fail("invalid varint");
                return value;
            }
        }
        fail("invalid varint");
    }
    Size size() { return to_size(var()); }
    View frame() { return take(size()); }
    View rest() { return take(data_.size()); }
    void end() const { if (!data_.empty()) fail("trailing frame bytes"); }
private:
    View data_;
};

class BitWriter {
public:
    void put(U64 value, unsigned width) {
        while (width) {
            const unsigned count = std::min(8 - used_, width);
            width -= count;
            pending_ |= (static_cast<unsigned>(value >> width) & mask(count)) << (8 - used_ - count);
            used_ += count;
            if (used_ == 8) flush();
        }
    }
    void bytes(View s) {
        if (!used_) out_.append(s);
        else for (char c : s) put(octet(c), 8);
    }
    void zeros(Size n) {
        if (used_) {
            const auto k = static_cast<unsigned>(std::min<Size>(n, 8 - used_));
            put(0, k);
            n -= k;
        }
        out_.append(n / 8, '\0');
        put(0, static_cast<unsigned>(n % 8));
    }
    Bytes finish() {
        if (used_) flush();
        return std::move(out_);
    }
private:
    void flush() { put_byte(out_, pending_); pending_ = used_ = 0; }
    Bytes out_;
    unsigned pending_ = 0;
    unsigned used_ = 0;
};

class BitReader {
public:
    explicit BitReader(View data) : data_(data), nbits_(mul(data.size(), 8)) {}
    Size remaining() const { return nbits_ - at_; }
    unsigned one() {
        if (!remaining()) fail("truncated bits");
        const Size i = at_++;
        return (octet(data_[i / 8]) >> (7 - i % 8)) & 1U;
    }
    U64 get(unsigned width) {
        if (width > remaining()) fail("truncated bits");
        U64 value = 0;
        while (width) {
            const unsigned off = static_cast<unsigned>(at_ % 8);
            const unsigned count = std::min(width, 8 - off);
            const unsigned p = (octet(data_[at_ / 8]) >> (8 - off - count)) & mask(count);
            value = (value << count) | p;
            at_ += count;
            width -= count;
        }
        return value;
    }
    void bytes_to(char* dest, Size n) {
        if (n > remaining() / 8) fail("truncated bits");
        if (!n) return;
        if (at_ % 8 == 0) {
            std::memcpy(dest, data_.data() + at_ / 8, n);
            at_ += n * 8;
        } else {
            for (Size j = 0; j < n; ++j) dest[j] = static_cast<char>(get(8));
        }
    }
    void pad() {
        if (remaining() >= 8 || get(static_cast<unsigned>(remaining())) != 0) fail("invalid bit padding");
    }
private:
    View data_;
    Size nbits_;
    Size at_ = 0;
};

struct Budget {
    Size remaining;
    void spend(Size n) {
        if (n > remaining) fail("decoded byte limit exceeded");
        remaining -= n;
    }
};

Bytes shape(const std::vector<Size>& lengths) {
    if (lengths.empty()) return Bytes(1, '\1');
    const auto [lo, hi] = std::minmax_element(lengths.begin(), lengths.end());
    Bytes head;
    if (*lo == *hi) {
        put_var(head, add(*lo, 1));
        return head;
    }
    Size var_cost = 2;
    for (Size n : lengths) var_cost = add(var_cost, var_size(n));
    const auto width = static_cast<unsigned>(std::bit_width(*hi - *lo));
    if (add(3 + var_size(*lo), ceil_bytes(mul(width, lengths.size()))) >= var_cost) {
        head.assign(2, '\0');
        head.reserve(var_cost);
        for (Size n : lengths) put_var(head, n);
    } else {
        head.assign("\0\1", 2);
        put_var(head, *lo);
        put_byte(head, width);
        BitWriter bits;
        for (Size n : lengths) bits.put(n - *lo, width);
        head += bits.finish();
    }
    return head;
}

std::vector<Size> unshape(Reader& in, Size n) {
    const Size fixed = in.size();
    if (fixed) return std::vector<Size>(n, fixed - 1);
    const unsigned mode = in.byte();
    std::vector<Size> out;
    out.reserve(n);
    if (!mode) {
        for (Size i = 0; i < n; ++i) out.push_back(in.size());
    } else if (mode == 1) {
        const Size low = in.size();
        const unsigned width = in.byte();
        if (width < 1 || width > 64) fail("invalid length-vector bit width");
        BitReader bits(in.take(ceil_bytes(mul(width, n))));
        for (Size i = 0; i < n; ++i) out.push_back(add(low, to_size(bits.get(width))));
        bits.pad();
    } else fail("unknown length-vector mode");
    return out;
}

// Pair counts are bounded by the 768 x 96 byte training sample. The touched
// list avoids rescanning the entire pair alphabet after each training pass.
std::vector<Bytes> train_bpe(const std::vector<View>& fields) {
    const Size sample = std::min<Size>(768, fields.size());
    std::vector<std::vector<unsigned>> work;
    work.reserve(sample);
    for (Size i = 0; i < sample; ++i) {
        // floor(i * size / sample), without multiplying a possibly large size.
        const Size rank = i * (fields.size() / sample) + i * (fields.size() % sample) / sample;
        const auto s = fields[rank].substr(0, 96);
        if (s.size() >= 2) {
            auto& row = work.emplace_back();
            row.reserve(s.size());
            for (char c : s) row.push_back(octet(c));
        }
    }
    std::vector<Bytes> text;
    text.reserve(symbols);
    for (unsigned i = 0; i < 256; ++i) text.emplace_back(1, static_cast<char>(i));
    std::vector<unsigned> counts(symbols * symbols, 0), touched;
    for (unsigned step = 0; step < max_tokens; ++step) {
        for (const auto& row : work) {
            for (Size i = 1; i < row.size(); ++i) {
                const unsigned key = row[i - 1] * symbols + row[i];
                if (counts[key]++ == 0) touched.push_back(key);
            }
        }
        unsigned best = symbols * symbols, max_count = 0;
        for (unsigned key : touched) {
            const unsigned count = std::exchange(counts[key], 0U);
            if (count >= 10 && text[key / symbols].size() + text[key % symbols].size() <= max_token &&
                (count > max_count || (count == max_count && key < best))) {
                best = key;
                max_count = count;
            }
        }
        touched.clear();
        if (!max_count) break;
        const unsigned a = best / symbols, b = best % symbols;
        auto joined = text[a] + text[b];
        const auto same = std::find(text.begin() + 256, text.end(), joined);
        auto id = static_cast<unsigned>(same - text.begin());
        if (same == text.end()) text.push_back(std::move(joined));
        for (auto& row : work) {
            Size out = 0;
            for (Size i = 0; i < row.size();) {
                if (i + 1 < row.size() && row[i] == a && row[i + 1] == b) {
                    row[out++] = id;
                    i += 2;
                } else row[out++] = row[i++];
            }
            row.resize(out);
        }
    }
    std::vector<Bytes> vocab(std::make_move_iterator(text.begin() + 256), std::make_move_iterator(text.end()));
    std::sort(vocab.begin(), vocab.end(), key_less);
    return vocab;
}

using Histogram = std::array<Size, symbols>;
using Lengths = std::array<unsigned, symbols>;
using Plan = std::vector<unsigned>;

Lengths huffman_lengths(const Histogram& freq) {
    struct Node { unsigned left; unsigned right; unsigned symbol; };
    using Rank = std::pair<Size, unsigned>;  // frequency, insertion serial
    std::priority_queue<Rank, std::vector<Rank>, std::greater<Rank>> heap;
    std::vector<Node> tree;
    tree.reserve(2 * symbols);
    for (unsigned id = 0; id < freq.size(); ++id) {
        if (freq[id]) {
            heap.emplace(freq[id], static_cast<unsigned>(tree.size()));
            tree.push_back({0, 0, id});
        }
    }
    Lengths result{};
    if (heap.empty()) return result;
    while (heap.size() > 1) {
        const auto [a, left] = heap.top(); heap.pop();
        const auto [b, right] = heap.top(); heap.pop();
        heap.emplace(add(a, b), static_cast<unsigned>(tree.size()));
        tree.push_back({left, right, symbols});
    }
    std::vector<std::pair<unsigned, unsigned>> stack{{heap.top().second, 0}};
    while (!stack.empty()) {
        const auto [i, depth] = stack.back();
        stack.pop_back();
        const auto& node = tree[i];
        if (node.symbol < symbols) result[node.symbol] = std::max(1U, depth);
        else {
            stack.emplace_back(node.left, depth + 1);
            stack.emplace_back(node.right, depth + 1);
        }
    }
    return result;
}

struct Code { U64 value = 0; unsigned width = 0; };
using Codes = std::array<Code, symbols>;

Codes canonical(const Lengths& lengths) {
    std::vector<std::pair<unsigned, unsigned>> order;
    for (unsigned i = 0; i < lengths.size(); ++i) if (lengths[i]) order.emplace_back(lengths[i], i);
    std::sort(order.begin(), order.end());
    Codes result{};
    U64 code = 0;
    unsigned prev = 0;
    for (auto [width, id] : order) {
        if (width > 63) fail("invalid Huffman code length");
        code <<= width - prev;
        if (code >= (U64{1} << width)) fail("overfull Huffman codebook");
        result[id] = {code++, width};
        prev = width;
    }
    return result;
}

class Tokenizer {
public:
    explicit Tokenizer(const std::vector<Bytes>& vocab) {
        for (unsigned i = 0; i < vocab.size(); ++i) first_[octet(vocab[i].front())].push_back({vocab[i], 256 + i});
        for (auto& options : first_) std::sort(options.begin(), options.end(), [](const auto& a, const auto& b) {
            return a.first.size() != b.first.size() ? a.first.size() > b.first.size() : a.second < b.second;
        });
    }

    Plan greedy(View s) const {
        Plan result;
        while (!s.empty()) {
            unsigned id = octet(s.front());
            Size span = 1;
            for (auto [text, tok] : first_[id]) {
                if (s.starts_with(text)) { id = tok; span = text.size(); break; }
            }
            result.push_back(id);
            s.remove_prefix(span);
        }
        return result;
    }

    Plan optimal(View s, const Lengths& lengths) const {
        std::vector<Size> d(add(s.size(), 1), 0);
        std::vector<std::pair<unsigned, Size>> next(s.size());
        for (Size j = s.size(); j != 0;) {
            --j;
            const unsigned literal = octet(s[j]);
            Size cost = lengths[literal] + d[j + 1], span = 1;
            unsigned id = literal;
            for (auto [text, tok] : first_[literal]) {
                if (s.substr(j).starts_with(text)) {
                    const Size w = lengths[tok] + d[j + text.size()];
                    if (w < cost) { cost = w; id = tok; span = text.size(); }
                }
            }
            d[j] = cost;
            next[j] = {id, span};
        }
        Plan result;
        for (Size j = 0; j < s.size();) {
            const auto [id, span] = next[j];
            result.push_back(id);
            j += span;
        }
        return result;
    }
private:
    std::array<std::vector<std::pair<View, unsigned>>, 256> first_;
};

Bytes huff_header(const Lengths& lengths, const std::vector<Bytes>& vocab) {
    Bytes out(32, '\0');
    for (unsigned id = 0; id < 256; ++id) if (lengths[id]) {
        set_flag(out, id);
        put_byte(out, lengths[id]);
    }
    put_var(out, vocab.size());
    for (unsigned i = 0; i < vocab.size(); ++i) {
        put_var(out, vocab[i].size());
        out.append(vocab[i]);
        put_byte(out, lengths[256 + i]);
    }
    return out;
}

void consider(Bytes& best, Bytes candidate) {
    if (candidate.size() < best.size()) best = std::move(candidate);
}
Bytes field_lane(const std::vector<View>& fields, Profile profile) {
    std::vector<Size> lengths;
    lengths.reserve(fields.size());
    Size total = 0;
    for (auto f : fields) { lengths.push_back(f.size()); total = add(total, f.size()); }
    const auto desc = shape(lengths);
    Bytes best(1, '\0');
    best.reserve(add(add(1, desc.size()), total));
    best += desc;
    for (auto f : fields) best.append(f);
    if (profile == Profile::plain || profile == Profile::structural || total < 64) return best;

    const auto try_huffman = [&](const Histogram& counts, const Lengths& lens,
                                 const std::vector<Bytes>& vocab, auto write_tokens) {
        if (*std::max_element(lens.begin(), lens.end()) > 63) return;
        Size bits = 0;
        for (unsigned i = 0; i < symbols; ++i) bits = add(bits, mul(counts[i], lens[i]));
        Bytes header(1, '\1');
        header += desc;
        header += huff_header(lens, vocab);
        const Size size = add(header.size(), ceil_bytes(bits));
        if (size >= best.size()) return;
        BitWriter writer;
        const auto codes = canonical(lens);
        write_tokens([&](unsigned id) { writer.put(codes[id].value, codes[id].width); });
        header += writer.finish();
        if (header.size() != size) fail("internal Huffman size mismatch");
        best = std::move(header);
    };

    Histogram byte_freq{};
    for (auto f : fields) for (char c : f) ++byte_freq[octet(c)];
    try_huffman(byte_freq, huffman_lengths(byte_freq), {}, [&](auto emit) {
        for (auto f : fields) for (char c : f) emit(octet(c));
    });
    if (profile == Profile::byte_huff || total < 512) return best;

    const auto vocab = train_bpe(fields);
    if (vocab.empty()) return best;
    const Tokenizer tokenizer(vocab);
    std::vector<Plan> plans;
    plans.reserve(fields.size());
    Histogram freq{};
    for (auto f : fields) {
        plans.push_back(tokenizer.greedy(f));
        for (unsigned id : plans.back()) ++freq[id];
    }
    auto smooth = freq;
    for (unsigned i = 0; i < 256; ++i) if (byte_freq[i]) ++smooth[i];
    for (unsigned i = 256; i < 256 + vocab.size(); ++i) ++smooth[i];
    const auto lens = huffman_lengths(smooth);
    if (*std::max_element(lens.begin(), lens.end()) > 63) return best;
    if (profile == Profile::rsm) {
        freq.fill(0);
        for (Size i = 0; i < fields.size(); ++i) {
            plans[i] = tokenizer.optimal(fields[i], lens);
            for (unsigned id : plans[i]) ++freq[id];
        }
    }
    try_huffman(freq, lens, vocab, [&](auto emit) {
        for (const auto& plan : plans) for (unsigned id : plan) emit(id);
    });
    return best;
}

Bytes read_huffman(Reader& in, Size expected) {
    Lengths lengths{};
    std::array<Bytes, symbols> texts;
    const auto literals = in.take(32);
    for (unsigned id = 0; id < 256; ++id) if (flag(literals, id)) {
        lengths[id] = in.byte();
        if (!lengths[id]) fail("zero Huffman code length");
        texts[id] = Bytes(1, static_cast<char>(id));
    }
    const Size n = in.size();
    if (n > max_tokens) fail("too many tokens");
    View prev;
    for (unsigned id = 256; id < 256 + n; ++id) {
        const Size width = in.size();
        if (width < 2 || width > max_token) fail("invalid token length");
        const auto word = in.take(width);
        if (!key_less(prev, word)) fail("unordered or duplicate token");
        prev = word;
        texts[id] = word;
        lengths[id] = in.byte();
        if (!lengths[id]) fail("zero Huffman code length");
    }
    const auto codes = canonical(lengths);
    struct Node { std::array<int, 2> child{-1, -1}; int symbol = -1; };
    std::vector<Node> tree(1);
    for (unsigned id = 0; id < codes.size(); ++id) {
        const auto [code, width] = codes[id];
        if (!width) continue;
        Size at = 0;
        for (unsigned j = width; j != 0; --j) {
            const auto bit = static_cast<unsigned>((code >> (j - 1)) & 1U);
            int target = tree[at].child[bit];
            if (target < 0) {
                target = static_cast<int>(tree.size());
                tree[at].child[bit] = target;
                tree.emplace_back();
            }
            at = static_cast<Size>(target);
        }
        tree[at].symbol = static_cast<int>(id);
    }
    if (tree.size() == 1) fail("empty Huffman codebook");
    BitReader bits(in.rest());
    if (expected / max_token + (expected % max_token != 0) > bits.remaining()) fail("truncated Huffman stream");
    Bytes out;
    out.reserve(expected);
    while (out.size() < expected) {
        Size at = 0;
        while (tree[at].symbol < 0) {
            const int next = tree[at].child[bits.one()];
            if (next < 0) fail("not a Huffman codeword");
            at = static_cast<Size>(next);
        }
        const auto& t = texts[static_cast<Size>(tree[at].symbol)];
        if (t.size() > expected - out.size()) fail("Huffman overrun");
        out += t;
    }
    bits.pad();
    return out;
}

std::vector<Bytes> read_lane(Reader& in, Size n, Budget& budget) {
    const unsigned mode = in.byte();
    const auto widths = unshape(in, n);
    Size sum = 0;
    for (Size length : widths) sum = add(sum, length);
    budget.spend(sum);
    Bytes expanded;
    View flat;
    if (mode == 0) flat = in.take(sum);
    else if (mode == 1) { expanded = read_huffman(in, sum); flat = expanded; }
    else fail("unknown field mode");
    in.end();
    std::vector<Bytes> out;
    out.reserve(n);
    for (Size width : widths) {
        out.emplace_back(flat.substr(0, width));
        flat.remove_prefix(width);
    }
    return out;
}

Size lcp(View a, View b) {
    const Size limit = std::min(a.size(), b.size());
    Size i = 0;
    while (i < limit && a[i] == b[i]) ++i;
    return i;
}

// Read the upper key bits with checked 64-bit arithmetic. A quotient too
// large for this calculation cannot beat the candidate with zero high bits;
// that candidate is linear in the number of rows, not the key universe size.
std::optional<U64> high_quotient(View key, unsigned ell) {
    const Size nbits = key.size() * 8 - ell;
    U64 x = 0;
    for (Size i = 0; i < nbits / 8; ++i) {
        if (x > (std::numeric_limits<U64>::max() >> 8)) return std::nullopt;
        x = (x << 8) | octet(key[i]);
    }
    const auto partial = static_cast<unsigned>(nbits % 8);
    if (partial) {
        if (x > (std::numeric_limits<U64>::max() >> partial)) return std::nullopt;
        x = (x << partial) | (octet(key[nbits / 8]) >> (8 - partial));
    }
    return x;
}

std::optional<Bytes> elias_fano(const std::vector<View>& keys) {
    if (keys.empty()) return std::nullopt;
    const Size w = keys.front().size();
    if (!w || w > max_ef_width) return std::nullopt;
    for (auto k : keys) if (k.size() != w) return std::nullopt;
    const auto max_ell = static_cast<unsigned>(8 * w);
    const Size bound = add(ceil_bytes(mul(keys.size(), max_ell + 1)), var_size(max_ell));
    unsigned ell = max_ell;
    Size best = bound;
    for (unsigned l = 0; l < max_ell; ++l) {
        const auto high = high_quotient(keys.back(), l);
        const Size base = mul(keys.size(), l + 1);
        if (!high || *high > size_max - base) continue;
        const Size cost = add(var_size(l), ceil_bytes(base + static_cast<Size>(*high)));
        if (cost < best || (cost == best && l < ell)) { best = cost; ell = l; }
    }
    BitWriter bits;
    const Size tail_bytes = ell / 8;
    const unsigned partial = ell % 8;
    for (auto k : keys) {
        if (partial) bits.put(octet(k[w - tail_bytes - 1]) & mask(partial), partial);
        bits.bytes(k.substr(w - tail_bytes));
    }
    U64 prev = 0;
    for (auto k : keys) {
        const auto high = high_quotient(k, ell);
        if (!high || *high < prev) fail("internal high quotient mismatch");
        bits.zeros(to_size(*high - prev));
        bits.put(1, 1);
        prev = *high;
    }
    Bytes out(1, '\2');
    put_var(out, w);
    put_var(out, ell);
    out += bits.finish();
    if (out.size() != add(1 + var_size(w), best)) fail("internal Elias-Fano size mismatch");
    return out;
}

std::vector<Bytes> read_elias(Reader& in, Size n, Budget& budget) {
    const Size w = in.size(), ell = in.size();
    if (!n || w < 1 || w > max_ef_width || ell > 8 * w) fail("invalid Elias-Fano header");
    budget.spend(mul(n, w));
    BitReader bits(in.rest());
    if (mul(n, ell + 1) > bits.remaining()) fail("truncated Elias-Fano stream");
    std::vector<Bytes> keys(n, Bytes(w, '\0'));
    const Size tail_bytes = ell / 8;
    const auto partial = static_cast<unsigned>(ell % 8);
    for (auto& key : keys) {
        if (partial) key[w - tail_bytes - 1] = static_cast<char>(bits.get(partial));
        bits.bytes_to(key.data() + (w - tail_bytes), tail_bytes);
    }
    U64 high = 0;
    for (auto& key : keys) {
        while (!bits.one()) {
            if (high == std::numeric_limits<U64>::max()) fail("Elias-Fano key out of range");
            ++high;
        }
        U64 quotient = high;
        Size i = w - tail_bytes;
        if (partial) {
            --i;
            key[i] = static_cast<char>(octet(key[i]) | ((quotient & mask(8 - partial)) << partial));
            quotient >>= 8 - partial;
        }
        while (i) { key[--i] = static_cast<char>(quotient & 255U); quotient >>= 8; }
        if (quotient) fail("Elias-Fano key out of range");
    }
    bits.pad();
    return keys;
}

Bytes key_lane(const std::vector<View>& keys, Profile profile) {
    Bytes best(1, '\0');
    best += field_lane(keys, profile);
    if (profile == Profile::plain) return best;
    std::vector<Size> lengths;
    std::vector<View> suffixes;
    lengths.reserve(keys.size());
    suffixes.reserve(keys.size());
    View prev;
    for (auto k : keys) {
        const Size p = lcp(prev, k);
        lengths.push_back(p);
        suffixes.push_back(k.substr(p));
        prev = k;
    }
    Bytes front(1, '\1');
    front += shape(lengths);
    front += field_lane(suffixes, profile);
    consider(best, std::move(front));
    auto ef = elias_fano(keys);
    if (ef) consider(best, std::move(*ef));
    return best;
}

std::vector<Bytes> read_keys(View data, Size n, Budget& budget) {
    Reader in(data);
    const unsigned method = in.byte();
    std::vector<Bytes> keys;
    if (method == 0) keys = read_lane(in, n, budget);
    else if (method == 1) {
        const auto p = unshape(in, n);
        keys = read_lane(in, n, budget);
        for (Size i = 0; i < n; ++i) {
            const View prev = i ? View(keys[i - 1]) : View();
            if (p[i] > prev.size()) fail("invalid front-code prefix");
            budget.spend(p[i]);
            if (p[i]) keys[i].insert(0, prev.substr(0, p[i]));
        }
    } else if (method == 2) keys = read_elias(in, n, budget);
    else fail("unknown key mode");
    for (Size i = 1; i < keys.size(); ++i)
        if (!key_less(keys[i - 1], keys[i])) fail("keys are not strictly increasing");
    return keys;
}

Bytes digest(View key) {
    std::array<unsigned char, cache_width> hash{};
    // A default-constructed empty string_view may have a null pointer.
    const auto* data = reinterpret_cast<const unsigned char*>(key.empty() ? "" : key.data());
    if (!SHA256(data, key.size(), hash.data())) fail("SHA-256 failed");
    return Bytes(reinterpret_cast<const char*>(hash.data()), hash.size());
}

Bytes cache_lane(const std::vector<const Entry*>& ranks, Profile profile) {
    Bytes best(1, '\0');
    best.reserve(add(1, mul(ranks.size(), cache_width)));
    for (const auto* e : ranks) best += *e->cache;
    if (profile == Profile::plain) return best;
    std::vector<Size> missed;
    for (Size i = 0; i < ranks.size(); ++i) if (*ranks[i]->cache != digest(ranks[i]->key)) missed.push_back(i);
    if (missed.empty()) {
        consider(best, Bytes(1, '\1'));
        return best;
    }
    Bytes map(ceil_bytes(ranks.size()), '\0');
    Bytes sparse(1, '\3');
    put_var(sparse, missed.size());
    Size next = 0;
    for (Size i : missed) { set_flag(map, i); put_var(sparse, i - next); next = i + 1; }
    Bytes bitmap(1, '\2');
    bitmap += map;
    const Size extra = mul(missed.size(), cache_width);
    // A tie goes to the earliest representation: raw, bitmap, then sparse.
    if (add(bitmap.size(), extra) <= add(sparse.size(), extra)) {
        if (add(bitmap.size(), extra) >= best.size()) return best;
        for (Size i : missed) bitmap += *ranks[i]->cache;
        return bitmap;
    }
    if (add(sparse.size(), extra) >= best.size()) return best;
    for (Size i : missed) sparse += *ranks[i]->cache;
    return sparse;
}

void read_cache(View data, std::vector<Entry>& rows, Budget& budget) {
    Reader in(data);
    const unsigned mode = in.byte();
    const Size n = rows.size();
    budget.spend(mul(n, cache_width));
    if (mode == 0) {
        for (auto& r : rows) r.cache.emplace(in.take(cache_width));
    } else if (mode == 1) {
        for (auto& r : rows) r.cache = digest(r.key);
    } else if (mode == 2) {
        const auto bitmap = in.take(ceil_bytes(n));
        if (n % 8 && (octet(bitmap.back()) >> (n % 8))) fail("invalid exception bitmap padding");
        for (Size i = 0; i < n; ++i) {
            if (flag(bitmap, i)) rows[i].cache.emplace(in.take(cache_width));
            else rows[i].cache = digest(rows[i].key);
        }
    } else if (mode == 3) {
        const Size count = in.size();
        if (count > n) fail("too many cache exceptions");
        std::vector<Size> exceptions;
        exceptions.reserve(count);
        Size next = 0;
        for (Size j = 0; j < count; ++j) {
            const Size i = add(next, in.size());
            if (i >= n) fail("invalid exception position");
            exceptions.push_back(i);
            next = i + 1;
        }
        Size j = 0;
        for (Size i = 0; i < n; ++i) {
            if (j < exceptions.size() && exceptions[j] == i) {
                rows[i].cache.emplace(in.take(cache_width));
                ++j;
            } else rows[i].cache = digest(rows[i].key);
        }
    } else fail("unknown cache mode");
    in.end();
}

}  // namespace

Bytes pack(const Map& map, Profile profile) {
    std::vector<const Entry*> ranks;
    ranks.reserve(map.entries.size());
    for (const auto& e : map.entries) {
        if (e.cache.has_value() != map.has_cache || (e.cache && e.cache->size() != cache_width))
            fail("inconsistent cache column; one 32-byte cache value required per cached row");
        ranks.push_back(&e);
    }
    std::sort(ranks.begin(), ranks.end(), [](const auto* a, const auto* b) { return key_less(a->key, b->key); });
    std::vector<View> keys, values;
    keys.reserve(ranks.size());
    values.reserve(ranks.size());
    for (const auto* e : ranks) {
        if (!keys.empty() && keys.back() == e->key) fail("duplicate key");
        keys.push_back(e->key);
        values.push_back(e->value);
    }
    Bytes archive(magic);
    put_byte(archive, map.has_cache ? 1 : 0);
    put_var(archive, ranks.size());
    put_frame(archive, key_lane(keys, profile));
    put_frame(archive, field_lane(values, profile));
    if (map.has_cache) put_frame(archive, cache_lane(ranks, profile));
    return archive;
}

Map unpack(View archive, DecodeLimits limits) {
    Reader in(archive);
    if (in.take(4) != magic) fail("not an RSM1 archive");
    const unsigned flags = in.byte();
    const Size n = in.size();
    if (flags > 1 || n > limits.max_entries) fail("unsupported header or entry limit exceeded");
    Budget budget{limits.max_decoded_bytes};
    auto keys = read_keys(in.frame(), n, budget);
    Reader value_frame(in.frame());
    auto values = read_lane(value_frame, n, budget);
    Map map{flags == 1, {}};
    map.entries.reserve(n);
    for (Size i = 0; i < n; ++i) map.entries.push_back({std::move(keys[i]), std::move(values[i]), std::nullopt});
    if (map.has_cache) read_cache(in.frame(), map.entries, budget);
    in.end();
    return map;
}

}  // namespace rsm
