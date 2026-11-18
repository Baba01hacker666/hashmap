#include "rsm.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <openssl/sha.h>
#include <random>
#include <stdexcept>

namespace {
using rsm::Bytes;
using rsm::Map;
using rsm::Profile;
constexpr std::array profiles{Profile::plain, Profile::structural, Profile::byte_huff, Profile::greedy, Profile::rsm};

void require(bool good, const char* message) {
    if (!good) throw std::runtime_error(message);
}

template <typename Callback> void rejects(Callback&& f) {
    try { f(); } catch (const std::runtime_error&) { return; }
    throw std::runtime_error("invalid input was accepted");
}

Bytes sha(const Bytes& key) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    require(SHA256(reinterpret_cast<const unsigned char*>(key.data()), key.size(), digest.data()) != nullptr, "SHA256 failed");
    return Bytes(reinterpret_cast<const char*>(digest.data()), digest.size());
}

Map sorted(Map m) {
    const auto less = [](char a, char b) { return static_cast<unsigned char>(a) < static_cast<unsigned char>(b); };
    std::sort(m.entries.begin(), m.entries.end(), [&](const rsm::Entry& a, const rsm::Entry& b) {
        return std::lexicographical_compare(a.key.begin(), a.key.end(), b.key.begin(), b.key.end(), less);
    });
    return m;
}

void check_profiles(const Map& m) {
    const auto expected = sorted(m);
    const auto plain_size = rsm::pack(m, Profile::plain).size();
    for (auto profile : profiles) {
        const auto a = rsm::pack(m, profile);
        require(rsm::unpack(a) == expected, "round-trip changed the map");
        require(a.size() <= plain_size, "raw fallback exceeded the plain size");
        require(rsm::pack(expected, profile) == a, "archive depended on insertion order");
    }
}

std::size_t var(std::string_view bytes, std::size_t& i) {
    std::size_t out = 0;
    unsigned shift = 0;
    for (;;) {
        const auto n = static_cast<unsigned char>(bytes.at(i++));
        out |= static_cast<std::size_t>(n & 127) << shift;
        if (n < 128) return out;
        shift += 7;
    }
}

int cache_tag(std::string_view archive) {
    std::size_t i = 5;
    (void)var(archive, i);
    for (int lane = 0; lane < 2; ++lane) {
        const auto size = var(archive, i);
        i += size;
    }
    (void)var(archive, i);
    return archive.at(i);
}

void cache_modes() {
    // One test for each mode: regenerate, sparse, bitmap, and verbatim fallback.
    for (const int tag : {1, 3, 2, 0}) {
        Map m{true, {}};
        for (unsigned i = 0; i < 256; ++i) {
            const Bytes k(1, static_cast<char>(i));
            auto digest = sha(k);
            if (tag == 0 || (tag == 3 && i == 1) || (tag == 2 && i % 2 == 0)) digest[0] ^= 1;
            m.entries.push_back({k, std::to_string(i), digest});
        }
        const auto archive = rsm::pack(m);
        require(cache_tag(archive) == tag, "wrong cache branch");
        check_profiles(m);
    }
}

Bytes random_bytes(std::mt19937_64& rng, std::size_t n) {
    Bytes result(n, '\0');
    for (auto& c : result) c = static_cast<char>(rng() & 255);
    return result;
}

void varied_roundtrips() {
    std::mt19937_64 rng(9'047);
    for (unsigned run = 0; run < 96; ++run) {
        Map m{run % 3 == 0, {}};
        const auto n = static_cast<unsigned>(rng() % 73);
        for (unsigned i = 0; i < n; ++i) {
            auto key = (run % 2 == 0 ? random_bytes(rng, rng() % 69) : "/foo/007?version=0&sort=lex#")
                + static_cast<char>(i);
            auto value = run % 2 == 0 ? random_bytes(rng, rng() % 47) : "a~4!b==02/cat#?" + std::to_string(i);
            std::optional<Bytes> cache;
            if (m.has_cache) cache = (i % 7 == 0 ? random_bytes(rng, 32) : sha(key));
            m.entries.push_back({std::move(key), std::move(value), std::move(cache)});
        }
        std::shuffle(m.entries.begin(), m.entries.end(), rng);
        check_profiles(m);
    }
    // Fixed-width keys from tiny to wide: leading zeros and big-endian high limbs.
    for (const std::size_t w : {1, 8, 16, 32, 64, 65}) {
        Map m;
        for (unsigned i = 0; i < 256; ++i) {
            auto key = random_bytes(rng, w);
            key.back() = static_cast<char>(i);
            m.entries.push_back({std::move(key), random_bytes(rng, 24), std::nullopt});
        }
        check_profiles(m);
    }
}

void bad_inputs() {
    Map m;
    Bytes all;
    for (unsigned i = 0; i < 256; ++i) all.push_back(static_cast<char>(i));
    m.entries = {{"", "", std::nullopt}, {"1", all, std::nullopt},
                 {"0001", std::string("\x00\xff", 2), std::nullopt}, {"\xc3\xa9", "?", std::nullopt}};
    const auto a = rsm::pack(m);
    for (std::size_t i = 0; i < a.size(); ++i) rejects([&] { (void)rsm::unpack(std::string_view(a).substr(0, i)); });
    rejects([&] { (void)rsm::unpack(a + '\0'); });
    rejects([&] { (void)rsm::unpack(a, {.max_entries = 3}); });
    rejects([&] { (void)rsm::unpack(a, {.max_decoded_bytes = 265}); });
    require(rsm::unpack(a, {.max_entries = 4, .max_decoded_bytes = 266}) == sorted(m), "wrong decoded byte budget");
    check_profiles(m);
    m.entries.push_back(m.entries.front());
    rejects([&] { (void)rsm::pack(m); });
    m.entries.pop_back();
    m.has_cache = true;
    rejects([&] { (void)rsm::pack(m); });
    for (auto& r : m.entries) r.cache = "wrong width";
    rejects([&] { (void)rsm::pack(m); });
}
}  // namespace

int main() {
    try {
        check_profiles(Map{});
        check_profiles(Map{true, {}});
        cache_modes();
        varied_roundtrips();
        bad_inputs();
        std::cout << "C++ tests passed (empty maps, 4 cache modes, 96 seeded maps, 6 fixed-width key cases, limits and truncations).\n";
    } catch (const std::exception& e) {
        std::cerr << "C++ test failed: " << e.what() << '\n';
        return 1;
    }
}
