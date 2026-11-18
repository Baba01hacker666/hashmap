#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rsm {

// std::string owns arbitrary bytes, including embedded NULs and non-UTF-8.
using Bytes = std::string;

struct Entry {
    Bytes key;
    Bytes value;
    std::optional<Bytes> cache;
    bool operator==(const Entry&) const = default;
};

struct Map {
    bool has_cache = false;
    std::vector<Entry> entries;
    bool operator==(const Map&) const = default;
};

// Profiles are for comparisons; they all write the same RSM1 wire format.
enum class Profile { plain, structural, byte_huff, greedy, rsm };

struct DecodeLimits {
    std::size_t max_entries = 1'000'000;
    std::size_t max_decoded_bytes = 1UL << 30;
};

// Accepts unique keys in any order. When has_cache is set, each entry must
// have a 32-byte cache value; otherwise all entries must have no cache value.
[[nodiscard]] Bytes pack(const Map&, Profile = Profile::rsm);

// Returns the logical map in ascending unsigned-byte key order.
// Format errors and exceeded limits throw std::runtime_error. The research
// codec has no integrity checksum; it is not a production untrusted parser.
[[nodiscard]] Map unpack(std::string_view archive, DecodeLimits = {});

}  // namespace rsm
