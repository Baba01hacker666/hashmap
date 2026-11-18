#include "rsm.hpp"

#include <charconv>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
using rsm::Bytes;
using View = std::string_view;
using Size = std::size_t;

[[noreturn]] void error(const char* msg) { throw std::runtime_error(msg); }

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
bool hex_space(char c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
Bytes unhex(View hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    for (Size i = 0; i < hex.size();) {
        if (hex_space(hex[i])) { ++i; continue; }
        const int a = hex_digit(hex[i++]);
        const int b = i == hex.size() ? -1 : hex_digit(hex[i++]);
        if (a < 0 || b < 0) error("map fields must be hex strings");
        out.push_back(static_cast<char>((a << 4) | b));
    }
    return out;
}
Bytes hex(View bytes) {
    static constexpr View digits = "0123456789abcdef";
    Bytes out;
    if (bytes.size() > out.max_size() / 2) error("hex output too large");
    out.reserve(bytes.size() * 2);
    for (char c : bytes) {
        const auto ch = static_cast<unsigned char>(c);
        out.push_back(digits[ch >> 4]);
        out.push_back(digits[ch & 15]);
    }
    return out;
}

// Deliberately small parser for the shared JSON interchange schema. JSON keys
// and field contents are ASCII (field bytes, including UTF-8, are hex encoded).
class MapJson {
public:
    explicit MapJson(View input) : input_(input) {}
    rsm::Map read() {
        expect('{');
        rsm::Map result;
        bool got_cache = false, got_entries = false;
        if (!take('}')) {
            do {
                const auto key = string();
                expect(':');
                if (key == "cache" && !got_cache) {
                    result.has_cache = boolean();
                    got_cache = true;
                } else if (key == "entries" && !got_entries) {
                    read_entries(result);
                    got_entries = true;
                } else error("unexpected or duplicate JSON field (expected cache and entries)");
            } while (take(','));
            expect('}');
        }
        skip();
        if (!got_cache || !got_entries || !input_.empty()) error("incomplete map JSON or trailing characters");
        return result;
    }
private:
    void skip() {
        while (!input_.empty() && View(" \t\r\n").find(input_.front()) != View::npos) input_.remove_prefix(1);
    }
    bool take(char c) {
        skip();
        if (input_.empty() || input_.front() != c) return false;
        input_.remove_prefix(1);
        return true;
    }
    void expect(char c) { if (!take(c)) error("invalid map JSON syntax"); }
    bool boolean() {
        skip();
        if (input_.starts_with("true")) { input_.remove_prefix(4); return true; }
        if (input_.starts_with("false")) { input_.remove_prefix(5); return false; }
        error("cache must be a JSON boolean");
    }
    char character() {
        if (input_.empty()) error("truncated map JSON string");
        const char c = input_.front();
        input_.remove_prefix(1);
        return c;
    }
    Bytes string() {
        expect('"');
        Bytes result;
        for (;;) {
            const char c = character();
            if (c == '"') return result;
            if (c != '\\') {
                const auto b = static_cast<unsigned char>(c);
                if (b < 0x20 || b >= 0x80) error("map JSON strings must contain ASCII or hex");
                result.push_back(c);
                continue;
            }
            switch (const char e = character()) {
                case '"': case '\\': case '/': result.push_back(e); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'u': {
                    unsigned value = 0;
                    for (int i = 0; i < 4; ++i) {
                        const int d = hex_digit(character());
                        if (d < 0) error("invalid JSON Unicode escape");
                        value = 16 * value + static_cast<unsigned>(d);
                    }
                    if (value >= 0x80) error("map JSON fields must contain ASCII or hex");
                    result.push_back(static_cast<char>(value));
                    break;
                }
                default: error("invalid map JSON escape");
            }
        }
    }
    void read_entries(rsm::Map& map) {
        expect('[');
        if (take(']')) return;
        do {
            expect('[');
            auto key = unhex(string());
            expect(',');
            auto value = unhex(string());
            std::optional<Bytes> cache;
            if (take(',')) cache = unhex(string());
            expect(']');
            map.entries.push_back({std::move(key), std::move(value), std::move(cache)});
        } while (take(','));
        expect(']');
    }
    View input_;
};

Bytes read_file(const char* path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error(Bytes("cannot open input: ") + path);
    const auto end = in.tellg();
    if (end < 0 || static_cast<std::uintmax_t>(end) > Bytes().max_size()) error("invalid input file size");
    Bytes data(static_cast<Size>(end), '\0');
    in.seekg(0);
    if (!in.read(data.data(), static_cast<std::streamsize>(end))) error("cannot read input file");
    return data;
}

void write_archive(const char* path, View data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error(Bytes("cannot open output: ") + path);
    if (data.size() > static_cast<Size>(std::numeric_limits<std::streamsize>::max())) error("archive too large");
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out) error("cannot write archive");
}

void write_map(const char* path, const rsm::Map& map) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error(Bytes("cannot open output: ") + path);
    out << "{\n  \"cache\": " << (map.has_cache ? "true" : "false") << ",\n  \"entries\": [";
    for (Size i = 0; i < map.entries.size(); ++i) {
        const auto& row = map.entries[i];
        out << (i ? ",\n" : "\n") << "    [\n      \"" << hex(row.key) << "\",\n      \"" << hex(row.value) << '"';
        if (row.cache) out << ",\n      \"" << hex(*row.cache) << '"';
        out << "\n    ]";
    }
    out << (map.entries.empty() ? "]\n}\n" : "\n  ]\n}\n");
    out.close();
    if (!out) error("cannot write map JSON");
}

Size number(View s) {
    Size x = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), x);
    if (ec != std::errc{} || end != s.data() + s.size()) error("invalid numeric limit");
    return x;
}

rsm::Profile profile(View s) {
    if (s == "plain") return rsm::Profile::plain;
    if (s == "structural") return rsm::Profile::structural;
    if (s == "byte-huff") return rsm::Profile::byte_huff;
    if (s == "greedy") return rsm::Profile::greedy;
    if (s == "rsm") return rsm::Profile::rsm;
    error("unknown profile");
}

void usage() {
    std::cerr << "Usage:\n"
        "  rsm_cpp pack INPUT.json OUTPUT.rsm [--profile plain|structural|byte-huff|greedy|rsm]\n"
        "  rsm_cpp unpack INPUT.rsm OUTPUT.json [--max-entries N] [--max-bytes N]\n";
}
}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && View(argv[1]) == "--help") { usage(); return 0; }
    if (argc < 4 || argc % 2 != 0) { usage(); return 2; }
    try {
        const View mode = argv[1];
        if (mode == "pack") {
            auto p = rsm::Profile::rsm;
            for (int i = 4; i < argc; i += 2) {
                if (View(argv[i]) != "--profile") error("unknown pack option");
                p = profile(argv[i + 1]);
            }
            const auto input = read_file(argv[2]);
            write_archive(argv[3], rsm::pack(MapJson(input).read(), p));
        } else if (mode == "unpack") {
            rsm::DecodeLimits limits;
            for (int i = 4; i < argc; i += 2) {
                const View opt = argv[i];
                if (opt == "--max-entries") limits.max_entries = number(argv[i + 1]);
                else if (opt == "--max-bytes") limits.max_decoded_bytes = number(argv[i + 1]);
                else error("unknown unpack option");
            }
            write_map(argv[3], rsm::unpack(read_file(argv[2]), limits));
        } else {
            usage();
            return 2;
        }
    } catch (const std::exception& e) {
        std::cerr << "rsm_cpp: " << e.what() << '\n';
        return 2;
    }
    return 0;
}
