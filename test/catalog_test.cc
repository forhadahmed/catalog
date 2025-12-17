// catalog_test.cc - Comprehensive unit tests for catalog
// Tests TokenMap, encoding, decoding, and adversarial cases

#include "test_helper.h"
#include "../src/catalog.h"
#include "../src/token.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <random>
#include <set>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace catalog;

//=============================================================================
// Helper functions
//=============================================================================

static std::string temp_file(const std::string& suffix = "") {
    return "/tmp/catalog_test_" + std::to_string(getpid()) + "_" + suffix;
}

static void write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    f.write(content.data(), content.size());
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

static void remove_file(const std::string& path) {
    unlink(path.c_str());
}

// Normalize whitespace for comparison (multiple spaces -> single space)
static std::string normalize_whitespace(const std::string& s) {
    std::string result;
    bool in_space = false;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == ' ' || c == '\t') {
            if (!in_space && !result.empty() && result.back() != '\n') {
                result += ' ';
            }
            in_space = true;
        } else if (c == '\r') {
            // Skip CR, will be handled with LF
        } else if (c == '\n') {
            // Trim trailing space before newline
            if (!result.empty() && result.back() == ' ') {
                result.pop_back();
            }
            result += '\n';
            in_space = false;
        } else {
            in_space = false;
            result += c;
        }
    }
    // Trim trailing space
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result;
}

//=============================================================================
// TokenMap Unit Tests
//=============================================================================

TEST(tokenmap_basic_insert) {
    TokenMap map(16);
    std::atomic<uint32_t> next_id{0};

    const char* token1 = "hello";
    const char* token2 = "world";

    uint32_t id1 = map.get_or_insert(token1, strlen(token1), next_id);
    uint32_t id2 = map.get_or_insert(token2, strlen(token2), next_id);

    ASSERT_EQ(id1, 0u);
    ASSERT_EQ(id2, 1u);
    ASSERT_EQ(next_id.load(), 2u);
}

TEST(tokenmap_duplicate_detection) {
    TokenMap map(16);
    std::atomic<uint32_t> next_id{0};

    const char* token = "duplicate";

    uint32_t id1 = map.get_or_insert(token, strlen(token), next_id);
    uint32_t id2 = map.get_or_insert(token, strlen(token), next_id);
    uint32_t id3 = map.get_or_insert(token, strlen(token), next_id);

    ASSERT_EQ(id1, id2);
    ASSERT_EQ(id2, id3);
    ASSERT_EQ(next_id.load(), 1u);  // Only one unique token
}

TEST(tokenmap_different_pointers_same_content) {
    TokenMap map(16);
    std::atomic<uint32_t> next_id{0};

    std::string s1 = "same_content";
    std::string s2 = "same_content";  // Different allocation, same content

    uint32_t id1 = map.get_or_insert(s1.data(), s1.size(), next_id);
    uint32_t id2 = map.get_or_insert(s2.data(), s2.size(), next_id);

    ASSERT_EQ(id1, id2);
    ASSERT_EQ(next_id.load(), 1u);
}

TEST(tokenmap_empty_string) {
    TokenMap map(16);
    std::atomic<uint32_t> next_id{0};

    const char* empty = "";
    uint32_t id = map.get_or_insert(empty, 0, next_id);

    ASSERT_EQ(id, 0u);
    ASSERT_EQ(next_id.load(), 1u);

    // Duplicate empty string
    uint32_t id2 = map.get_or_insert(empty, 0, next_id);
    ASSERT_EQ(id, id2);
}

TEST(tokenmap_single_char_tokens) {
    TokenMap map(256);
    std::atomic<uint32_t> next_id{0};

    // Insert all printable ASCII characters
    std::string chars;
    for (char c = 32; c < 127; ++c) chars += c;

    std::set<uint32_t> ids;
    for (char c : chars) {
        uint32_t id = map.get_or_insert(&c, 1, next_id);
        ids.insert(id);
    }

    ASSERT_EQ(ids.size(), chars.size());
    ASSERT_EQ(next_id.load(), static_cast<uint32_t>(chars.size()));
}

TEST(tokenmap_very_long_token) {
    TokenMap map(16);
    std::atomic<uint32_t> next_id{0};

    // 10KB token
    std::string long_token(10000, 'x');
    for (size_t i = 0; i < long_token.size(); ++i) {
        long_token[i] = 'a' + (i % 26);
    }

    uint32_t id1 = map.get_or_insert(long_token.data(), long_token.size(), next_id);
    uint32_t id2 = map.get_or_insert(long_token.data(), long_token.size(), next_id);

    ASSERT_EQ(id1, id2);
    ASSERT_EQ(next_id.load(), 1u);
}

TEST(tokenmap_max_token_length) {
    TokenMap map(16);
    std::atomic<uint32_t> next_id{0};

    // 65535 bytes (max uint16_t length)
    std::string max_token(65535, 'M');

    uint32_t id = map.get_or_insert(max_token.data(), max_token.size(), next_id);
    ASSERT_EQ(id, 0u);
}

TEST(tokenmap_hash_collision_handling) {
    // Use a small capacity to force collisions
    TokenMap map(8);
    std::atomic<uint32_t> next_id{0};

    // Insert many tokens - will have collisions in 8-slot table
    std::vector<std::string> tokens;
    for (int i = 0; i < 4; ++i) {  // 50% load factor
        tokens.push_back("token_" + std::to_string(i));
    }

    std::set<uint32_t> ids;
    for (const auto& tok : tokens) {
        uint32_t id = map.get_or_insert(tok.data(), tok.size(), next_id);
        ids.insert(id);
    }

    ASSERT_EQ(ids.size(), tokens.size());

    // Verify all can be retrieved
    for (const auto& tok : tokens) {
        uint32_t id = map.get_or_insert(tok.data(), tok.size(), next_id);
        ASSERT_TRUE(ids.count(id) > 0);
    }
}

TEST(tokenmap_high_load_factor) {
    // Test with 60% load factor (TokenMap limits probes to 70% of capacity)
    size_t capacity = 1024;
    size_t num_tokens = capacity * 6 / 10;

    TokenMap map(capacity);
    std::atomic<uint32_t> next_id{0};

    std::vector<std::string> tokens;
    for (size_t i = 0; i < num_tokens; ++i) {
        tokens.push_back("token_number_" + std::to_string(i));
    }

    for (const auto& tok : tokens) {
        uint32_t id = map.get_or_insert(tok.data(), tok.size(), next_id);
        ASSERT_NE(id, UINT32_MAX);
    }

    ASSERT_EQ(next_id.load(), static_cast<uint32_t>(num_tokens));
}

TEST(tokenmap_get_ordered_tokens) {
    TokenMap map(64);
    std::atomic<uint32_t> next_id{0};

    std::vector<std::string> tokens = {"alpha", "beta", "gamma", "delta"};
    std::vector<uint32_t> ids;

    for (const auto& tok : tokens) {
        ids.push_back(map.get_or_insert(tok.data(), tok.size(), next_id));
    }

    const std::string_view* retrieved = map.get_ordered_tokens();
    uint32_t count = next_id.load();

    ASSERT_EQ(count, tokens.size());
    for (size_t i = 0; i < tokens.size(); ++i) {
        ASSERT_EQ(retrieved[ids[i]], tokens[i]);
    }
}

TEST(tokenmap_concurrent_insert_same_token) {
    TokenMap map(1024);
    std::atomic<uint32_t> next_id{0};
    std::atomic<int> ready{0};

    const char* shared_token = "concurrent_token";
    size_t len = strlen(shared_token);

    std::vector<uint32_t> results(8);
    std::vector<std::thread> threads;

    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&, i]() {
            ready.fetch_add(1);
            while (ready.load() < 8) _mm_pause();  // Sync start
            results[i] = map.get_or_insert(shared_token, len, next_id);
        });
    }

    for (auto& t : threads) t.join();

    // All threads should get the same ID
    for (int i = 1; i < 8; ++i) {
        ASSERT_EQ(results[0], results[i]);
    }
    ASSERT_EQ(next_id.load(), 1u);
}

TEST(tokenmap_concurrent_insert_different_tokens) {
    TokenMap map(1024);
    std::atomic<uint32_t> next_id{0};
    std::atomic<int> ready{0};

    std::vector<std::string> token_data(8);
    for (int i = 0; i < 8; ++i) {
        token_data[i] = "unique_token_" + std::to_string(i);
    }

    std::vector<uint32_t> results(8);
    std::vector<std::thread> threads;

    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&, i]() {
            ready.fetch_add(1);
            while (ready.load() < 8) _mm_pause();
            results[i] = map.get_or_insert(token_data[i].data(), token_data[i].size(), next_id);
        });
    }

    for (auto& t : threads) t.join();

    // All IDs should be unique
    std::set<uint32_t> id_set(results.begin(), results.end());
    ASSERT_EQ(id_set.size(), 8u);
    ASSERT_EQ(next_id.load(), 8u);
}

TEST(tokenmap_concurrent_stress) {
    TokenMap map(65536);
    std::atomic<uint32_t> next_id{0};

    const int num_threads = 8;
    const int tokens_per_thread = 1000;

    std::vector<std::vector<std::string>> thread_tokens(num_threads);
    for (int t = 0; t < num_threads; ++t) {
        for (int i = 0; i < tokens_per_thread; ++i) {
            thread_tokens[t].push_back("t" + std::to_string(t) + "_tok" + std::to_string(i));
        }
    }

    std::vector<std::thread> threads;
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (const auto& tok : thread_tokens[t]) {
                uint32_t id = map.get_or_insert(tok.data(), tok.size(), next_id);
                ASSERT_NE(id, UINT32_MAX);
            }
        });
    }

    for (auto& th : threads) th.join();

    ASSERT_EQ(next_id.load(), static_cast<uint32_t>(num_threads * tokens_per_thread));
}

TEST(tokenmap_binary_content) {
    TokenMap map(64);
    std::atomic<uint32_t> next_id{0};

    // Token with null bytes - use explicit construction
    char data1[] = {'h', 'e', 'l', 'l', 'o', '\0', 'w', 'o', 'r', 'l', 'd'};
    std::string binary_token(data1, sizeof(data1));

    uint32_t id1 = map.get_or_insert(binary_token.data(), binary_token.size(), next_id);
    uint32_t id2 = map.get_or_insert(binary_token.data(), binary_token.size(), next_id);

    ASSERT_EQ(id1, id2);

    // Different binary content after the null
    char data2[] = {'h', 'e', 'l', 'l', 'o', '\0', 'e', 'a', 'r', 't', 'h'};
    std::string binary_token2(data2, sizeof(data2));

    uint32_t id3 = map.get_or_insert(binary_token2.data(), binary_token2.size(), next_id);
    ASSERT_NE(id1, id3);
}

TEST(tokenmap_prefix_suffix_tokens) {
    TokenMap map(64);
    std::atomic<uint32_t> next_id{0};

    // Tokens that are prefixes/suffixes of each other
    std::vector<std::string> tokens = {"a", "ab", "abc", "abcd", "abcde"};
    std::set<uint32_t> ids;

    for (const auto& tok : tokens) {
        uint32_t id = map.get_or_insert(tok.data(), tok.size(), next_id);
        ids.insert(id);
    }

    ASSERT_EQ(ids.size(), tokens.size());
}

//=============================================================================
// Hash Function Tests
//=============================================================================

TEST(hash_deterministic) {
    const char* data = "test_string";
    size_t len = strlen(data);

    uint64_t h1 = fnv1a_hash(data, len);
    uint64_t h2 = fnv1a_hash(data, len);

    ASSERT_EQ(h1, h2);
}

TEST(hash_different_for_different_strings) {
    const char* s1 = "string1";
    const char* s2 = "string2";

    uint64_t h1 = fnv1a_hash(s1, strlen(s1));
    uint64_t h2 = fnv1a_hash(s2, strlen(s2));

    ASSERT_NE(h1, h2);
}

TEST(hash_length_sensitive) {
    const char* s = "abcdefgh";

    uint64_t h4 = fnv1a_hash(s, 4);
    uint64_t h8 = fnv1a_hash(s, 8);

    ASSERT_NE(h4, h8);
}

TEST(hash_nonzero_for_empty) {
    uint64_t h = fnv1a_hash("", 0);
    // FNV-1a basis is non-zero, so empty string hash should be non-zero
    ASSERT_NE(h, 0u);
}

//=============================================================================
// File Format Tests (using binary files directly)
//=============================================================================

TEST(header_size) {
    ASSERT_EQ(sizeof(CatalogHeader), 48u);
}

TEST(header_magic) {
    ASSERT_EQ(MAGIC, 0x474C5443u);

    // Verify it spells "CTLG" in little-endian
    char* magic_bytes = reinterpret_cast<char*>(const_cast<uint32_t*>(&MAGIC));
    ASSERT_EQ(magic_bytes[0], 'C');
    ASSERT_EQ(magic_bytes[1], 'T');
    ASSERT_EQ(magic_bytes[2], 'L');
    ASSERT_EQ(magic_bytes[3], 'G');
}

//=============================================================================
// Whitespace Normalization Tests
//=============================================================================

TEST(normalize_single_spaces) {
    std::string input = "hello world foo";
    std::string expected = "hello world foo";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

TEST(normalize_multiple_spaces) {
    std::string input = "hello    world";
    std::string expected = "hello world";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

TEST(normalize_tabs) {
    std::string input = "hello\t\tworld";
    std::string expected = "hello world";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

TEST(normalize_mixed_whitespace) {
    std::string input = "hello \t  \t world";
    std::string expected = "hello world";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

TEST(normalize_leading_whitespace) {
    std::string input = "   hello world";
    std::string expected = "hello world";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

TEST(normalize_trailing_whitespace) {
    std::string input = "hello world   ";
    std::string expected = "hello world";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

TEST(normalize_crlf) {
    std::string input = "line1\r\nline2\r\n";
    std::string expected = "line1\nline2\n";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

TEST(normalize_whitespace_before_newline) {
    std::string input = "hello   \nworld";
    std::string expected = "hello\nworld";
    ASSERT_EQ(normalize_whitespace(input), expected);
}

//=============================================================================
// Edge Case File Content Generation
//=============================================================================

std::string generate_test_content_empty() {
    return "";
}

std::string generate_test_content_single_token() {
    return "hello\n";
}

std::string generate_test_content_single_line_multiple_tokens() {
    return "hello world foo bar baz\n";
}

std::string generate_test_content_multiple_lines() {
    return "line one\nline two\nline three\n";
}

std::string generate_test_content_empty_lines() {
    return "line one\n\nline three\n\n\nline six\n";
}

std::string generate_test_content_whitespace_only_lines() {
    return "   \n\t\t\t\n  \t  \n";
}

std::string generate_test_content_leading_trailing_whitespace() {
    return "  hello world  \n\tgoodbye  \n";
}

std::string generate_test_content_mixed_whitespace() {
    return "hello  \t\t  world\t\t  foo   bar\n";
}

std::string generate_test_content_crlf() {
    return "line1\r\nline2\r\nline3\r\n";
}

std::string generate_test_content_mixed_line_endings() {
    return "unix\nwindows\r\nold_mac\runix2\n";
}

std::string generate_test_content_no_trailing_newline() {
    return "line1\nline2\nlast_line";
}

std::string generate_test_content_very_long_line() {
    std::string line;
    for (int i = 0; i < 10000; ++i) {
        line += "token" + std::to_string(i) + " ";
    }
    line += "\n";
    return line;
}

std::string generate_test_content_very_long_token() {
    std::string token(60000, 'x');
    for (size_t i = 0; i < token.size(); ++i) {
        token[i] = 'a' + (i % 26);
    }
    return token + "\n";
}

std::string generate_test_content_all_same_tokens() {
    std::string content;
    for (int line = 0; line < 100; ++line) {
        for (int tok = 0; tok < 50; ++tok) {
            content += "same ";
        }
        content += "\n";
    }
    return content;
}

std::string generate_test_content_all_unique_tokens() {
    std::string content;
    for (int line = 0; line < 100; ++line) {
        for (int tok = 0; tok < 10; ++tok) {
            content += "token_" + std::to_string(line) + "_" + std::to_string(tok) + " ";
        }
        content += "\n";
    }
    return content;
}

std::string generate_test_content_numeric_tokens() {
    std::string content;
    for (int i = 0; i < 100; ++i) {
        content += std::to_string(i) + " " + std::to_string(i * i) + " " + std::to_string(i * 100) + "\n";
    }
    return content;
}

std::string generate_test_content_special_chars() {
    return "hello@world foo.bar baz#qux a=b c:d e/f\n"
           "!@#$%^&*() []{}|\\;':\",./<>?\n";
}

std::string generate_test_content_unicode() {
    return "hello world\n"
           "cafe\n"
           "naive\n"
           "resume\n";
}

std::string generate_test_content_repeated_patterns() {
    std::string content;
    for (int i = 0; i < 1000; ++i) {
        content += "ERROR: failed to connect to server at port 8080\n";
    }
    return content;
}

std::string generate_test_content_log_like() {
    std::string content;
    std::vector<std::string> levels = {"INFO", "DEBUG", "WARN", "ERROR"};
    std::vector<std::string> messages = {
        "Processing request",
        "Connection established",
        "Timeout occurred",
        "Failed to authenticate"
    };

    for (int i = 0; i < 1000; ++i) {
        content += "2024-12-16 10:";
        content += std::to_string(i / 60) + ":";
        content += std::to_string(i % 60) + " ";
        content += levels[i % levels.size()] + " ";
        content += messages[i % messages.size()] + " ";
        content += "id=" + std::to_string(i) + "\n";
    }
    return content;
}

//=============================================================================
// Test Registrations (will be collected by TEST macro infrastructure)
//=============================================================================

// Helper struct to track test functions
struct TestRegistry {
    static std::vector<std::pair<std::string, std::function<void()>>>& tests() {
        static std::vector<std::pair<std::string, std::function<void()>>> t;
        return t;
    }
};

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[]) {
    std::cout << "=== Catalog Unit Tests ===\n\n";

    // Tests are auto-registered by TEST macro and run during static initialization
    // This main() just prints the summary

    return test::print_summary();
}
