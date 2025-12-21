// test_helper.h - Minimal test framework (no external dependencies)
// Common assert/pass/fail functions for all unit tests

#ifndef TEST_HELPER_H
#define TEST_HELPER_H

#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

//=============================================================================
// ANSI Color Codes
//=============================================================================

#define TEST_GREEN "\033[0;32m"
#define TEST_RED   "\033[0;31m"
#define TEST_NC    "\033[0m"

//=============================================================================
// Test State (global)
//=============================================================================

namespace test {

inline int& tests_run() { static int n = 0; return n; }
inline int& tests_passed() { static int n = 0; return n; }
inline int& tests_failed() { static int n = 0; return n; }
inline std::vector<std::string>& failed_tests() { static std::vector<std::string> v; return v; }
inline std::string& last_error() { static std::string s; return s; }

//=============================================================================
// Test Runner
//=============================================================================

inline void run_test(const char* name, std::function<void()> fn) {
    ++tests_run();
    last_error().clear();
    try {
        fn();
        ++tests_passed();
        std::cout << TEST_GREEN "[PASS]" TEST_NC " " << name << "\n";
    } catch (const std::exception& e) {
        ++tests_failed();
        failed_tests().push_back(name);
        std::cout << TEST_RED "[FAIL]" TEST_NC " " << name;
        if (!last_error().empty()) {
            std::cout << " (" << last_error() << ")";
        }
        std::cout << "\n";
    } catch (...) {
        ++tests_failed();
        failed_tests().push_back(name);
        std::cout << TEST_RED "[FAIL]" TEST_NC " " << name << " (unknown exception)\n";
    }
}

//=============================================================================
// Test Summary
//=============================================================================

inline int print_summary() {
    std::cout << "\nTest Summary:\n";
    std::cout << "-------------\n";
    std::cout << "Total:  " << tests_run() << "\n";
    std::cout << "Passed: " << tests_passed() << "\n";
    std::cout << "Failed: " << tests_failed() << "\n";

    if (!failed_tests().empty()) {
        std::cout << "\nFailed tests:\n";
        for (const auto& name : failed_tests()) {
            std::cout << "  - " << name << "\n";
        }
    }

    return tests_failed() > 0 ? 1 : 0;
}

} // namespace test

//=============================================================================
// TEST Macro
//=============================================================================

#define TEST(name) \
    void test_##name(); \
    struct TestRunner_##name { \
        TestRunner_##name() { test::run_test(#name, test_##name); } \
    } test_runner_instance_##name; \
    void test_##name()

//=============================================================================
// Assert Macros
//=============================================================================

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        test::last_error() = std::string("ASSERT_TRUE: ") + #cond; \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

#define ASSERT_FALSE(cond) do { \
    if (cond) { \
        test::last_error() = std::string("ASSERT_FALSE: ") + #cond; \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

// Helper to convert values to printable form (handles enums)
namespace test {
template<typename T>
auto to_printable(T val) -> typename std::enable_if<std::is_enum<T>::value, typename std::underlying_type<T>::type>::type {
    return static_cast<typename std::underlying_type<T>::type>(val);
}
template<typename T>
auto to_printable(T val) -> typename std::enable_if<!std::is_enum<T>::value, T>::type {
    return val;
}
} // namespace test

#define ASSERT_EQ(a, b) do { \
    auto va = (a); auto vb = (b); \
    if (va != vb) { \
        std::ostringstream ss; \
        ss << #a << " (" << test::to_printable(va) << ") != " << #b << " (" << test::to_printable(vb) << ")"; \
        test::last_error() = ss.str(); \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

#define ASSERT_NE(a, b) do { \
    auto va = (a); auto vb = (b); \
    if (va == vb) { \
        std::ostringstream ss; \
        ss << #a << " == " << #b << " (" << test::to_printable(va) << ")"; \
        test::last_error() = ss.str(); \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

#define ASSERT_LT(a, b) do { \
    auto va = (a); auto vb = (b); \
    if (!(va < vb)) { \
        std::ostringstream ss; \
        ss << #a << " (" << test::to_printable(va) << ") >= " << #b << " (" << test::to_printable(vb) << ")"; \
        test::last_error() = ss.str(); \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

#define ASSERT_LE(a, b) do { \
    auto va = (a); auto vb = (b); \
    if (!(va <= vb)) { \
        std::ostringstream ss; \
        ss << #a << " (" << test::to_printable(va) << ") > " << #b << " (" << test::to_printable(vb) << ")"; \
        test::last_error() = ss.str(); \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

#define ASSERT_GT(a, b) do { \
    auto va = (a); auto vb = (b); \
    if (!(va > vb)) { \
        std::ostringstream ss; \
        ss << #a << " (" << test::to_printable(va) << ") <= " << #b << " (" << test::to_printable(vb) << ")"; \
        test::last_error() = ss.str(); \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

#define ASSERT_GE(a, b) do { \
    auto va = (a); auto vb = (b); \
    if (!(va >= vb)) { \
        std::ostringstream ss; \
        ss << #a << " (" << test::to_printable(va) << ") < " << #b << " (" << test::to_printable(vb) << ")"; \
        test::last_error() = ss.str(); \
        throw std::runtime_error(test::last_error()); \
    } \
} while(0)

#endif // TEST_HELPER_H
