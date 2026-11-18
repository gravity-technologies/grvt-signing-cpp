// A tiny test harness: TEST(name) { CHECK(...); CHECK_EQ(a, b); }. Each test file is its own CTest
// executable (main in test_main.cpp). No exceptions: a failed check records and continues.
#pragma once

#include <cstdio>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace test {

struct Case {
  const char* name;
  void (*fn)();
};

inline std::vector<Case>& cases() {
  static std::vector<Case> all;
  return all;
}

inline int& failures() {
  static int n = 0;
  return n;
}

struct Register {
  Register(const char* name, void (*fn)()) { cases().push_back({name, fn}); }
};

inline void fail(const char* file, int line, const std::string& what) {
  ++failures();
  std::fprintf(stderr, "%s:%d: FAILED: %s\n", file, line, what.c_str());
}

template <class T>
std::string show(const T& v) {
  if constexpr (requires(std::ostream& o) { o << v; }) {
    std::ostringstream o;
    o << v;
    return o.str();
  } else {
    return "(value)";
  }
}

inline std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

}  // namespace test

#define TEST_CAT2(a, b) a##b
#define TEST_CAT(a, b) TEST_CAT2(a, b)
#define TEST(name)                                                \
  static void name();                                             \
  static const test::Register TEST_CAT(reg_, name)(#name, &name); \
  static void name()

#define CHECK(cond)                                     \
  do {                                                  \
    if (!(cond)) test::fail(__FILE__, __LINE__, #cond); \
  } while (0)

#define CHECK_MSG(cond, msg)                                                          \
  do {                                                                                \
    if (!(cond)) test::fail(__FILE__, __LINE__, std::string(#cond) + " -- " + (msg)); \
  } while (0)

#define CHECK_EQ(a, b)                                                                                             \
  do {                                                                                                             \
    const auto va_ = (a);                                                                                          \
    const auto vb_ = (b);                                                                                          \
    if (!(va_ == vb_))                                                                                             \
      test::fail(__FILE__, __LINE__, std::string(#a " == " #b ": ") + test::show(va_) + " vs " + test::show(vb_)); \
  } while (0)

// Stops the current test when a Result is an error.
#define REQUIRE_OK(r)                                                                \
  do {                                                                               \
    if (!(r)) {                                                                      \
      test::fail(__FILE__, __LINE__, std::string(#r ": ") + (r).error().describe()); \
      return;                                                                        \
    }                                                                                \
  } while (0)
