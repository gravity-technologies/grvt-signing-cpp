// Hex parsing shared by signing and its tests.
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace grvt::detail {

inline std::optional<std::uint8_t> nibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
  return std::nullopt;
}

inline std::string_view strip_0x(std::string_view s) {
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
  return s;
}

// Even-length hex, with or without 0x.
inline std::optional<std::vector<std::uint8_t>> parse_hex(std::string_view s) {
  s = strip_0x(s);
  if (s.size() % 2 != 0) return std::nullopt;
  std::vector<std::uint8_t> out(s.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    auto hi = nibble(s[2 * i]), lo = nibble(s[2 * i + 1]);
    if (!hi || !lo) return std::nullopt;
    out[i] = static_cast<std::uint8_t>(*hi << 4 | *lo);
  }
  return out;
}

}  // namespace grvt::detail
