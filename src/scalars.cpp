#include "grvt/scalars.hpp"

#include <charconv>
#include <cstdlib>

#include "codec_support.hpp"

namespace grvt {

namespace {

// -?(0|[1-9][0-9]*)(\.[0-9]+)?
bool valid_decimal(std::string_view s) {
  std::size_t i = 0;
  if (i < s.size() && s[i] == '-') ++i;
  if (i >= s.size()) return false;
  if (s[i] == '0') {
    ++i;
  } else if (s[i] >= '1' && s[i] <= '9') {
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
  } else {
    return false;
  }
  if (i == s.size()) return true;
  if (s[i] != '.' || ++i == s.size()) return false;
  while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
  return i == s.size();
}

struct Parts {
  bool negative;
  std::string_view whole;  // no leading zeros ("" for zero)
  std::string_view frac;   // no trailing zeros
};

Parts parts(std::string_view s) {
  Parts p{false, s, {}};
  if (!s.empty() && s[0] == '-') {
    p.negative = true;
    s.remove_prefix(1);
  }
  const auto dot = s.find('.');
  p.whole = s.substr(0, dot);
  if (dot != std::string_view::npos) p.frac = s.substr(dot + 1);
  while (!p.whole.empty() && p.whole.front() == '0') p.whole.remove_prefix(1);
  while (!p.frac.empty() && p.frac.back() == '0') p.frac.remove_suffix(1);
  if (p.whole.empty() && p.frac.empty()) p.negative = false;
  return p;
}

int compare_magnitude(const Parts& a, const Parts& b) {
  if (a.whole.size() != b.whole.size()) return a.whole.size() < b.whole.size() ? -1 : 1;
  if (int c = a.whole.compare(b.whole); c != 0) return c < 0 ? -1 : 1;
  if (int c = a.frac.compare(b.frac); c != 0) return c < 0 ? -1 : 1;
  return 0;
}

}  // namespace

bool Decimal::valid(std::string_view text) noexcept { return valid_decimal(text); }

Result<Decimal> Decimal::parse(std::string_view text) {
  if (!valid_decimal(text)) {
    return Error::config("invalid decimal \"" + std::string(text) +
                         "\": want a finite base-10 string without an exponent");
  }
  return Decimal(std::string(text));
}

Decimal Decimal::from_int(std::int64_t value) { return Decimal(std::to_string(value)); }

double Decimal::to_double() const { return std::strtod(std::string(text()).c_str(), nullptr); }

int Decimal::sign() const noexcept {
  const Parts p = parts(text());
  if (p.whole.empty() && p.frac.empty()) return 0;
  return p.negative ? -1 : 1;
}

std::strong_ordering operator<=>(const Decimal& a, const Decimal& b) noexcept {
  const Parts pa = parts(a.text()), pb = parts(b.text());
  const int sa = a.sign(), sb = b.sign();
  if (sa != sb) return sa <=> sb;
  int c = compare_magnitude(pa, pb);
  if (sa < 0) c = -c;
  return c <=> 0;
}

namespace detail::codec {

bool parse_integer(std::string_view s, bool quoted, bool is_signed, std::uint64_t& magnitude, bool& negative) {
  if (quoted && s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    negative = false;
    const auto* end = s.data() + s.size();
    auto r = std::from_chars(s.data() + 2, end, magnitude, 16);
    return r.ec == std::errc() && r.ptr == end;
  }
  negative = !s.empty() && s[0] == '-';
  if (negative) {
    if (!is_signed) return false;
    s.remove_prefix(1);
  }
  if (s.empty() || s[0] < '0' || s[0] > '9') return false;
  const auto* end = s.data() + s.size();
  auto r = std::from_chars(s.data(), end, magnitude);
  return r.ec == std::errc() && r.ptr == end;
}

bool parse_integer(const json::Value& v, bool is_signed, std::uint64_t& magnitude, bool& negative) {
  if (!v.is_number() && !v.is_string()) return false;
  return parse_integer(v.text, v.is_string(), is_signed, magnitude, negative);
}

}  // namespace detail::codec

}  // namespace grvt
