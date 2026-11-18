// Value types the generated models use: exact decimals, nanosecond timestamps, enums that keep unknown
// wire values, and raw JSON for the contract's untyped fields.
#pragma once

#include <array>
#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "grvt/result.hpp"

namespace grvt {

namespace detail::codec {
template <class T>
struct Io;
}  // namespace detail::codec

// An exact decimal as the wire text ("65000.1"). No arithmetic library is exposed: compare, check the
// sign, or convert explicitly. Comparison is numeric ("10.0" == "10"); text() keeps the exact digits.
class Decimal {
 public:
  // Zero.
  Decimal() = default;

  // A finite base-10 string without an exponent: -?(0|[1-9][0-9]*)(\.[0-9]+)?
  static Result<Decimal> parse(std::string_view text);
  // Whether parse() accepts text.
  static bool valid(std::string_view text) noexcept;
  static Decimal from_int(std::int64_t value);

  // The exact text ("0" for a default-constructed value).
  std::string_view text() const noexcept { return text_.empty() ? std::string_view("0") : text_; }
  std::string to_string() const { return std::string(text()); }
  // Lossy: for display or statistics only, never for prices sent back to the exchange.
  double to_double() const;

  // -1, 0 or 1.
  int sign() const noexcept;
  bool is_zero() const noexcept { return sign() == 0; }

  friend std::strong_ordering operator<=>(const Decimal& a, const Decimal& b) noexcept;
  friend bool operator==(const Decimal& a, const Decimal& b) noexcept { return (a <=> b) == 0; }

 private:
  explicit Decimal(std::string text) : text_(std::move(text)) {}
  // The decoder writes the text in place, reusing its memory.
  template <class T>
  friend struct detail::codec::Io;
  std::string text_;
};

// Unix nanoseconds. On the wire a JSON string of a signed 64-bit integer ("1793172225200080949").
using Timestamp = std::chrono::sys_time<std::chrono::nanoseconds>;

constexpr Timestamp timestamp_from_ns(std::int64_t ns) noexcept { return Timestamp(std::chrono::nanoseconds(ns)); }
constexpr std::int64_t timestamp_ns(Timestamp t) noexcept { return t.time_since_epoch().count(); }

// A JSON value kept as its exact text (the contract's "any" fields).
struct RawJson {
  std::string text = "null";
  friend bool operator==(const RawJson&, const RawJson&) = default;
};

// One known value of a contract enum: the wire string and the integer used when signing.
struct EnumValue {
  std::string_view wire;
  std::int64_t code;
};

// A contract enum. Def (generated) holds `enum Known` and `values`. A value this SDK version does not know
// (from a newer server) is kept as its wire string, so decoding never fails on a new enum value.
//
//   enums::TimeInForce t = enums::TimeInForce::GOOD_TILL_TIME;
//   if (t == enums::TimeInForce::GOOD_TILL_TIME) ...
//   t.wire();  // "GOOD_TILL_TIME"
template <class Def>
class Enum : public Def {
 public:
  using Known = typename Def::Known;

  // An empty unknown value ("").
  Enum() = default;
  Enum(Known value) noexcept : index_(static_cast<int>(value)) {}

  static Enum from_wire(std::string_view wire) {
    Enum e;
    for (std::size_t i = 0; i < Def::values.size(); ++i) {
      if (Def::values[i].wire == wire) {
        e.index_ = static_cast<int>(i);
        return e;
      }
    }
    e.unknown_ = std::string(wire);
    return e;
  }

  // Every value this SDK knows, in contract order.
  static constexpr std::span<const EnumValue> all() noexcept { return Def::values; }

  std::string_view wire() const noexcept {
    return index_ >= 0 ? Def::values[static_cast<std::size_t>(index_)].wire : std::string_view(unknown_);
  }
  bool is_unknown() const noexcept { return index_ < 0; }
  std::optional<Known> known() const noexcept {
    if (index_ < 0) return std::nullopt;
    return static_cast<Known>(index_);
  }
  // The integer signed in EIP-712 messages; nullopt for an unknown value.
  std::optional<std::int64_t> code() const noexcept {
    if (index_ < 0) return std::nullopt;
    return Def::values[static_cast<std::size_t>(index_)].code;
  }

  friend bool operator==(const Enum& a, const Enum& b) noexcept { return a.wire() == b.wire(); }
  friend bool operator==(const Enum& a, Known b) noexcept { return a.index_ == static_cast<int>(b); }

 private:
  int index_ = -1;
  std::string unknown_;
};

namespace detail {
// Builds a model without its required values; only decoders and sign functions use it, and they set every
// required value before returning the model.
struct Uninitialized {};
}  // namespace detail

}  // namespace grvt
