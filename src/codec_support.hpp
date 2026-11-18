// What the generated codecs (generated/models.cpp) are built from: one Io<T> per wire value type, and the
// required / optional / nullable field rules. See codec.hpp for the wire rules.
//
// Decoding is one pass: Io<T>::read pulls the next value from a json::Reader straight into the field, and
// reuses the memory the field already holds (strings, lists, nested models), so decoding again into the
// same object allocates nothing once its sizes have settled.
#pragma once

#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "grvt/result.hpp"
#include "grvt/scalars.hpp"
#include "json.hpp"

namespace grvt::detail::codec {

// The first decode error, as "Type.field: why".
struct Ctx {
  std::string error;
  bool fail(std::string_view where, std::string_view why) {
    if (error.empty()) {
      error.assign(where);
      error += ": ";
      error += why;
    }
    return false;
  }
};

template <class T>
struct Io;

// Integers: from a number, a quoted number, or (64-bit) a 0x hex string. Written as numbers, except 64-bit
// integers, which the gateway wants as strings.
bool parse_integer(std::string_view text, bool quoted, bool is_signed, std::uint64_t& magnitude, bool& negative);
bool parse_integer(const json::Value& v, bool is_signed, std::uint64_t& magnitude, bool& negative);

// Readers: each looks at the next value and reads it into out (reusing out's memory), or fails. A wrong
// type is ctx's error; broken JSON is the reader's (r.failed()).

// The value at r as a string (decoded), or false with ctx's error.
inline bool read_text(json::Reader& r, std::string_view& out, Ctx& ctx, const char* type, const char* why) {
  const char c = r.peek();
  if (c == '"') return r.string_view(out);
  return c == '\0' ? false : ctx.fail(type, why);
}

template <class T>
struct IntIo {
  static T make() { return T{}; }
  static bool read(json::Reader& r, T& out, Ctx& ctx) {
    const char c = r.peek();
    const std::size_t start = r.pos();
    std::string_view text;
    const bool quoted = c == '"';
    if (quoted) {
      if (!r.string_view(text)) return false;
    } else if (c == '-' || (c >= '0' && c <= '9')) {
      if (!r.number(text)) return false;
    } else if (c == '\0' || !r.skip()) {
      return false;
    }
    std::uint64_t mag = 0;
    bool neg = false;
    if (text.data() == nullptr || !parse_integer(text, quoted, std::is_signed_v<T>, mag, neg)) {
      return ctx.fail("integer", "not an integer: " + std::string(r.slice(start)));
    }
    if (neg) {
      using U = std::make_unsigned_t<T>;
      const auto limit = static_cast<std::uint64_t>(static_cast<U>(std::numeric_limits<T>::max())) + 1;
      if (mag > limit) return ctx.fail("integer", "out of range: " + std::string(r.slice(start)));
      out = static_cast<T>(0 - static_cast<U>(mag));
      return true;
    }
    if constexpr (sizeof(T) < sizeof(std::uint64_t) || std::is_signed_v<T>) {
      if (mag > static_cast<std::uint64_t>(std::numeric_limits<T>::max()))
        return ctx.fail("integer", "out of range: " + std::string(r.slice(start)));
    }
    out = static_cast<T>(mag);
    return true;
  }
  static void write(json::Writer& w, T v) {
    char buf[24];
    auto r = std::to_chars(buf, buf + sizeof buf, v);
    if constexpr (sizeof(T) == 8) {
      w.string(std::string_view(buf, static_cast<std::size_t>(r.ptr - buf)));
    } else {
      w.number(std::string_view(buf, static_cast<std::size_t>(r.ptr - buf)));
    }
  }
};

template <>
struct Io<std::uint8_t> : IntIo<std::uint8_t> {};
template <>
struct Io<std::uint16_t> : IntIo<std::uint16_t> {};
template <>
struct Io<std::uint32_t> : IntIo<std::uint32_t> {};
template <>
struct Io<std::uint64_t> : IntIo<std::uint64_t> {};
template <>
struct Io<std::int8_t> : IntIo<std::int8_t> {};
template <>
struct Io<std::int16_t> : IntIo<std::int16_t> {};
template <>
struct Io<std::int32_t> : IntIo<std::int32_t> {};
template <>
struct Io<std::int64_t> : IntIo<std::int64_t> {};

template <>
struct Io<bool> {
  static bool make() { return false; }
  static bool read(json::Reader& r, bool& out, Ctx& ctx) {
    const char c = r.peek();
    if (c == 't' || c == 'f') return r.boolean(out);
    return c == '\0' ? false : ctx.fail("bool", "not a boolean");
  }
  static void write(json::Writer& w, bool v) { w.boolean(v); }
};

template <>
struct Io<std::string> {
  static std::string make() { return {}; }
  static bool read(json::Reader& r, std::string& out, Ctx& ctx) {
    const char c = r.peek();
    if (c == '"') return r.string(out);
    return c == '\0' ? false : ctx.fail("string", "not a string");
  }
  static void write(json::Writer& w, const std::string& v) { w.string(v); }
};

template <>
struct Io<Decimal> {
  static Decimal make() { return {}; }
  static bool read(json::Reader& r, Decimal& out, Ctx& ctx) {
    std::string_view text;
    if (!read_text(r, text, ctx, "decimal", "not a decimal string")) return false;
    if (!Decimal::valid(text)) return ctx.fail("decimal", Decimal::parse(text).error().message);
    out.text_.assign(text);
    return true;
  }
  static void write(json::Writer& w, const Decimal& v) { w.string(v.text()); }
};

template <>
struct Io<Timestamp> {
  static Timestamp make() { return {}; }
  static bool read(json::Reader& r, Timestamp& out, Ctx& ctx) {
    std::string_view text;
    if (!read_text(r, text, ctx, "timestamp", "not a quoted integer of nanoseconds")) return false;
    std::int64_t ns = 0;
    const auto* end = text.data() + text.size();
    auto res = std::from_chars(text.data(), end, ns);
    if (text.empty() || res.ec != std::errc() || res.ptr != end)
      return ctx.fail("timestamp", "not a signed 64-bit integer: " + std::string(text));
    out = timestamp_from_ns(ns);
    return true;
  }
  static void write(json::Writer& w, Timestamp v) {
    char buf[24];
    auto r = std::to_chars(buf, buf + sizeof buf, timestamp_ns(v));
    w.string(std::string_view(buf, static_cast<std::size_t>(r.ptr - buf)));
  }
};

template <>
struct Io<RawJson> {
  static RawJson make() { return {}; }
  static bool read(json::Reader& r, RawJson& out, Ctx&) {
    if (r.peek() == '\0') return false;
    const std::size_t start = r.pos();
    if (!r.skip()) return false;
    out.text.assign(r.slice(start));
    return true;
  }
  static void write(json::Writer& w, const RawJson& v) {
    w.raw(v.text.empty() ? std::string_view("null") : std::string_view(v.text));
  }
};

template <class Def>
struct Io<Enum<Def>> {
  static Enum<Def> make() { return {}; }
  static bool read(json::Reader& r, Enum<Def>& out, Ctx& ctx) {
    std::string_view text;
    if (!read_text(r, text, ctx, "enum", "not a string")) return false;
    out = Enum<Def>::from_wire(text);
    return true;
  }
  static void write(json::Writer& w, const Enum<Def>& v) { w.string(v.wire()); }
};

// Reads into the elements already there (keeping their memory), then adds or drops elements to match.
template <class T>
struct Io<std::vector<T>> {
  static std::vector<T> make() { return {}; }
  static bool read(json::Reader& r, std::vector<T>& out, Ctx& ctx) {
    const char c = r.peek();
    if (c != '[') return c == '\0' ? false : ctx.fail("list", "not an array");
    r.begin_array();
    std::size_t n = 0;
    for (;;) {
      const json::Next next = r.next_item();
      if (next == json::Next::end) break;
      if (next == json::Next::error) return false;
      if (n == out.size()) out.push_back(Io<T>::make());
      if (!Io<T>::read(r, out[n], ctx)) return false;
      ++n;
    }
    out.erase(out.begin() + static_cast<std::ptrdiff_t>(n), out.end());
    return true;
  }
  static void write(json::Writer& w, const std::vector<T>& v) {
    w.begin_array();
    for (const auto& x : v) Io<T>::write(w, x);
    w.end_array();
  }
};

// Reads one field. The error names the field ("OrderLeg.size: not a decimal string").
template <class T>
bool read_field(json::Reader& r, T& out, Ctx& ctx, std::string_view where) {
  Ctx inner;
  if (Io<T>::read(r, out, inner)) return true;
  if (r.failed()) return false;
  // A nested model already named its own field; a scalar names only its type.
  const auto colon = inner.error.find(':');
  const bool nested = inner.error.find('.') != std::string::npos && inner.error.find('.') < colon;
  if (nested) return ctx.fail(inner.error.substr(0, colon), inner.error.substr(colon + 2));
  return ctx.fail(where, colon == std::string::npos ? inner.error : inner.error.substr(colon + 2));
}

// The generated model readers: each key the model knows is read once (a repeat is a JSON error), then
// fields that never came are checked (required and nullable must be there) or cleared (optional).
inline bool first_time(json::Reader& r, std::uint64_t* seen, unsigned i) {
  const std::uint64_t bit = std::uint64_t{1} << (i % 64);
  if ((seen[i / 64] & bit) != 0) return r.fail("duplicate key");
  seen[i / 64] |= bit;
  return true;
}

inline bool was_seen(const std::uint64_t* seen, unsigned i) {
  return (seen[i / 64] & (std::uint64_t{1} << (i % 64))) != 0;
}

// Not null.
template <class T>
bool read_required(json::Reader& r, T& out, Ctx& ctx, std::string_view where) {
  if (r.peek() == 'n') return r.null() && ctx.fail(where, "required field is null");
  return read_field(r, out, ctx, where);
}

// Null is empty (nullable and optional fields).
template <class T>
bool read_maybe(json::Reader& r, std::optional<T>& out, Ctx& ctx, std::string_view where) {
  if (r.peek() == 'n') {
    out.reset();
    return r.null();
  }
  if (!out) out.emplace(Io<T>::make());
  return read_field(r, *out, ctx, where);
}

template <class T>
void write_required(json::Writer& w, std::string_view key, const T& v) {
  w.key(key);
  Io<T>::write(w, v);
}

template <class T>
void write_nullable(json::Writer& w, std::string_view key, const std::optional<T>& v) {
  w.key(key);
  if (v)
    Io<T>::write(w, *v);
  else
    w.null();
}

template <class T>
void write_optional(json::Writer& w, std::string_view key, const std::optional<T>& v) {
  if (!v) return;
  w.key(key);
  Io<T>::write(w, *v);
}

template <class T>
void encode_into(const T& v, std::string& out) {
  out.clear();
  json::Writer w(out);
  Io<T>::write(w, v);
}

template <class T>
std::string encode_value(const T& v) {
  std::string out;
  encode_into(v, out);
  return out;
}

// On an error out is left partly read.
template <class T>
Result<void> decode_into(std::string_view text, T& out) {
  json::Reader r(text);
  Ctx ctx;
  if (!Io<T>::read(r, out, ctx)) return Error::decode("", r.failed() ? r.message() : ctx.error);
  if (!r.finish()) return Error::decode("", r.message());
  return {};
}

template <class T>
Result<T> decode_value(std::string_view text) {
  T out = Io<T>::make();
  if (auto ok = decode_into(text, out); !ok) return std::move(ok).error();
  return out;
}

}  // namespace grvt::detail::codec
