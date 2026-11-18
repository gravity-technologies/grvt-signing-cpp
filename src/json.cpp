#include "json.hpp"

#include <bit>
#include <cstdint>
#include <cstring>

namespace grvt::detail::json {

const Value* Value::find(std::string_view key) const noexcept {
  for (const auto& m : members) {
    if (m.key == key) return &m.value;
  }
  return nullptr;
}

namespace {

void utf8(std::string& out, std::uint32_t cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xC0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xE0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else {
    out += static_cast<char>(0xF0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}

// The length of one well-formed multi-byte UTF-8 sequence at s[i] (no overlong forms, surrogates or
// values over U+10FFFF), or 0.
std::size_t utf8_sequence(std::string_view s, std::size_t i) {
  const auto b = [&](std::size_t k) { return static_cast<unsigned char>(s[i + k]); };
  const unsigned char c = b(0);
  std::size_t n = 0;
  unsigned char lo = 0x80, hi = 0xBF;
  if (c >= 0xC2 && c <= 0xDF) {
    n = 2;
  } else if (c >= 0xE0 && c <= 0xEF) {
    n = 3;
    if (c == 0xE0) lo = 0xA0;
    if (c == 0xED) hi = 0x9F;
  } else if (c >= 0xF0 && c <= 0xF4) {
    n = 4;
    if (c == 0xF0) lo = 0x90;
    if (c == 0xF4) hi = 0x8F;
  } else {
    return 0;
  }
  if (i + n > s.size()) return 0;
  if (b(1) < lo || b(1) > hi) return 0;
  for (std::size_t k = 2; k < n; ++k) {
    if (b(k) < 0x80 || b(k) > 0xBF) return 0;
  }
  return n;
}

// A mask of the bytes among the 8 at p that end the plain run of a string: '"', '\\', below 0x20 or above
// 0x7F. Bytes above the first such byte may be marked wrongly, but the lowest marked byte is exact.
inline std::uint64_t special8(const char* p) noexcept {
  std::uint64_t w;
  std::memcpy(&w, p, 8);
  constexpr std::uint64_t ones = 0x0101010101010101ull, highs = 0x8080808080808080ull;
  auto zero_byte = [](std::uint64_t v) { return (v - ones) & ~v & highs; };
  return zero_byte(w ^ (ones * '"')) | zero_byte(w ^ (ones * '\\')) | ((w - ones * 0x20) & ~w & highs) | (w & highs);
}

bool hex4(std::string_view s, std::size_t& pos, std::uint32_t& cp) {
  if (pos + 4 > s.size()) return false;
  cp = 0;
  for (int i = 0; i < 4; ++i) {
    const char c = s[pos++];
    cp <<= 4;
    if (c >= '0' && c <= '9')
      cp |= static_cast<std::uint32_t>(c - '0');
    else if (c >= 'a' && c <= 'f')
      cp |= static_cast<std::uint32_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F')
      cp |= static_cast<std::uint32_t>(c - 'A' + 10);
    else
      return false;
  }
  return true;
}

}  // namespace

std::string Reader::message() const { return "invalid JSON at byte " + std::to_string(error_pos_) + ": " + why_; }

bool Reader::fail(const char* why) noexcept {
  if (!failed_) {
    failed_ = true;
    why_ = why;
    error_pos_ = pos_;
  }
  return false;
}

bool Reader::finish() noexcept {
  skip_ws();
  if (pos_ != s_.size()) return fail("trailing characters");
  return !failed_;
}

void Reader::open() noexcept {
  ++pos_;
  ++depth_;
  first_[depth_] = true;
  keys_from_[depth_] = key_count_;
}

void Reader::close() noexcept {
  ++pos_;
  drop_keys(keys_from_[depth_]);
  --depth_;
}

Next Reader::next_member(std::string_view& key) {
  skip_ws();
  if (pos_ >= s_.size()) return fail("unexpected end"), Next::error;
  if (s_[pos_] == '}') {
    close();
    return Next::end;
  }
  if (first_[depth_]) {
    first_[depth_] = false;
  } else {
    if (s_[pos_] != ',') return fail("expected ',' or '}'"), Next::error;
    ++pos_;
    skip_ws();
  }
  if (pos_ >= s_.size() || s_[pos_] != '"') return fail("expected a key"), Next::error;
  if (!scan_string(key, key_buf_)) return Next::error;
  skip_ws();
  if (pos_ >= s_.size() || s_[pos_] != ':') return fail("expected ':'"), Next::error;
  ++pos_;
  return Next::item;
}

Next Reader::next_item() noexcept {
  skip_ws();
  if (pos_ >= s_.size()) return fail("unexpected end"), Next::error;
  if (s_[pos_] == ']') {
    close();
    return Next::end;
  }
  if (first_[depth_]) {
    first_[depth_] = false;
  } else {
    if (s_[pos_] != ',') return fail("expected ',' or ']'"), Next::error;
    ++pos_;
  }
  return Next::item;
}

bool Reader::unique_key(std::string_view key) {
  const std::uint32_t from = keys_from_[depth_];
  const std::size_t h = std::hash<std::string_view>{}(key);
  if (indexed_ && from >= indexed_from_) {
    for (auto [it, end] = key_index_.equal_range(h); it != end; ++it) {
      if (it->second >= from && key_text(key_at(it->second)) == key) return fail("duplicate key");
    }
  } else {
    for (std::uint32_t i = from; i < key_count_; ++i) {
      if (key_text(key_at(i)) == key) return fail("duplicate key");
    }
  }
  KeyRef k{key.data(), 0, static_cast<std::uint32_t>(key.size())};
  if (key.data() < s_.data() || key.data() + key.size() > s_.data() + s_.size()) {
    // Decoded from escapes into key_buf_, which the next key reuses.
    k = {nullptr, static_cast<std::uint32_t>(key_arena_.size()), static_cast<std::uint32_t>(key.size())};
    key_arena_.append(key);
  }
  if (key_count_ < INLINE_KEYS) {
    keys_[key_count_] = k;
  } else {
    more_keys_.push_back(k);
  }
  ++key_count_;
  if (indexed_) {
    key_index_.emplace(h, key_count_ - 1);
  } else if (key_count_ - from > INLINE_KEYS) {
    // An object with many unknown keys: index them by hash so each check stays O(1), not O(keys).
    indexed_ = true;
    indexed_from_ = from;
    for (std::uint32_t i = from; i < key_count_; ++i) {
      key_index_.emplace(std::hash<std::string_view>{}(key_text(key_at(i))), i);
    }
  }
  return true;
}

void Reader::drop_keys(std::uint32_t from) {
  if (from >= key_count_) return;
  if (indexed_) {
    if (from <= indexed_from_) {
      key_index_.clear();
      indexed_ = false;
    } else {
      // Only the dropped keys (an inner object's), before their text goes from the arena.
      for (std::uint32_t i = from; i < key_count_; ++i) {
        for (auto [it, end] = key_index_.equal_range(std::hash<std::string_view>{}(key_text(key_at(i)))); it != end;
             ++it) {
          if (it->second == i) {
            key_index_.erase(it);
            break;
          }
        }
      }
    }
  }
  if (!key_arena_.empty()) {
    for (std::uint32_t i = from; i < key_count_; ++i) {
      if (key_at(i).source == nullptr) {
        key_arena_.resize(key_at(i).offset);
        break;
      }
    }
  }
  key_count_ = from;
  if (from < INLINE_KEYS) {
    more_keys_.clear();
  } else {
    more_keys_.resize(from - INLINE_KEYS);
  }
}

bool Reader::word(std::string_view w) noexcept {
  if (s_.substr(pos_, w.size()) != w) return fail("unexpected character");
  pos_ += w.size();
  return true;
}

bool Reader::boolean(bool& out) noexcept {
  out = s_[pos_] == 't';
  return word(out ? "true" : "false");
}

bool Reader::null() noexcept {
  if (peek() != 'n') return false;
  return word("null");
}

bool Reader::number(std::string_view& out) noexcept {
  const std::size_t start = pos_;
  auto digits = [&] {
    const std::size_t d = pos_;
    while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
    return pos_ > d;
  };
  if (pos_ < s_.size() && s_[pos_] == '-') ++pos_;
  if (pos_ < s_.size() && s_[pos_] == '0') {
    ++pos_;
  } else if (!digits()) {
    return fail("unexpected character");
  }
  if (pos_ < s_.size() && s_[pos_] == '.') {
    ++pos_;
    if (!digits()) return fail("bad number");
  }
  if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
    ++pos_;
    if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
    if (!digits()) return fail("bad number");
  }
  out = s_.substr(start, pos_ - start);
  return true;
}

bool Reader::scan_string(std::string_view& out, std::string& buf) {
  ++pos_;
  const std::size_t start = pos_;
  // Fast path: no escapes, so the text is a slice of the source. Jumps eight bytes at a time to the next
  // quote, backslash, control character or non-ASCII byte (little-endian: the lowest byte comes first).
  for (;;) {
    if (pos_ + 8 <= s_.size()) {
      const std::uint64_t m = special8(s_.data() + pos_);
      if (m == 0) {
        pos_ += 8;
        continue;
      }
      if constexpr (std::endian::native == std::endian::little)
        pos_ += static_cast<std::size_t>(std::countr_zero(m) / 8);
    } else if (pos_ >= s_.size()) {
      return fail("unterminated string");
    }
    const auto c = static_cast<unsigned char>(s_[pos_]);
    if (c == '"') {
      out = s_.substr(start, pos_ - start);
      ++pos_;
      return true;
    }
    if (c == '\\') break;
    if (c < 0x20) return fail("control character in string");
    if (c < 0x80) {
      ++pos_;
      continue;
    }
    const std::size_t n = utf8_sequence(s_, pos_);
    if (n == 0) return fail("invalid UTF-8 in string");
    pos_ += n;
  }
  // An escape: decode into buf from here on.
  buf.assign(s_.substr(start, pos_ - start));
  for (;;) {
    if (pos_ >= s_.size()) return fail("unterminated string");
    const auto c = static_cast<unsigned char>(s_[pos_]);
    if (c == '"') {
      ++pos_;
      out = buf;
      return true;
    }
    if (c < 0x20) return fail("control character in string");
    if (c >= 0x80) {
      const std::size_t n = utf8_sequence(s_, pos_);
      if (n == 0) return fail("invalid UTF-8 in string");
      buf.append(s_.substr(pos_, n));
      pos_ += n;
      continue;
    }
    ++pos_;
    if (c != '\\') {
      buf += static_cast<char>(c);
      continue;
    }
    if (pos_ >= s_.size()) return fail("unterminated string");
    const char e = s_[pos_++];
    switch (e) {
      case '"': buf += '"'; break;
      case '\\': buf += '\\'; break;
      case '/': buf += '/'; break;
      case 'b': buf += '\b'; break;
      case 'f': buf += '\f'; break;
      case 'n': buf += '\n'; break;
      case 'r': buf += '\r'; break;
      case 't': buf += '\t'; break;
      case 'u': {
        std::uint32_t cp = 0;
        if (!hex4(s_, pos_, cp)) return fail("bad \\u escape");
        if (cp >= 0xD800 && cp < 0xDC00) {
          // A high surrogate must be followed by an escaped low one.
          std::uint32_t lo = 0;
          if (s_.substr(pos_, 2) != "\\u") return fail("bad surrogate pair");
          pos_ += 2;
          if (!hex4(s_, pos_, lo) || lo < 0xDC00 || lo >= 0xE000) return fail("bad surrogate pair");
          cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
        } else if (cp >= 0xDC00 && cp < 0xE000) {
          return fail("bad surrogate pair");
        }
        utf8(buf, cp);
        break;
      }
      default: return fail("bad escape");
    }
  }
}

bool Reader::string(std::string& out) {
  std::string_view v;
  if (!scan_string(v, out)) return false;
  if (v.data() != out.data()) out.assign(v);
  return true;
}

bool Reader::string_view(std::string_view& out) { return scan_string(out, value_buf_); }

bool Reader::skip() {
  switch (peek()) {
    case '\0': return false;
    case '{': {
      begin_object();
      std::string_view key;
      for (;;) {
        const Next n = next_member(key);
        if (n == Next::end) return true;
        if (n == Next::error || !skip_member(key)) return false;
      }
    }
    case '[':
      begin_array();
      for (;;) {
        const Next n = next_item();
        if (n == Next::end) return true;
        if (n == Next::error || !skip()) return false;
      }
    case '"': {
      std::string_view v;
      return string_view(v);
    }
    case 't':
    case 'f': {
      bool b = false;
      return boolean(b);
    }
    case 'n': return word("null");
    default: {
      std::string_view v;
      return number(v);
    }
  }
}

bool Reader::skip_unchecked() noexcept {
  const char c0 = peek();
  if (c0 != '{' && c0 != '[') {
    if (c0 == '\0') return false;
    if (c0 != '"') {
      std::string_view v;
      bool b = false;
      if (c0 == 't' || c0 == 'f') return boolean(b);
      if (c0 == 'n') return word("null");
      return number(v);
    }
  }
  int depth = 0;
  while (pos_ < s_.size()) {
    const char c = s_[pos_++];
    if (c == '"') {
      // To the closing quote, stepping over escaped characters.
      for (;;) {
        while (pos_ + 8 <= s_.size()) {
          const std::uint64_t m = special8(s_.data() + pos_);
          if (m == 0) {
            pos_ += 8;
            continue;
          }
          if constexpr (std::endian::native == std::endian::little)
            pos_ += static_cast<std::size_t>(std::countr_zero(m) / 8);
          break;
        }
        if (pos_ >= s_.size()) return fail("unterminated string");
        const char d = s_[pos_++];
        if (d == '"') break;
        if (d == '\\') ++pos_;
      }
      if (depth == 0) return true;
    } else if (c == '{' || c == '[') {
      ++depth;
    } else if (c == '}' || c == ']') {
      if (--depth == 0) return true;
    }
  }
  return fail("unexpected end");
}

namespace {

// The tree, built with a Reader.
bool build(Reader& r, Value& v) {
  const char c = r.peek();
  const std::size_t start = r.pos();
  bool ok = true;
  switch (c) {
    case '\0': return false;
    case '{': {
      v.kind = Kind::object;
      r.begin_object();
      std::string_view key;
      for (;;) {
        const Next n = r.next_member(key);
        if (n == Next::end) break;
        if (n == Next::error || !r.unique_key(key)) return false;
        Member m;
        m.key.assign(key);
        if (!build(r, m.value)) return false;
        v.members.push_back(std::move(m));
      }
      break;
    }
    case '[':
      v.kind = Kind::array;
      r.begin_array();
      for (;;) {
        const Next n = r.next_item();
        if (n == Next::end) break;
        if (n == Next::error) return false;
        Value item;
        if (!build(r, item)) return false;
        v.items.push_back(std::move(item));
      }
      break;
    case '"':
      v.kind = Kind::string;
      ok = r.string(v.text);
      break;
    case 't':
    case 'f':
      v.kind = Kind::boolean;
      ok = r.boolean(v.boolean);
      break;
    case 'n': ok = r.null(); break;
    default: {
      v.kind = Kind::number;
      std::string_view n;
      ok = r.number(n);
      if (ok) v.text.assign(n);
    }
  }
  if (!ok) return false;
  v.raw = r.slice(start);
  return true;
}

}  // namespace

Result<Value> parse(std::string_view text) {
  Reader r(text);
  Value v;
  if (!build(r, v) || !r.finish()) return Error::decode("", r.message());
  return v;
}

void append_quoted(std::string& out, std::string_view s) {
  static constexpr char hex[] = "0123456789abcdef";
  out += '"';
  for (const char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          out += "\\u00";
          out += hex[(c >> 4) & 0xF];
          out += hex[c & 0xF];
        } else {
          out += c;
        }
    }
  }
  out += '"';
}

void Writer::key(std::string_view k) {
  value_prefix();
  append_quoted(*out_, k);
  *out_ += ':';
  after_key_ = true;
}

void Writer::string(std::string_view s) {
  value_prefix();
  append_quoted(*out_, s);
}

}  // namespace grvt::detail::json
