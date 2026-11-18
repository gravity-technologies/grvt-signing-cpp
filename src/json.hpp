// Internal JSON reader and writer. Numbers keep their exact text (no double round trip). Not part of the
// public API.
//
// Two readers:
// - Reader: one pass over the text, no tree. The generated decoders pull each value straight into its
//   model field, so decoding a reply or stream frame builds nothing in between. Used on every hot path.
// - parse(): a small tree (Value), for cold paths that look at a few fields of a body (login replies,
//   error bodies, subscribe acks).
// Both accept the same JSON: nesting up to 128 levels, no duplicate object keys, valid UTF-8 only, so a
// frame cannot carry two readings of one field.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "grvt/result.hpp"

namespace grvt::detail::json {

inline constexpr int MAX_DEPTH = 128;

enum class Kind { null, boolean, number, string, array, object };

struct Member;

struct Value {
  Kind kind = Kind::null;
  bool boolean = false;
  // number: the literal text; string: the decoded text.
  std::string text;
  std::vector<Value> items;
  std::vector<Member> members;
  // The value's text in the parsed source (valid while the source lives).
  std::string_view raw;

  bool is_null() const noexcept { return kind == Kind::null; }
  bool is_object() const noexcept { return kind == Kind::object; }
  bool is_array() const noexcept { return kind == Kind::array; }
  bool is_string() const noexcept { return kind == Kind::string; }
  bool is_number() const noexcept { return kind == Kind::number; }
  bool is_bool() const noexcept { return kind == Kind::boolean; }
  // The first member with this key, or null.
  const Value* find(std::string_view key) const noexcept;
};

struct Member {
  std::string key;
  Value value;
};

// One complete JSON text as a tree.
Result<Value> parse(std::string_view text);

// The next step inside an object or array.
enum class Next { item, end, error };

// Reads one JSON text front to back. Callers look at the next value with peek() and then read it with the
// matching call; a type mismatch is the caller's error, a syntax error is the reader's (failed()).
//
//   if (r.peek() != '{') ...;  r.begin_object();
//   std::string_view key;
//   while (r.next_member(key) == Next::item) { ...read the value, or skip_member(key)... }
//   if (r.failed()) ...;
//
// Keys the caller does not know go through skip_member(), which also rejects a key seen twice; callers
// check repeats of the keys they read themselves.
class Reader {
 public:
  explicit Reader(std::string_view text) noexcept : s_(text) {
    first_[0] = true;
    keys_from_[0] = 0;
  }
  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;

  bool failed() const noexcept { return failed_; }
  // "invalid JSON at byte N: why".
  std::string message() const;
  // Records a syntax error (the first one wins). Always false.
  bool fail(const char* why) noexcept;

  // The first character of the next value, after whitespace; 0 at the end of the text or when the value
  // is nested deeper than MAX_DEPTH (both syntax errors).
  char peek() noexcept {
    skip_ws();
    if (depth_ > MAX_DEPTH) return fail("nested too deeply"), '\0';
    if (pos_ >= s_.size()) return fail("unexpected end"), '\0';
    return s_[pos_];
  }
  std::size_t pos() const noexcept { return pos_; }
  std::string_view slice(std::size_t from) const noexcept { return {s_.data() + from, pos_ - from}; }
  // Only whitespace is left.
  bool finish() noexcept;

  // After peek() == '{' / '['.
  void begin_object() noexcept { open(); }
  void begin_array() noexcept { open(); }
  // The next key (decoded; valid until the next key is read) or the end of the object.
  Next next_member(std::string_view& key);
  Next next_item() noexcept;

  // After peek() == '"': the decoded text into out (its capacity is reused).
  bool string(std::string& out);
  // After peek() == '"': the decoded text, as a view of the source when it has no escapes, else of a
  // buffer that the next string_view() call reuses.
  bool string_view(std::string_view& out);
  // After peek() is '-' or a digit: the number's exact text.
  bool number(std::string_view& out) noexcept;
  // After peek() is 't' or 'f'.
  bool boolean(bool& out) noexcept;
  // Reads null if it is next.
  bool null() noexcept;
  // Any value, checked but not kept.
  bool skip();
  // Any value, by its brackets and string quotes only: well-formed JSON is skipped exactly, broken JSON
  // inside the value may pass. For a payload that is read (and so checked) later.
  bool skip_unchecked() noexcept;
  // The value of a key the caller does not read: rejects a repeated key, then skips the value.
  bool skip_member(std::string_view key) { return unique_key(key) && skip(); }
  // Rejects a key already passed here in the current object.
  bool unique_key(std::string_view key);

 private:
  void skip_ws() noexcept {
    while (pos_ < s_.size()) {
      const char c = s_[pos_];
      if (c != ' ' && c != '\n' && c != '\r' && c != '\t') return;
      ++pos_;
    }
  }
  void open() noexcept;
  void close() noexcept;
  void drop_keys(std::uint32_t from);
  bool word(std::string_view w) noexcept;
  // Reads a string at pos_ (the opening quote). out views the source when there are no escapes, else
  // buf, which then holds the decoded text.
  bool scan_string(std::string_view& out, std::string& buf);

  std::string_view s_;
  std::size_t pos_ = 0;
  int depth_ = 0;
  bool failed_ = false;
  std::size_t error_pos_ = 0;
  const char* why_ = "";
  // Per open container: nothing read yet; where its keys start in the key list.
  // Set by open(); the root's entries by the constructor.
  bool first_[MAX_DEPTH + 2];
  std::uint32_t keys_from_[MAX_DEPTH + 2];
  std::string key_buf_;
  std::string value_buf_;

  // The keys skip_member() has passed in the open objects. The first ones live here; only a text with many
  // unknown keys open at once needs the heap.
  struct KeyRef {
    const char* source;  // the key in the source text, or null: key_arena_[offset, offset + size)
    std::uint32_t offset;
    std::uint32_t size;
  };
  static constexpr std::uint32_t INLINE_KEYS = 32;
  KeyRef& key_at(std::uint32_t i) noexcept { return i < INLINE_KEYS ? keys_[i] : more_keys_[i - INLINE_KEYS]; }
  std::string_view key_text(const KeyRef& k) const noexcept {
    return {k.source ? k.source : key_arena_.data() + k.offset, k.size};
  }
  KeyRef keys_[INLINE_KEYS];
  std::uint32_t key_count_ = 0;
  std::vector<KeyRef> more_keys_;
  // Unknown keys that had escapes, decoded.
  std::string key_arena_;
  // Hash -> key index, built only once an object has more than INLINE_KEYS unknown keys; it covers every key
  // from indexed_from_ on, so duplicate checks in a huge object stay linear overall.
  bool indexed_ = false;
  std::uint32_t indexed_from_ = 0;
  std::unordered_multimap<std::size_t, std::uint32_t> key_index_;
};

// Appends compact JSON to a string (its own, or one the caller reuses). Callers write keys and values in
// order; the writer adds commas. Models nest far less than MAX_DEPTH.
class Writer {
 public:
  Writer() noexcept : out_(&own_) {}
  explicit Writer(std::string& out) noexcept : out_(&out) {}
  Writer(const Writer&) = delete;
  Writer& operator=(const Writer&) = delete;

  void begin_object() { open('{'); }
  void end_object() { close('}'); }
  void begin_array() { open('['); }
  void end_array() { close(']'); }
  void key(std::string_view k);
  void string(std::string_view s);
  // A number literal written verbatim.
  void number(std::string_view text) {
    value_prefix();
    *out_ += text;
  }
  void boolean(bool b) {
    value_prefix();
    *out_ += b ? "true" : "false";
  }
  void null() {
    value_prefix();
    *out_ += "null";
  }
  // Already-encoded JSON written verbatim.
  void raw(std::string_view json) {
    value_prefix();
    *out_ += json;
  }

  std::string take() { return std::move(*out_); }
  const std::string& str() const noexcept { return *out_; }

 private:
  void open(char c) {
    value_prefix();
    *out_ += c;
    if (depth_ + 1 < MAX_DEPTH) first_[++depth_] = true;
  }
  void close(char c) {
    *out_ += c;
    if (depth_ > 0) --depth_;
  }
  void value_prefix() {
    if (after_key_) {
      after_key_ = false;
      return;
    }
    if (depth_ > 0) {
      if (!first_[depth_]) *out_ += ',';
      first_[depth_] = false;
    }
  }
  std::string own_;
  std::string* out_;
  int depth_ = 0;
  bool after_key_ = false;
  bool first_[MAX_DEPTH] = {};
};

// s as a JSON string literal.
void append_quoted(std::string& out, std::string_view s);

}  // namespace grvt::detail::json
