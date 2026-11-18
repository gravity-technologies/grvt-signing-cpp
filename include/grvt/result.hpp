// Expected encoding and signing failures are returned as values.
#pragma once

#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace grvt {

enum class ErrorKind { signing, decode, config };
struct Error {
  ErrorKind kind = ErrorKind::config;
  std::string message;
  static Error config(std::string message);
  static Error signing(std::string message);
  static Error decode(std::string context, std::string message);
  std::string describe() const { return message; }
};

// T or an Error. Accessing the wrong alternative is a programming error (asserted).
template <class T>
class [[nodiscard]] Result {
 public:
  Result(T value) : v_(std::in_place_index<0>, std::move(value)) {}
  Result(Error error) : v_(std::in_place_index<1>, std::move(error)) {}

  bool ok() const noexcept { return v_.index() == 0; }
  explicit operator bool() const noexcept { return ok(); }

  T& value() & {
    assert(ok());
    return *std::get_if<0>(&v_);
  }
  const T& value() const& {
    assert(ok());
    return *std::get_if<0>(&v_);
  }
  T&& value() && {
    assert(ok());
    return std::move(*std::get_if<0>(&v_));
  }
  T& operator*() & { return value(); }
  const T& operator*() const& { return value(); }
  T&& operator*() && { return std::move(*this).value(); }
  T* operator->() { return &value(); }
  const T* operator->() const { return &value(); }

  const Error& error() const& {
    assert(!ok());
    return *std::get_if<1>(&v_);
  }
  Error&& error() && {
    assert(!ok());
    return std::move(*std::get_if<1>(&v_));
  }

  T value_or(T fallback) const& { return ok() ? value() : std::move(fallback); }

 private:
  std::variant<T, Error> v_;
};

template <>
class [[nodiscard]] Result<void> {
 public:
  Result() = default;
  Result(Error error) : e_(std::move(error)) {}

  bool ok() const noexcept { return !e_.has_value(); }
  explicit operator bool() const noexcept { return ok(); }

  const Error& error() const& {
    assert(!ok());
    return *e_;
  }
  Error&& error() && {
    assert(!ok());
    return std::move(*e_);
  }

 private:
  std::optional<Error> e_;
};

}  // namespace grvt
