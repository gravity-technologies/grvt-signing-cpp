// JSON encoding of the generated models (full field names, as on the wire).
//
// - Decimals, 64-bit integers and timestamps travel as JSON strings; nothing goes through a double.
//   64-bit integers also decode from a number or a 0x hex string.
// - Small integers (uint8/16/32, int8/16/32) are JSON numbers; they also decode from a quoted number.
// - Optional fields are omitted when empty. Required nullable fields are written as null when empty and
//   must be present when decoding. Required fields must be present and not null.
// - Unknown fields are ignored; unknown enum values are kept.
#pragma once

#include <string>
#include <string_view>

#include "grvt/result.hpp"
#include "grvt/scalars.hpp"

namespace grvt {

// Specialized for every generated model (generated/models.hpp).
template <class T>
struct Codec;

template <class T>
std::string encode(const T& value) {
  return Codec<T>::encode(value);
}

template <class T>
Result<T> decode(std::string_view json) {
  return Codec<T>::decode(json);
}

// The same, reusing memory the caller keeps: out's contents are replaced and its capacity kept, so encoding
// or decoding again into the same object allocates nothing once its sizes have settled. A failed
// decode_into leaves out partly read; it is still safe to decode into again.
template <class T>
void encode_into(const T& value, std::string& out) {
  Codec<T>::encode_into(value, out);
}

template <class T>
Result<void> decode_into(std::string_view json, T& out) {
  return Codec<T>::decode_into(json, out);
}

// A model to decode into, with every field empty or zero (required fields too, so it is not a valid value
// until something is decoded into it):
//
//   auto frame = grvt::blank<api::orderbook_delta_stream::Feed>();
//   grvt::decode_feed<api::orderbook_delta_stream>(msg, frame);
template <class T>
T blank() {
  return T(detail::Uninitialized{});
}

}  // namespace grvt
