// What the generated sign functions (generated/signing.cpp) are built from: one helper per contract
// transform (contract.json signed.transforms), the fixed-layout struct encoder, the signature steps
// (prepare, sign, commit). Encoding errors always happen before
// anything is signed or written into the request.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "grvt/result.hpp"
#include "grvt/scalars.hpp"
#include "grvt/signing.hpp"
#include "keccak.hpp"

namespace grvt::detail::sign {

__extension__ typedef __int128 i128;
__extension__ typedef unsigned __int128 u128;

std::string to_string(i128 v);
std::string to_string(u128 v);

// One EIP-712 scalar, as a transform produced it. A string points into the request.
struct Value {
  enum class Kind { boolean, integer, u256, address, string };
  Kind kind = Kind::integer;
  bool b = false;
  i128 i = 0;
  std::array<std::uint8_t, 32> word{};
  std::array<std::uint8_t, 20> addr{};
  std::string_view s;

  static Value boolean(bool v);
  static Value integer(i128 v);
  static Value u256(const std::array<std::uint8_t, 32>& v);
  static Value address(const std::array<std::uint8_t, 20>& v);
  static Value string(std::string_view v);
};

// A wire value as the transforms see it.
struct Scalar {
  enum class Kind { str, integer, boolean };
  Kind kind = Kind::str;
  std::string_view s;
  i128 i = 0;
  bool b = false;

  static Scalar str(std::string_view v) { return Scalar{Kind::str, v, 0, false}; }
  static Scalar integer(i128 v) { return Scalar{Kind::integer, {}, v, false}; }
  static Scalar boolean(bool v) { return Scalar{Kind::boolean, {}, 0, v}; }
};

// The value of a member, or null when an optional member is empty.
template <class T>
const T* ptr(const T& v) noexcept {
  return &v;
}
template <class T>
const T* ptr(const std::optional<T>& v) noexcept {
  return v ? &*v : nullptr;
}

inline std::optional<Scalar> scalar(const std::string* v) {
  if (!v) return std::nullopt;
  return Scalar::str(*v);
}
inline std::optional<Scalar> scalar(const bool* v) {
  if (!v) return std::nullopt;
  return Scalar::boolean(*v);
}
inline std::optional<Scalar> scalar(const Decimal* v) {
  if (!v) return std::nullopt;
  return Scalar::str(v->text());
}
inline std::optional<Scalar> scalar(const Timestamp* v) {
  if (!v) return std::nullopt;
  return Scalar::integer(timestamp_ns(*v));
}
template <class T>
  requires(std::is_integral_v<T> && !std::is_same_v<T, bool>)
std::optional<Scalar> scalar(const T* v) {
  if (!v) return std::nullopt;
  return Scalar::integer(static_cast<i128>(*v));
}

// copy: the wire value as the EIP-712 type, or def when absent.
Result<Value> copy(std::optional<Scalar> v, std::string_view eip_type, std::string_view at, std::optional<Scalar> def);
// address: absent is the zero address.
Result<Value> address(const std::string* v, std::string_view at);
// Builder-style variant rules: is this address set to something other than zero?
bool address_set(const std::string* v) noexcept;
// scaled: decimal string x 10^decimals. Over-precision is rejected, never rounded.
Result<Value> scaled(const std::string* v, std::uint32_t decimals, std::string_view at,
                     std::optional<std::string_view> def);
Result<Value> scaled(const Decimal* v, std::uint32_t decimals, std::string_view at,
                     std::optional<std::string_view> def);
// "65000.1", 9 -> 65000100000000. The error is the reason only (callers add where).
Result<i128> scale_decimal(std::string_view s, std::uint32_t decimals);

// enumCode: the enum's signed integer. Absent is 0; a value this SDK does not know is an error.
template <class Def>
Result<Value> enum_code(const Enum<Def>* v, std::string_view at) {
  if (!v) return Value::integer(0);
  auto code = v->code();
  if (!code) return Error::signing(std::string(at) + ": unknown enum value \"" + std::string(v->wire()) + "\"");
  return Value::integer(*code);
}

// The metadata of one sign call (SignContext::metadata).
class Meta {
 public:
  explicit Meta(const SignContext& ctx) : m_(ctx.metadata ? *ctx.metadata : empty()) {}
  Result<const InstrumentMeta*> instrument(const std::string* name) const;
  Result<const CurrencyMeta*> currency(const std::string* symbol) const;
  // assetKey: the instrument hash as a uint256.
  Result<Value> asset_key(const std::string* name) const;
  // currencyId.
  Result<Value> currency_id(const std::string* symbol) const;
  // mainAccount: the caller-supplied main account address.
  Result<Value> main_account() const;

 private:
  static const SigningMetadata& empty();
  const SigningMetadata& m_;
};

// Adds a non-empty name once.
void present(std::vector<std::string>& out, const std::string* v);

// --- the struct encoder -------------------------------------------------------------------------

// How a field is written into its 32-byte word, decided at generation time from the EIP-712 type.
enum class FieldKind { boolean, address, string, uint, sint, list };

struct TypeDef;
struct FieldDef {
  std::string_view name;
  std::string_view type;
  const TypeDef* nested;  // the item type of a struct list
  FieldKind kind;
  std::uint32_t bits;  // uint / sint width
};
struct TypeDef {
  std::string_view name;
  Bytes32 type_hash;
  std::span<const FieldDef> fields;
};

// Writes v into word as field f of struct st (an error names "st.field").
Result<void> put(std::uint8_t* word, const FieldDef& f, const Value& v, std::string_view st);

// The generated fill_<type> functions write a struct's fields into an encoder Enc, one of two kinds with
// the same interface: Encoder<N> builds the EIP-712 struct hash, JsonStruct the typed-data message JSON.
// One code path for both, so the JSON a wallet signs is exactly what is hashed.
//
//   enc.put(i, value)            field i (checked to fit its type)
//   auto l = enc.template list<M>(i, item_type); l.open() -> item encoder; l.close(item); enc.end_list(i, l)

template <std::size_t N>
class Encoder;

// keccak256 of the concatenated item hashes of a struct list.
template <std::size_t M>
class HashList {
 public:
  explicit HashList(const TypeDef& t) : t_(t) {}
  Encoder<M> open() const { return Encoder<M>(t_); }
  void close(const Encoder<M>& item) noexcept { h_.update(item.hash()); }
  Bytes32 finish() noexcept { return h_.finish(); }

 private:
  const TypeDef& t_;
  Keccak256 h_;
};

// typeHash || one word per field, on the stack, hashed when complete (hashStruct).
template <std::size_t N>
class Encoder {
 public:
  explicit Encoder(const TypeDef& t) : t_(t) { std::memcpy(buf_, t.type_hash.data(), 32); }
  Result<void> put(std::size_t field, const Value& v) {
    return sign::put(buf_ + 32 * (field + 1), t_.fields[field], v, t_.name);
  }
  template <std::size_t M>
  HashList<M> list(std::size_t, const TypeDef& item) const {
    return HashList<M>(item);
  }
  template <std::size_t M>
  void end_list(std::size_t field, HashList<M>& l) noexcept {
    const Bytes32 h = l.finish();
    std::memcpy(buf_ + 32 * (field + 1), h.data(), 32);
  }
  Bytes32 hash() const noexcept { return keccak256(std::span<const std::uint8_t>(buf_, sizeof buf_)); }

 private:
  const TypeDef& t_;
  std::uint8_t buf_[32 * (N + 1)] = {};
};

class JsonList;

// One struct of the typed-data message as JSON: {"field": value, ...} in field order. Integers are decimal
// strings, addresses EIP-55 checksummed, like eth_signTypedData_v4 tooling prints them.
class JsonStruct {
 public:
  explicit JsonStruct(const TypeDef& t) : t_(t) {}
  Result<void> put(std::size_t field, const Value& v);
  template <std::size_t M>
  JsonList list(std::size_t, const TypeDef& item) const;
  void end_list(std::size_t field, JsonList& items);
  std::string finish();

 private:
  void key(std::size_t field);
  const TypeDef& t_;
  std::string out_;
};

// The JSON array of a struct list.
class JsonList {
 public:
  explicit JsonList(const TypeDef& item) : item_(item) {}
  JsonStruct open() const { return JsonStruct(item_); }
  void close(JsonStruct& item);
  std::string finish();

 private:
  const TypeDef& item_;
  std::string out_;
};

template <std::size_t M>
JsonList JsonStruct::list(std::size_t, const TypeDef& item) const {
  return JsonList(item);
}

// The whole eth_signTypedData_v4 document: types (EIP712Domain, the primary type, its nested types),
// primaryType, domain and the message JSON.
std::string typed_document(const TypeDef& primary, std::uint64_t chain_id, std::string_view message);

// EIP-55 mixed-case hex of a 20-byte address.
std::string checksum_address(std::span<const std::uint8_t, 20> addr);

// --- signature steps ----------------------------------------------------------------------------

// Explicit nonce and expiration, with signer address and chain id resolved from caller inputs.
struct Prepared {
  std::string_view address;  // ctx.signer->address()
  bool has_signer = false;   // the signature object names its signer already
  std::uint32_t nonce = 0;
  std::int64_t expiration = 0;
  std::uint64_t chain_id = 0;
};

// sig is null when the request has no signature object yet. Expiration 0 counts as absent.
template <class Sig>
Result<Prepared> prepare(const Sig* sig, const SignContext& ctx) {
  Prepared p;
  p.address =
      ctx.signer ? ctx.signer->address() : (sig && sig->signer ? std::string_view(*sig->signer) : std::string_view{});
  p.has_signer = sig && sig->signer && !sig->signer->empty();
  if (!sig || !sig->nonce || !sig->expiration || timestamp_ns(*sig->expiration) == 0)
    return Error::config("explicit signature nonce and expiration are required");
  p.nonce = *sig->nonce;
  p.expiration = timestamp_ns(*sig->expiration);
  // An explicit 0 means "Grvt's chain" on the server, as does a missing one: both resolve to the context's chain
  // here, so the digest, the typed data a wallet sees and the request all carry the same id.
  if (sig && sig->chain_id && *sig->chain_id != 0) {
    p.chain_id = *sig->chain_id;
  } else {
    if (ctx.chain_id == 0) return Error::config("this call needs a chain id: set SignContext::chain_id");
    p.chain_id = ctx.chain_id;
  }
  return p;
}

// The SigningRequest for a struct hash in the domain of chain_id (0: the context's), without typed data.
SigningRequest signing_request(const SignContext& ctx, std::uint64_t chain_id, const TypeDef& t,
                               const Bytes32& struct_hash) noexcept;
// typed_source/typed_render (for SigningRequest::typed_data()) are set by sign_hashed while the signer runs.
using TypedRender = Result<std::string> (*)(const void*);
// Check signature shape and invoke the caller verification callback when supplied.
Result<void> check(const SignContext& ctx, const SigningRequest& req, const RawSignature& sig);
// Require the caller verification callback for externally attached signatures.
Result<void> check_recovered(const SignContext& ctx, const SigningRequest& req, const RawSignature& sig);
// Has ctx.signer sign the struct hash and checks what it returns.
Result<RawSignature> sign_hashed(const SignContext& ctx, std::uint64_t chain_id, const TypeDef& t,
                                 const Bytes32& struct_hash, const void* typed_source = nullptr,
                                 TypedRender typed_render = nullptr);

// What a generated typed_<id> renderer reads: the request (or one bulk element), the context and the
// prepared signature values. Lives on the sign function's stack while the signer runs.
template <class Req>
struct TypedSource {
  const Req* req;
  const SignContext* ctx;
  Prepared p;
};

// One element of a per-element binding (bulk orders) between hashing and signing.
struct Pending {
  Prepared p;
  const TypeDef* st = nullptr;
  Bytes32 hash{};
  RawSignature sig;
};

// Sets an optional string to v, reusing its buffer.
inline void set_text(std::optional<std::string>& out, std::string_view v) {
  if (!out) {
    out.emplace(v);
  } else if (*out != v) {
    out->assign(v);
  }
}
// "0x" + hex of 32 bytes, reusing the buffer.
void set_hex(std::optional<std::string>& out, const Bytes32& bytes);

// Whether a signature object already holds every value prepare() fills in (what attaching a signature
// made elsewhere needs: the digest was computed with exactly these values).
template <class Sig>
bool fully_prepared(const Sig* sig) noexcept {
  return sig && sig->signer && !sig->signer->empty() && sig->nonce && sig->expiration &&
         timestamp_ns(*sig->expiration) != 0 && sig->chain_id;
}

// Writes the prepared signer, nonce, expiration and chain id into the signature object.
template <class Sig>
void commit_prepared(Sig& sig, const Prepared& p) {
  if (!p.has_signer) set_text(sig.signer, p.address);
  sig.nonce = p.nonce;
  sig.expiration = timestamp_from_ns(p.expiration);
  sig.chain_id = p.chain_id;
}

// Writes the signed signature object: the prepared values, r/s/v, and as signer what the signer reported
// (its address when it reported none).
template <class Sig>
void commit(Sig& sig, const Prepared& p, const RawSignature& s) {
  sig.nonce = p.nonce;
  sig.expiration = timestamp_from_ns(p.expiration);
  sig.chain_id = p.chain_id;
  set_text(sig.signer, s.signer.empty() ? p.address : std::string_view(s.signer));
  set_hex(sig.r, s.r);
  set_hex(sig.s, s.s);
  sig.v = s.v;
}

}  // namespace grvt::detail::sign
