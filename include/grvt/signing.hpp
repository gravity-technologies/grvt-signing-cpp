// EIP-712 signing inputs: the signer plug-in, the metadata a sign function reads, and the context it runs
// in. The generated sign functions (generated/signing.hpp) use these; the SDK signs only Grvt's own
// messages and has no generic EIP-712 API.
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "grvt/result.hpp"
#include "grvt/scalars.hpp"

namespace grvt {

using Bytes32 = std::array<std::uint8_t, 32>;

// Exact decimal x 10^decimals as integer text. Never rounds. Trailing fractional zeros
// are normalized before the precision check. Supported scale: 0..38; signed 128-bit result.
Result<std::string> scaled_decimal(std::string_view value, std::uint32_t decimals);

// Ethereum Keccak-256 (not SHA3-256: the padding differs).
Bytes32 keccak256(std::span<const std::uint8_t> data) noexcept;
Bytes32 keccak256(std::string_view data) noexcept;

// 0x-prefixed lowercase hex.
std::string hex0x(std::span<const std::uint8_t> bytes);

// keccak256(EIP712Domain(name "GRVT Exchange", version "0", chainId)). Cached per thread for the last
// chain id, so signing does not recompute it.
Bytes32 domain_separator(std::uint64_t chain_id) noexcept;

struct Signature {
  std::string signer;  // 0x-prefixed lowercase address
  std::string r;       // 0x-prefixed 32-byte hex
  std::string s;       // 0x-prefixed 32-byte hex, low-s (the server rejects high s, code 2007)
  std::uint8_t v = 0;  // 27 or 28
};

// The same signature as bytes. The sign functions keep a signature in this form until they write r and s
// into the request as hex.
struct RawSignature {
  Bytes32 r{};
  Bytes32 s{};
  std::uint8_t v = 0;  // 27 or 28
  // As Signature::signer: the address as the signer spells it, or empty for Signer::address(). It is what
  // the request's signature object gets as its signer.
  std::string signer;
};

// r and s as 0x-prefixed hex, v as is.
Signature to_signature(const RawSignature& raw);

// What a signer is asked to sign. Only `digest` is signed; the rest says what it is, for signers that log
// or check requests (KMS, HSM, hardware wallets).
struct SigningRequest {
  Bytes32 digest{};  // keccak256(0x1901 || domain_separator || struct_hash)
  Bytes32 struct_hash{};
  Bytes32 domain_separator{};
  std::uint64_t chain_id = 0;
  std::string_view primary_type;  // e.g. "Order"

  // The eth_signTypedData_v4 JSON of what is signed (types, primaryType, domain, message; integers as
  // decimal strings, addresses checksummed), for signers that sign typed data rather than a digest
  // (browser wallets, some KMS). Built only when called, and only on the request Signer::sign is given,
  // while it runs. A copy has none, and neither do requests from signing::digests_* (a config error), so a
  // request kept after signing cannot read freed memory.
  Result<std::string> typed_data() const;

  SigningRequest() = default;
  SigningRequest(const SigningRequest& o) noexcept { copy_from(o); }
  SigningRequest& operator=(const SigningRequest& o) noexcept {
    if (this != &o) copy_from(o);
    return *this;
  }

  // Set by the SDK for typed_data(); cleared on copy.
  const void* typed_source = nullptr;
  Result<std::string> (*typed_render)(const void*) = nullptr;

 private:
  void copy_from(const SigningRequest& o) noexcept {
    digest = o.digest;
    struct_hash = o.struct_hash;
    domain_separator = o.domain_separator;
    chain_id = o.chain_id;
    primary_type = o.primary_type;
    typed_source = nullptr;
    typed_render = nullptr;
  }
};

// The signer plug-in: the application signs a 32-byte digest (a local key, KMS, HSM, wallet). The SDK
// checks what it returns: 32-byte r and s, v 27 or 28, low-s (normalize a high s: s = n - s, flip v), and
// its signer field is empty or address(). Otherwise: a signing error. The signer only sees the digest the
// SDK computed, so it cannot sign a different message; whether it used the right key is checked only when
// SignContext::verify is set (one ecrecover per signature).
class Signer {
 public:
  virtual ~Signer() = default;
  // 0x-prefixed lowercase address.
  virtual std::string_view address() const = 0;
  virtual Result<Signature> sign(const SigningRequest& request) = 0;
  // What the sign functions call. The default calls sign(), checks the signature's shape and decodes its
  // hex; a signer that has bytes anyway (PrivateKeySigner) overrides it to skip the hex round trip.
  virtual Result<RawSignature> sign_raw(const SigningRequest& request);
};

// The check the SDK applies to every signature (see Signer); no recovery, so it does not prove the key.
Result<void> check_signature_shape(const Signature& signature, std::string_view address);
Result<void> check_signature_shape(const RawSignature& signature, std::string_view address);
// Caller-supplied encoding metadata for one instrument.
struct InstrumentMeta {
  std::string instrument_hash;
  std::uint32_t base_decimals = 0;
  std::uint32_t quote_decimals = 0;
};

// Caller-supplied currency encoding metadata.
struct CurrencyMeta {
  std::uint32_t id = 0;
  std::string symbol;
  std::uint32_t balance_decimals = 0;
};

// Metadata supplied and kept current by the application.
struct SigningMetadata {
  std::map<std::string, InstrumentMeta, std::less<>> instruments;
  std::map<std::string, CurrencyMeta, std::less<>> currencies;
  // Main account address for calls whose typed message includes it.
  std::optional<std::string> main_account;

  void add_currencies(const std::vector<CurrencyMeta>& list) {
    for (const auto& c : list) currencies[c.symbol] = c;
  }
};

// Metadata names read by one call (generated needs_<call>).
struct SigningNeeds {
  std::vector<std::string> instruments;
  std::vector<std::string> currencies;
  bool main_account = false;
};

struct SignContext {
  Signer* signer = nullptr;
  // May be null for calls whose needs are empty.
  const SigningMetadata* metadata = nullptr;
  // Explicit caller chain id; a nonzero signature chain_id takes precedence.
  std::uint64_t chain_id = 0;
  // Optional recovery check after the core checks shape and signer address. Required by bulk attach.
  // Must reject signatures that do not recover to the supplied address for this digest.
  // The libsecp256k1 adapter supplies verify_signature.
  Result<void> (*verify)(const Bytes32&, const RawSignature&, std::string_view) = nullptr;
};

}  // namespace grvt
