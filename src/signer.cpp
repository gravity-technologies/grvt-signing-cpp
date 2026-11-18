// secp256k1 through libsecp256k1 (recovery module). Kept out of the public headers.
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <cstring>
#include <random>

#include "grvt/signer.hpp"
#include "hex.hpp"

namespace grvt {

namespace {

const secp256k1_context* ctx() {
  static secp256k1_context* c = [] {
#ifdef SECP256K1_CONTEXT_NONE
    secp256k1_context* made = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
#else
    secp256k1_context* made = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
#endif
    // Blinding against side channels while signing.
    std::random_device rd;
    std::uint8_t seed[32];
    for (std::size_t i = 0; i < sizeof seed; i += 4) {
      const std::uint32_t r = rd();
      std::memcpy(seed + i, &r, 4);
    }
    // Fails only for a context that cannot sign at all; signing still works without blinding. (A plain
    // (void) cast does not silence warn_unused_result under GCC.)
    [[maybe_unused]] const int randomized = secp256k1_context_randomize(made, seed);
    return made;
  }();
  return c;
}

std::string address_of(const secp256k1_pubkey& key) {
  std::uint8_t raw[65];
  std::size_t len = sizeof raw;
  secp256k1_ec_pubkey_serialize(ctx(), raw, &len, &key, SECP256K1_EC_UNCOMPRESSED);
  const Bytes32 h = keccak256(std::span<const std::uint8_t>(raw + 1, 64));
  return hex0x(std::span<const std::uint8_t>(h.data() + 12, 20));
}

}  // namespace

namespace {

// Zeroes key bytes; the volatile writes keep the compiler from dropping them.
template <class Bytes>
void wipe(Bytes& b) noexcept {
  volatile std::uint8_t* p = b.data();
  for (std::size_t i = 0; i < b.size(); ++i) p[i] = 0;
}

}  // namespace

Result<PrivateKeySigner> PrivateKeySigner::from_hex(std::string_view private_key) {
  auto raw = detail::parse_hex(private_key);
  const bool ok = raw && raw->size() == 32;
  PrivateKeySigner s;
  if (ok) std::memcpy(s.key_.data(), raw->data(), 32);
  if (raw) wipe(*raw);
  if (!ok) return Error::config("private key is not 32 bytes of hex");
  secp256k1_pubkey pub;
  if (!secp256k1_ec_seckey_verify(ctx(), s.key_.data()) || !secp256k1_ec_pubkey_create(ctx(), &pub, s.key_.data())) {
    return Error::config("bad private key");
  }
  s.address_ = address_of(pub);
  return s;
}

PrivateKeySigner::~PrivateKeySigner() { wipe(key_); }

RawSignature PrivateKeySigner::sign_digest_raw(const Bytes32& digest) const noexcept {
  // libsecp256k1 always returns low-s.
  secp256k1_ecdsa_recoverable_signature sig;
  secp256k1_ecdsa_sign_recoverable(ctx(), &sig, digest.data(), key_.data(), nullptr, nullptr);
  std::uint8_t compact[64];
  int rec = 0;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx(), compact, &rec, &sig);
  RawSignature out;
  std::memcpy(out.r.data(), compact, 32);
  std::memcpy(out.s.data(), compact + 32, 32);
  out.v = static_cast<std::uint8_t>(27 + rec);
  return out;
}

Signature PrivateKeySigner::sign_digest(const Bytes32& digest) const {
  Signature s = to_signature(sign_digest_raw(digest));
  s.signer = address_;
  return s;
}

Result<Signature> PrivateKeySigner::sign(const SigningRequest& request) { return sign_digest(request.digest); }

Result<RawSignature> PrivateKeySigner::sign_raw(const SigningRequest& request) {
  return sign_digest_raw(request.digest);
}

std::optional<std::string> recover_address(const Bytes32& digest, const RawSignature& signature) {
  if (signature.v != 27 && signature.v != 28) return std::nullopt;
  std::uint8_t compact[64];
  std::memcpy(compact, signature.r.data(), 32);
  std::memcpy(compact + 32, signature.s.data(), 32);
  secp256k1_ecdsa_recoverable_signature sig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx(), &sig, compact, signature.v - 27)) return std::nullopt;
  secp256k1_pubkey pub;
  if (!secp256k1_ecdsa_recover(ctx(), &pub, &sig, digest.data())) return std::nullopt;
  return address_of(pub);
}

std::optional<std::string> recover_address(const Bytes32& digest, const Signature& signature) {
  auto r = detail::parse_hex(signature.r);
  auto s = detail::parse_hex(signature.s);
  if (!r || !s || r->size() != 32 || s->size() != 32 || (signature.v != 27 && signature.v != 28)) return std::nullopt;
  RawSignature raw;
  std::memcpy(raw.r.data(), r->data(), 32);
  std::memcpy(raw.s.data(), s->data(), 32);
  raw.v = signature.v;
  return recover_address(digest, raw);
}

namespace {
bool equal_fold(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; };
    if (lower(a[i]) != lower(b[i])) return false;
  }
  return true;
}
Error invalid(std::string_view address, const std::string& why) {
  return Error::signing("signer " + std::string(address) + " returned an invalid signature: " + why);
}
template <class Sig>
Result<void> verify(const Bytes32& digest, const Sig& sig, std::string_view address) {
  if (auto ok = check_signature_shape(sig, address); !ok) return ok;
  auto got = recover_address(digest, sig);
  if (!got || !equal_fold(*got, address)) {
    return invalid(address, "it recovers to " + got.value_or("no address") +
                                ", not to the signer address (wrong key, or a different message was signed)");
  }
  return {};
}
}  // namespace

Result<void> verify_signature(const Bytes32& digest, const Signature& sig, std::string_view address) {
  return verify(digest, sig, address);
}

Result<void> verify_signature(const Bytes32& digest, const RawSignature& sig, std::string_view address) {
  return verify(digest, sig, address);
}

}  // namespace grvt
