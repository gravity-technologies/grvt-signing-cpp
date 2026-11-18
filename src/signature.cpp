#include <cstring>
#include "grvt/signing.hpp"
#include "hex.hpp"
namespace grvt {
namespace {
// Half the secp256k1 group order: a valid signature has s <= HALF_ORDER (low-s).
constexpr std::uint8_t HALF_ORDER[32] = {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4,
                                         0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0};

bool equal_fold(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
    if (x != y) return false;
  }
  return true;
}

}  // namespace
std::string hex0x(std::span<const std::uint8_t> bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out = "0x";
  out.reserve(2 + 2 * bytes.size());
  for (const auto b : bytes) {
    out += digits[b >> 4];
    out += digits[b & 0xF];
  }
  return out;
}

Signature to_signature(const RawSignature& raw) { return Signature{raw.signer, hex0x(raw.r), hex0x(raw.s), raw.v}; }

Result<std::string> SigningRequest::typed_data() const {
  if (typed_render == nullptr) return Error::config("no typed data for this signing request (from signing::digests_*)");
  return typed_render(typed_source);
}

Result<RawSignature> Signer::sign_raw(const SigningRequest& request) {
  auto s = sign(request);
  if (!s) return std::move(s).error();
  if (auto ok = check_signature_shape(*s, address()); !ok) return std::move(ok).error();
  const auto r = detail::parse_hex(s->r);
  const auto sv = detail::parse_hex(s->s);
  if (!r || !sv) return Error::signing("signer returned r or s that is not hex");
  RawSignature raw;
  std::memcpy(raw.r.data(), r->data(), 32);
  std::memcpy(raw.s.data(), sv->data(), 32);
  raw.v = s->v;
  raw.signer = std::move(s->signer);
  return raw;
}

namespace {
Error invalid(std::string_view address, const std::string& why) {
  return Error::signing("signer " + std::string(address) + " returned an invalid signature: " + why);
}
}  // namespace

namespace {
Result<void> check_shape(const std::uint8_t* r, const std::uint8_t* s, std::uint8_t v, const std::string& signer,
                         std::string_view address) {
  if (v != 27 && v != 28) return invalid(address, "v must be 27 or 28, got " + std::to_string(v));
  constexpr std::uint8_t ORDER[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
                                      0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
  auto zero = [](const std::uint8_t* bytes) {
    std::uint8_t bits = 0;
    for (int i = 0; i < 32; ++i) bits |= bytes[i];
    return bits == 0;
  };
  if (zero(r) || std::memcmp(r, ORDER, 32) >= 0) return invalid(address, "r is outside the curve order");
  if (zero(s)) return invalid(address, "s is zero");
  if (address.size() != 42 || address.substr(0, 2) != "0x")
    return invalid(address, "signer address is not 20 bytes of hex");
  for (char c : address.substr(2))
    if (!detail::nibble(c)) return invalid(address, "signer address is not 20 bytes of hex");
  if (std::memcmp(s, HALF_ORDER, 32) > 0) return invalid(address, "s is not low-s");
  if (!signer.empty() && !equal_fold(signer, address)) {
    return invalid(address, "its signer field " + signer + " is not the signer address");
  }
  return {};
}

}  // namespace
Result<void> check_signature_shape(const Signature& sig, std::string_view address) {
  auto r = detail::parse_hex(sig.r);
  auto s = detail::parse_hex(sig.s);
  if (!r || !s || r->size() != 32 || s->size() != 32) return invalid(address, "r and s must be 32 bytes of hex");
  return check_shape(r->data(), s->data(), sig.v, sig.signer, address);
}

Result<void> check_signature_shape(const RawSignature& sig, std::string_view address) {
  return check_shape(sig.r.data(), sig.s.data(), sig.v, sig.signer, address);
}

Bytes32 domain_separator(std::uint64_t chain_id) noexcept {
  struct Cached {
    std::uint64_t chain_id = 0;
    bool set = false;
    Bytes32 separator{};
  };
  thread_local Cached last;
  if (last.set && last.chain_id == chain_id) return last.separator;
  std::uint8_t buf[128] = {};
  const Bytes32 type_hash = keccak256("EIP712Domain(string name,string version,uint256 chainId)");
  const Bytes32 name = keccak256("GRVT Exchange");
  const Bytes32 version = keccak256("0");
  std::memcpy(buf, type_hash.data(), 32);
  std::memcpy(buf + 32, name.data(), 32);
  std::memcpy(buf + 64, version.data(), 32);
  for (int i = 0; i < 8; ++i) buf[127 - i] = static_cast<std::uint8_t>(chain_id >> (8 * i));
  last.separator = keccak256(std::span<const std::uint8_t>(buf, sizeof buf));
  last.chain_id = chain_id;
  last.set = true;
  return last.separator;
}

}  // namespace grvt
