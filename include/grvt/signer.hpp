#pragma once
#include "grvt/signing.hpp"
namespace grvt {
// An in-process secp256k1 key (libsecp256k1). Also fits session keys. Never prints the key.
class PrivateKeySigner final : public Signer {
 public:
  // 32 bytes as hex, with or without 0x.
  static Result<PrivateKeySigner> from_hex(std::string_view private_key);

  PrivateKeySigner(const PrivateKeySigner&) = default;
  PrivateKeySigner& operator=(const PrivateKeySigner&) = default;
  ~PrivateKeySigner() override;

  std::string_view address() const override { return address_; }
  Result<Signature> sign(const SigningRequest& request) override;
  Result<RawSignature> sign_raw(const SigningRequest& request) override;
  Signature sign_digest(const Bytes32& digest) const;
  // No allocation, and safe to call from several threads at once (e.g. to sign the digests of
  // signing::digests_order_bulk_orders in parallel).
  RawSignature sign_digest_raw(const Bytes32& digest) const noexcept;

 private:
  PrivateKeySigner() = default;
  std::array<std::uint8_t, 32> key_{};
  std::string address_;
};

// The address that signed digest with r/s/v (27/28), or nullopt.
std::optional<std::string> recover_address(const Bytes32& digest, const Signature& signature);
std::optional<std::string> recover_address(const Bytes32& digest, const RawSignature& signature);
// check_signature_shape, plus the signature recovers to address (what SignContext::verify adds).
Result<void> verify_signature(const Bytes32& digest, const Signature& signature, std::string_view address);
Result<void> verify_signature(const Bytes32& digest, const RawSignature& signature, std::string_view address);

}  // namespace grvt
