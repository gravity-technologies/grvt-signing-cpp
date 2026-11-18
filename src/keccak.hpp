// Incremental Keccak-256, for hashing data that arrives in pieces (an EIP-712 list hashes the
// concatenation of its item hashes) without buffering it all.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "grvt/signing.hpp"

namespace grvt::detail {

class Keccak256 {
 public:
  void update(std::span<const std::uint8_t> data) noexcept;
  Bytes32 finish() noexcept;

 private:
  static constexpr std::size_t RATE = 136;
  std::uint64_t state_[25] = {};
  std::uint8_t block_[RATE] = {};
  std::size_t used_ = 0;
};

}  // namespace grvt::detail
