// Keccak-256 as Ethereum uses it: Keccak-f[1600], rate 136 bytes, padding 0x01 ... 0x80 (SHA3-256 pads with
// 0x06 instead, so its digests differ). The permutation is unrolled by hand (theta, rho and pi, chi, iota
// per round); tests check it against published vectors.
#include "keccak.hpp"

#include <bit>
#include <cstring>

namespace grvt {

namespace {

constexpr std::uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL,
    0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

constexpr std::uint64_t rotl(std::uint64_t x, int n) { return std::rotl(x, n); }

void keccak_f(std::uint64_t a[25]) noexcept {
  for (int round = 0; round < 24; ++round) {
    const std::uint64_t c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    const std::uint64_t c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    const std::uint64_t c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    const std::uint64_t c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    const std::uint64_t c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    const std::uint64_t d0 = c4 ^ rotl(c1, 1);
    const std::uint64_t d1 = c0 ^ rotl(c2, 1);
    const std::uint64_t d2 = c1 ^ rotl(c3, 1);
    const std::uint64_t d3 = c2 ^ rotl(c4, 1);
    const std::uint64_t d4 = c3 ^ rotl(c0, 1);
    const std::uint64_t b0 = rotl(a[0] ^ d0, 0);
    const std::uint64_t b1 = rotl(a[6] ^ d1, 44);
    const std::uint64_t b2 = rotl(a[12] ^ d2, 43);
    const std::uint64_t b3 = rotl(a[18] ^ d3, 21);
    const std::uint64_t b4 = rotl(a[24] ^ d4, 14);
    const std::uint64_t b5 = rotl(a[3] ^ d3, 28);
    const std::uint64_t b6 = rotl(a[9] ^ d4, 20);
    const std::uint64_t b7 = rotl(a[10] ^ d0, 3);
    const std::uint64_t b8 = rotl(a[16] ^ d1, 45);
    const std::uint64_t b9 = rotl(a[22] ^ d2, 61);
    const std::uint64_t b10 = rotl(a[1] ^ d1, 1);
    const std::uint64_t b11 = rotl(a[7] ^ d2, 6);
    const std::uint64_t b12 = rotl(a[13] ^ d3, 25);
    const std::uint64_t b13 = rotl(a[19] ^ d4, 8);
    const std::uint64_t b14 = rotl(a[20] ^ d0, 18);
    const std::uint64_t b15 = rotl(a[4] ^ d4, 27);
    const std::uint64_t b16 = rotl(a[5] ^ d0, 36);
    const std::uint64_t b17 = rotl(a[11] ^ d1, 10);
    const std::uint64_t b18 = rotl(a[17] ^ d2, 15);
    const std::uint64_t b19 = rotl(a[23] ^ d3, 56);
    const std::uint64_t b20 = rotl(a[2] ^ d2, 62);
    const std::uint64_t b21 = rotl(a[8] ^ d3, 55);
    const std::uint64_t b22 = rotl(a[14] ^ d4, 39);
    const std::uint64_t b23 = rotl(a[15] ^ d0, 41);
    const std::uint64_t b24 = rotl(a[21] ^ d1, 2);
    a[0] = b0 ^ (~b1 & b2);
    a[1] = b1 ^ (~b2 & b3);
    a[2] = b2 ^ (~b3 & b4);
    a[3] = b3 ^ (~b4 & b0);
    a[4] = b4 ^ (~b0 & b1);
    a[5] = b5 ^ (~b6 & b7);
    a[6] = b6 ^ (~b7 & b8);
    a[7] = b7 ^ (~b8 & b9);
    a[8] = b8 ^ (~b9 & b5);
    a[9] = b9 ^ (~b5 & b6);
    a[10] = b10 ^ (~b11 & b12);
    a[11] = b11 ^ (~b12 & b13);
    a[12] = b12 ^ (~b13 & b14);
    a[13] = b13 ^ (~b14 & b10);
    a[14] = b14 ^ (~b10 & b11);
    a[15] = b15 ^ (~b16 & b17);
    a[16] = b16 ^ (~b17 & b18);
    a[17] = b17 ^ (~b18 & b19);
    a[18] = b18 ^ (~b19 & b15);
    a[19] = b19 ^ (~b15 & b16);
    a[20] = b20 ^ (~b21 & b22);
    a[21] = b21 ^ (~b22 & b23);
    a[22] = b22 ^ (~b23 & b24);
    a[23] = b23 ^ (~b24 & b20);
    a[24] = b24 ^ (~b20 & b21);
    a[0] ^= RC[round];
  }
}

std::uint64_t load_le(const std::uint8_t* p) noexcept {
  std::uint64_t v;
  std::memcpy(&v, p, 8);
  if constexpr (std::endian::native == std::endian::big) v = __builtin_bswap64(v);
  return v;
}

void absorb(std::uint64_t a[25], const std::uint8_t* block) noexcept {
  for (int i = 0; i < 17; ++i) a[i] ^= load_le(block + 8 * i);
  keccak_f(a);
}

Bytes32 squeeze(const std::uint64_t a[25]) noexcept {
  Bytes32 out{};
  for (int i = 0; i < 32; ++i) out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(a[i / 8] >> (8 * (i % 8)));
  return out;
}

}  // namespace

Bytes32 keccak256(std::span<const std::uint8_t> data) noexcept {
  detail::Keccak256 h;
  h.update(data);
  return h.finish();
}

Bytes32 keccak256(std::string_view data) noexcept {
  return keccak256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

namespace detail {

void Keccak256::update(std::span<const std::uint8_t> data) noexcept {
  const std::uint8_t* p = data.data();
  std::size_t n = data.size();
  if (used_ > 0) {
    const std::size_t take = n < RATE - used_ ? n : RATE - used_;
    std::memcpy(block_ + used_, p, take);
    used_ += take;
    p += take;
    n -= take;
    if (used_ < RATE) return;
    absorb(state_, block_);
    used_ = 0;
  }
  for (; n >= RATE; p += RATE, n -= RATE) absorb(state_, p);
  if (n > 0) std::memcpy(block_, p, n);
  used_ = n;
}

Bytes32 Keccak256::finish() noexcept {
  std::memset(block_ + used_, 0, RATE - used_);
  block_[used_] ^= 0x01;
  block_[RATE - 1] ^= 0x80;
  absorb(state_, block_);
  return squeeze(state_);
}

}  // namespace detail

}  // namespace grvt
