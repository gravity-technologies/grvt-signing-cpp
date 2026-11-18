// Ethereum Keccak-256 against published vectors, and across the 136-byte block boundary.
#include <string>

#include "grvt/signing.hpp"
#include "test.hpp"

namespace {
std::string k(const std::string& s) { return grvt::hex0x(grvt::keccak256(s)); }
}  // namespace

TEST(keccak_published_vectors) {
  CHECK_EQ(k(""), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  CHECK_EQ(k("abc"), "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  CHECK_EQ(k("The quick brown fox jumps over the lazy dog"),
           "0x4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");
}

TEST(keccak_block_boundaries) {
  // From golang.org/x/crypto/sha3.NewLegacyKeccak256.
  CHECK_EQ(k(std::string(135, 'a')), "0x34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446");
  CHECK_EQ(k(std::string(136, 'a')), "0xa6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e");
  CHECK_EQ(k(std::string(137, 'a')), "0xd869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39");
  CHECK_EQ(k(std::string(200, 'a')), "0x96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d");
  CHECK_EQ(k(std::string(272, 'a')), "0xcf7fcd4f705ee749930d19ca84561a9bf62516bd90a471545fa2f49fdc7e63c8");
}

TEST(eip712_domain_type_hash) {
  CHECK_EQ(k("EIP712Domain(string name,string version,uint256 chainId)"),
           "0xc2f8787176b8ac6bf7215b4adcc1e069bf4ab82d9ab1df05a57a91d425935b6e");
}

#include "keccak.hpp"

TEST(keccak_in_pieces) {
  // Fed in uneven pieces across block boundaries, the incremental hash equals the one-shot hash.
  std::string data;
  for (int i = 0; i < 1000; ++i) data.push_back(static_cast<char>(i * 31 + 7));
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.data());
  for (std::size_t piece : {1u, 7u, 135u, 136u, 137u, 300u}) {
    grvt::detail::Keccak256 h;
    for (std::size_t off = 0; off < data.size(); off += piece) {
      h.update(std::span<const std::uint8_t>(bytes + off, std::min(piece, data.size() - off)));
    }
    CHECK_EQ(grvt::hex0x(h.finish()), k(data));
  }
}
