// Local microbenchmark; excludes network, metadata fetch, parsing and request construction.
#include <chrono>
#include <cstdio>
#include "inputs.hpp"
#ifdef GRVT_WITH_SIGNER
#include "grvt/signer.hpp"
#endif
int main() {
  auto order = reference::order();
  auto meta = reference::metadata();
  grvt::SignContext ctx;
  ctx.chain_id = 326;
  ctx.metadata = &meta;
  constexpr int count = 10000;
  auto run = [&](const char* label, auto fn) {
    for (int i = 0; i < 100; ++i)
      if (!fn()) return false;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < count; ++i)
      if (!fn()) return false;
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
    std::printf("%s: %.1f ns/op (%d iterations)\n", label, double(elapsed) / count, count);
    return true;
  };
  if (!run("order digest", [&] { return bool(grvt::signing::digest_order_create_order(order, ctx)); })) return 1;
#ifdef GRVT_WITH_SIGNER
  auto signer = grvt::PrivateKeySigner::from_hex(reference::test_key);
  if (!signer) return 2;
  ctx.signer = &*signer;
  if (!run("order digest + sign", [&] { return bool(grvt::signing::sign_order_create_order(order, ctx)); })) return 3;
#endif
}
