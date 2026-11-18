// Count allocations for warmed signing paths using caller-owned inputs.
#include <cstdlib>
#include <new>
#include <string>

#include "../examples/inputs.hpp"
#include "grvt/grvt.hpp"
#include "test.hpp"

namespace {
std::size_t allocations = 0;
}  // namespace

void* operator new(std::size_t n) {
  ++allocations;
  void* p = std::malloc(n == 0 ? 1 : n);
  if (p == nullptr) std::abort();
  return p;
}
void* operator new[](std::size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

using namespace grvt;

namespace {

// Allocations per call of f once it has run a few times.
template <class F>
std::size_t steady(F f) {
  for (int i = 0; i < 3; ++i) f();
  const std::size_t before = allocations;
  for (int i = 0; i < 20; ++i) f();
  return allocations - before;
}

}  // namespace

TEST(digest_reuses_caller_objects) {
  auto order = reference::order();
  auto meta = reference::metadata();
  SignContext ctx;
  ctx.metadata = &meta;
  ctx.chain_id = 326;
  bool ok = true;
  CHECK_EQ(steady([&] { ok = ok && bool(signing::digest_order_create_order(order, ctx)); }), 0u);
  CHECK(ok);
}

#ifdef GRVT_WITH_SIGNER
#include "grvt/signer.hpp"
TEST(signing_reuses_caller_objects) {
  auto order = reference::order();
  auto meta = reference::metadata();
  auto key = PrivateKeySigner::from_hex(reference::test_key);
  REQUIRE_OK(key);
  SignContext ctx;
  ctx.metadata = &meta;
  ctx.chain_id = 326;
  ctx.signer = &*key;
  bool ok = true;
  CHECK_EQ(steady([&] { ok = ok && bool(signing::sign_order_create_order(order, ctx)); }), 0u);
  CHECK(ok);
}
#endif
