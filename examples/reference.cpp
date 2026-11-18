// Offline reference. Replace the print callback with your own HTTP transport.
#include <cstdio>
// Published conformance inputs. These are test values, never production credentials.
#include "grvt/grvt.hpp"
namespace reference {
inline auto order() {
  grvt::models::OrderLeg leg("BTC_USDT_Perp", *grvt::Decimal::parse("0.01"), true);
  leg.limit_price = *grvt::Decimal::parse("60000");
  grvt::models::OrderInput input(grvt::enums::TimeInForce::GOOD_TILL_TIME, std::vector<grvt::models::OrderLeg>{leg});
  input.sub_account_id = 8289849667772468ULL;
  input.is_market = false;
  input.post_only = true;
  input.reduce_only = false;
  input.metadata.emplace();
  input.metadata->client_order_id = (1ULL << 63) | 1001;  // API client ID range
  input.signature.emplace();
  input.signature->signer = "0x1267c6181aee40f5ddbd70c56ecf4613117326b5";
  input.signature->nonce = 1001;
  input.signature->expiration = grvt::timestamp_from_ns(4102444800000000000LL);
  input.signature->chain_id = 326;
  return grvt::models::ApiCreateOrderRequestInput(std::move(input));
}
inline grvt::SigningMetadata metadata() {
  grvt::SigningMetadata meta;
  meta.instruments["BTC_USDT_Perp"] = {"0x030501", 9, 6};
  return meta;
}
inline constexpr auto test_key = "0xbfe25ff07bd38cb3fbc28a2a296d41aabd68a78c929d257935906489fc9c6d89";
}  // namespace reference

#ifdef GRVT_WITH_SIGNER
#include "grvt/signer.hpp"
#endif

// The host owns HTTP, secrets, cookies and account state. Nothing is sent by this example.
using HostPost = void (*)(std::string_view path, std::string_view cookie, std::string_view account_id,
                          std::string_view body);
void print_wire(std::string_view path, std::string_view cookie, std::string_view account_id, std::string_view body) {
  std::printf("POST %.*s\n", int(path.size()), path.data());
  if (!cookie.empty()) std::printf("Cookie: %.*s\n", int(cookie.size()), cookie.data());
  if (!account_id.empty()) std::printf("X-Grvt-Account-Id: %.*s\n", int(account_id.size()), account_id.data());
  std::printf("%.*s\n", int(body.size()), body.data());
}
int main() {
  HostPost post = &print_wire;
  // API-key login wire shape. Read Set-Cookie gravity and X-Grvt-Account-Id from the
  // real response in the host. Never print real keys or cookies in production logs.
  post("/auth/api_key/login", {}, {}, R"({"api_key":"REPLACE_IN_HOST"})");
  auto order = reference::order();
  auto meta = reference::metadata();
  grvt::SignContext ctx;
  ctx.chain_id = 326;  // caller selects the chain; the core has no environment lookup
  ctx.metadata = &meta;
  auto digest = grvt::signing::digest_order_create_order(order, ctx);
  if (!digest) return 1;
  std::printf("digest: %s\n", grvt::hex0x(digest->digest).c_str());
#ifdef GRVT_WITH_SIGNER
  auto signer = grvt::PrivateKeySigner::from_hex(reference::test_key);
  if (!signer) return 2;
  ctx.signer = &*signer;
  ctx.verify = &grvt::verify_signature;
  if (!grvt::signing::sign_order_create_order(order, ctx)) return 3;
  post("/full/v1/create_order", "gravity=HOST_COOKIE", "HOST_ACCOUNT_ID", grvt::encode(order));
#endif
  // If a write times out after sending, its result is unknown. Keep client_order_id
  // and reconcile with get_order/order history. An absent lookup does not prove that
  // the order was rejected. Keep the result unknown and never automatically resend.
  // A fresh nonce is not a retry guarantee. The host owns this policy and its storage.
  std::puts("unknown write: reconcile by client_order_id; absent lookup stays unknown; never automatically resend");
  return 0;
}
