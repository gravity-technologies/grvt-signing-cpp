// Published conformance inputs. These are test values, never production credentials.
#pragma once
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
