// JSON codecs: exact decimals, 64-bit integers as strings, unknown enums kept, required fields enforced,
// explicit null versus omitted where the contract distinguishes (required nullable fields).
#include <string>

#include "grvt/grvt.hpp"
#include "json.hpp"
#include "test.hpp"

using namespace grvt;

TEST(decimal_text_is_exact) {
  auto leg = decode<models::OrderLeg>(
      R"({"instrument":"BTC_USDT_Perp","is_buying_asset":false,"size":"0.1234567890123456789012345678901234","limit_price":"65000.10"})");
  REQUIRE_OK(leg);
  CHECK_EQ(leg->size.text(), "0.1234567890123456789012345678901234");
  CHECK_EQ(leg->limit_price->text(), "65000.10");
  CHECK_EQ(
      encode(*leg),
      R"({"instrument":"BTC_USDT_Perp","size":"0.1234567890123456789012345678901234","limit_price":"65000.10","is_buying_asset":false})");
  for (const char* bad : {"abc", "1.2.3", "1e5", "01", ".5", "5.", "+1", ""}) {
    auto r =
        decode<models::OrderLeg>(std::string(R"({"instrument":"X","is_buying_asset":true,"size":")") + bad + "\"}");
    CHECK_MSG(!r, bad);
  }
  CHECK(!decode<models::OrderLeg>(R"({"instrument":"X","is_buying_asset":true,"size":1.5})"));
}

TEST(decimal_compares_numerically) {
  CHECK(*Decimal::parse("10.0") == *Decimal::parse("10"));
  CHECK(*Decimal::parse("-0") == Decimal());
  CHECK(*Decimal::parse("9.99") < *Decimal::parse("10"));
  CHECK(*Decimal::parse("-2") < *Decimal::parse("-1.5"));
  CHECK_EQ(Decimal::parse("0.000")->sign(), 0);
  CHECK_EQ(Decimal::parse("-0.01")->sign(), -1);
  CHECK_EQ(Decimal().text(), "0");
}

TEST(unknown_enum_values_are_kept) {
  auto order = decode<models::OrderInput>(R"({"time_in_force":"FUTURE_TIF","legs":[]})");
  REQUIRE_OK(order);
  CHECK(order->time_in_force.is_unknown());
  CHECK_EQ(order->time_in_force.wire(), "FUTURE_TIF");
  CHECK(!order->time_in_force.code());
  CHECK(encode(*order).find(R"("time_in_force":"FUTURE_TIF")") != std::string::npos);
  enums::TimeInForce known = enums::TimeInForce::GOOD_TILL_TIME;
  CHECK(known == enums::TimeInForce::GOOD_TILL_TIME);
  CHECK_EQ(known.wire(), "GOOD_TILL_TIME");
  CHECK_EQ(*known.code(), 1);
  CHECK(enums::TimeInForce::from_wire("GOOD_TILL_TIME") == known);
}

TEST(round_trip_is_stable) {
  models::OrderLeg leg("BTC_USDT_Perp", *Decimal::parse("0.010"), true);
  leg.limit_price = *Decimal::parse("60000");
  auto back = decode<models::OrderLeg>(encode(leg));
  REQUIRE_OK(back);
  CHECK(*back == leg);
  CHECK_EQ(back->size.text(), "0.010");
}

TEST(json_reader_keeps_number_text) {
  auto v = detail::json::parse(R"({"a":12345678901234567890123,"b":"é😀"})");
  REQUIRE_OK(v);
  CHECK_EQ(v->find("a")->text, "12345678901234567890123");
  CHECK_EQ(v->find("b")->text, "\xc3\xa9\xf0\x9f\x98\x80");
  CHECK(!detail::json::parse("{\"a\":1,}"));
  // Two readings of one field, and invalid UTF-8, are rejected.
  CHECK(!detail::json::parse(R"({"a":1,"a":2})"));
  CHECK(!decode<models::OrderLeg>(R"({"instrument":"X","size":"1","size":"2","is_buying_asset":true})"));
  for (const char* bad : {"\xff", "\xc0\xaf", "\xe0\x80\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xc3", "\xe2\x82"}) {
    CHECK_MSG(!detail::json::parse(std::string("\"") + bad + "\""), "invalid UTF-8 accepted");
  }
  auto ok = detail::json::parse("\"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\"");
  CHECK(ok && ok->text == "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80");
  CHECK(!detail::json::parse(std::string(200, '[') + std::string(200, ']')));
}

TEST(reader_rejects_repeated_keys_however_spelled) {
  // A known key spelled with an escape is still the same key.
  CHECK(!decode<models::OrderLeg>(R"({"instrument":"X","size":"1","\u0073ize":"2","is_buying_asset":true})"));
  // Unknown keys too, in the object itself and in skipped values.
  CHECK(!decode<models::OrderLeg>(R"({"instrument":"X","size":"1","is_buying_asset":true,"zz":1,"\u007a\u007a":2})"));
  CHECK(!decode<models::OrderLeg>(
      R"({"instrument":"X","size":"1","is_buying_asset":true,"zz":{"a":1,"b":{"a":1},"a":2}})"));
  CHECK(decode<models::OrderLeg>(
      R"({"instrument":"X","size":"1","is_buying_asset":true,"zz":{"a":1,"b":{"a":1}},"a":3})"));
  // More unknown keys than the reader keeps inline.
  std::string many = R"({"instrument":"X","size":"1","is_buying_asset":true)";
  for (int i = 0; i < 80; ++i) many += ",\"k" + std::to_string(i) + "\":{\"x\\u0031\":" + std::to_string(i) + "}";
  CHECK(decode<models::OrderLeg>(many + "}"));
  CHECK(!decode<models::OrderLeg>(many + ",\"k3\":0}"));
  CHECK(!decode<models::OrderLeg>(many + ",\"\\u006b40\":0}"));
  // A large object inside a large object: each checks only its own keys, before and after the inner one.
  std::string inner = "{";
  for (int i = 0; i < 50; ++i) inner += std::string(i ? "," : "") + "\"k" + std::to_string(i) + "\":0";
  CHECK(decode<models::OrderLeg>(many + ",\"in\":" + inner + "},\"k80\":0}"));
  CHECK(!decode<models::OrderLeg>(many + ",\"in\":" + inner + ",\"k7\":1}}"));
  CHECK(!decode<models::OrderLeg>(many + ",\"in\":" + inner + "},\"k7\":0}"));
  CHECK(!decode<models::OrderLeg>(many + ",\"in\":" + inner + "},\"in\":0}"));
}
