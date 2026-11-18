// Replays every server-produced signing case in sdk/scenarios/signing.json through the generated sign functions:
// equal domain separator, struct hash, digest, r/s/v, signature object and signed request; a reject case
// fails before anything is signed.
#include <set>
#include <string>
#include <vector>

#include "grvt/grvt.hpp"
#include "grvt/signer.hpp"
#include "json.hpp"
#include "test.hpp"
#include "test_bindings.hpp"

using namespace grvt;
namespace json = grvt::detail::json;

namespace {

// Signs with a real key, records what it was asked, and goes through the SDK's external-signer check.
class RecordingSigner : public Signer {
 public:
  explicit RecordingSigner(PrivateKeySigner key) : key_(std::move(key)) {}
  std::string_view address() const override { return key_.address(); }
  Result<Signature> sign(const SigningRequest& r) override {
    seen.push_back(r);
    primary.emplace_back(r.primary_type);
    auto td = r.typed_data();
    typed.push_back(td ? *td : "error: " + td.error().message);
    return key_.sign_digest(r.digest);
  }
  std::vector<SigningRequest> seen;
  std::vector<std::string> primary;
  std::vector<std::string> typed;

 private:
  PrivateKeySigner key_;
};

bool json_equal(const json::Value& a, const json::Value& b) {
  if (a.kind != b.kind) return false;
  switch (a.kind) {
    case json::Kind::null: return true;
    case json::Kind::boolean: return a.boolean == b.boolean;
    case json::Kind::number:
    case json::Kind::string: return a.text == b.text;
    case json::Kind::array:
      if (a.items.size() != b.items.size()) return false;
      for (std::size_t i = 0; i < a.items.size(); ++i) {
        if (!json_equal(a.items[i], b.items[i])) return false;
      }
      return true;
    case json::Kind::object:
      if (a.members.size() != b.members.size()) return false;
      for (const auto& m : a.members) {
        const auto* o = b.find(m.key);
        if (!o || !json_equal(m.value, *o)) return false;
      }
      return true;
  }
  return false;
}

bool json_text_equal(std::string_view a, const json::Value& b) {
  auto pa = json::parse(a);
  return pa && json_equal(*pa, b);
}

std::string str(const json::Value* v) { return v && v->is_string() ? v->text : std::string(); }
std::uint64_t num(const json::Value* v) { return v ? std::stoull(v->text) : 0; }

SigningMetadata metadata_of(const json::Value& meta) {
  SigningMetadata m;
  if (const auto* list = meta.find("instruments")) {
    for (const auto& i : list->items) {
      InstrumentMeta im;
      im.instrument_hash = str(i.find("instrument_hash"));
      im.base_decimals = static_cast<std::uint32_t>(num(i.find("base_decimals")));
      im.quote_decimals = static_cast<std::uint32_t>(num(i.find("quote_decimals")));

      m.instruments[str(i.find("instrument"))] = im;
    }
  }
  if (const auto* list = meta.find("currencies")) {
    for (const auto& c : list->items) {
      m.currencies[str(c.find("symbol"))] =
          CurrencyMeta{static_cast<std::uint32_t>(num(c.find("id"))), str(c.find("symbol")),
                       static_cast<std::uint32_t>(num(c.find("balance_decimals")))};
    }
  }
  if (const auto* a = meta.find("main_account_id")) m.main_account = a->text;
  return m;
}

struct Outcome {
  Result<std::string> signed_json = Error::config("not run");
  SigningNeeds needs;
};

template <class Op>
Outcome sign_wire(const json::Value& wire, Signer& signer, const SigningMetadata& meta, bool check_orders = true,
                  bool recover_signer = false) {
  Outcome out;
  auto req = decode<typename Op::Request>(wire.raw);
  if (!req) {
    out.signed_json = req.error();
    return out;
  }
  // The typed request re-encodes to the same wire JSON.
  if (!json_text_equal(encode(*req), wire))
    test::fail(__FILE__, __LINE__, "re-encoding changed " + std::string(Op::spec.id));
  out.needs = Op::needs(*req);
  SignContext ctx;
  ctx.signer = &signer;
  ctx.metadata = &meta;
  ctx.chain_id = 326;
  (void)check_orders;
  ctx.verify =
      recover_signer
          ? static_cast<Result<void> (*)(const Bytes32&, const RawSignature&, std::string_view)>(&verify_signature)
          : nullptr;
  const auto before = *req;
  if (auto r = Op::sign(*req, ctx); !r) {
    if (!(*req == before)) test::fail(__FILE__, __LINE__, "a failed sign changed the request");
    out.signed_json = r.error();
    return out;
  }
  out.signed_json = encode(*req);
  return out;
}

Outcome sign_case(std::string_view rpc, const json::Value& wire, Signer& signer, const SigningMetadata& meta) {
  if (rpc == "order.create_order") return sign_wire<api::create_order>(wire, signer, meta);
  if (rpc == "order.bulk_orders") return sign_wire<api::bulk_orders>(wire, signer, meta);
  if (rpc == "transfer.transfer") return sign_wire<api::transfer>(wire, signer, meta);
  if (rpc == "transfer.withdrawal") return sign_wire<api::withdrawal>(wire, signer, meta);
  if (rpc == "edge.wallet_login") return sign_wire<api::edge_wallet_login>(wire, signer, meta);
  if (rpc == "derisk_mm_ratio.set_derisk_mm_ratio") return sign_wire<api::set_derisk_mm_ratio>(wire, signer, meta);
  if (rpc == "position.add_position_margin") return sign_wire<api::add_position_margin>(wire, signer, meta);
  if (rpc == "position.set_position_config") return sign_wire<api::set_position_config>(wire, signer, meta);
  if (rpc == "vault.vault_burn_tokens") return sign_wire<api::vault_burn_tokens>(wire, signer, meta);
  if (rpc == "vault.vault_invest") return sign_wire<api::vault_invest>(wire, signer, meta);
  if (rpc == "vault.vault_redeem") return sign_wire<api::vault_redeem>(wire, signer, meta);
  Outcome o;
  o.signed_json = Error::config("no binding for " + std::string(rpc));
  return o;
}

// One signature against its signing case steps.
void check_steps(const std::string& name, const RecordingSigner& signer, std::size_t i, const std::string& signed_type,
                 const json::Value& steps, const json::Value& sig) {
  if (i >= signer.seen.size()) {
    test::fail(__FILE__, __LINE__, name + ": not signed");
    return;
  }
  const auto& seen = signer.seen[i];
  CHECK_MSG(signer.primary[i] == signed_type, name);
  CHECK_MSG(hex0x(seen.domain_separator) == str(steps.find("domain_separator")), name + ": domain separator");
  CHECK_MSG(hex0x(seen.struct_hash) == str(steps.find("struct_hash")), name + ": struct hash");
  CHECK_MSG(hex0x(seen.digest) == str(steps.find("digest")), name + ": digest");
  // A wallet given typed_data() signs the same message (eth_signTypedData_v4 JSON, as the server made it).
  CHECK_MSG(json_text_equal(signer.typed[i], *steps.find("typed_data")), name + ": typed data " + signer.typed[i]);
  // The kept copy of the request has no typed data: it would point at a request that no longer exists.
  CHECK_MSG(!seen.typed_data() && seen.typed_data().error().kind == ErrorKind::config, name + ": copy has typed data");
  CHECK_MSG(str(sig.find("r")) == str(steps.find("r")) && str(sig.find("s")) == str(steps.find("s")), name + ": r/s");
  CHECK_MSG(sig.find("v") && sig.find("v")->text == steps.find("v")->text, name + ": v");
  CHECK_MSG(json_equal(sig, *steps.find("signature")), name + ": signature object");
  // The signature recovers to the test key.
  Signature s{str(sig.find("signer")), str(sig.find("r")), str(sig.find("s")),
              static_cast<std::uint8_t>(num(sig.find("v")))};
  CHECK_MSG(recover_address(seen.digest, s) == std::optional<std::string>(std::string(signer.address())),
            name + ": recovery");
}

struct SigningCases {
  std::string text;
  json::Value root;
};

const SigningCases& signing_cases() {
  static SigningCases v = [] {
    SigningCases out;
    out.text = test::read_file(GRVT_SIGNING_CASES_FILE);
    auto parsed = json::parse(out.text);
    if (parsed) out.root = std::move(*parsed);
    return out;
  }();
  return v;
}

PrivateKeySigner test_key() {
  return *PrivateKeySigner::from_hex(str(signing_cases().root.find("test_key")->find("private_key")));
}

}  // namespace

TEST(test_key_address) {
  const auto& tk = *signing_cases().root.find("test_key");
  auto key = PrivateKeySigner::from_hex(str(tk.find("private_key")));
  REQUIRE_OK(key);
  CHECK_EQ(std::string(key->address()), str(tk.find("address")));
  CHECK(!PrivateKeySigner::from_hex("0x00"));
  CHECK(!PrivateKeySigner::from_hex(std::string(64, '0')));
}

TEST(every_signing_case) {
  const auto& list = signing_cases().root.find("cases")->items;
  CHECK_EQ(list.size(), 20u);
  std::set<std::string> rpcs;
  for (const auto& vec : list) {
    const std::string name = str(vec.find("name"));
    const std::string rpc = str(vec.find("rpc"));
    rpcs.insert(rpc);
    const auto& inputs = *vec.find("inputs");
    CHECK_EQ(num(inputs.find("env_chain_id")), 326);
    const SigningMetadata meta = metadata_of(*inputs.find("metadata"));
    RecordingSigner signer(test_key());
    Outcome out = sign_case(rpc, *inputs.find("wire_request"), signer, meta);
    for (const auto& n : out.needs.instruments)
      CHECK_MSG(meta.instruments.count(n) == 1, name + ": needs instrument " + n);
    for (const auto& c : out.needs.currencies) CHECK_MSG(meta.currencies.count(c) == 1, name + ": needs currency " + c);
    CHECK_MSG(out.needs.main_account == meta.main_account.has_value(), name + ": needs main account");

    // The same case through PrivateKeySigner directly (no external-signer check) signs the same bytes.
    PrivateKeySigner direct = test_key();
    Outcome fast = sign_case(rpc, *inputs.find("wire_request"), direct, meta);
    CHECK_MSG(out.signed_json.ok() == fast.signed_json.ok(), name + ": fast path verdict");
    if (out.signed_json && fast.signed_json)
      CHECK_MSG(*out.signed_json == *fast.signed_json, name + ": fast path bytes");

    if (str(vec.find("expect")) == "reject") {
      CHECK_MSG(!out.signed_json, name + ": expected a signing error");
      if (!out.signed_json) {
        CHECK_MSG(out.signed_json.error().kind == ErrorKind::signing, name);
        CHECK_MSG(out.signed_json.error().message.find("decimal places") != std::string::npos,
                  out.signed_json.error().message);
      }
      CHECK_MSG(signer.seen.empty(), name + ": refused before signing");
      continue;
    }
    if (!out.signed_json) {
      test::fail(__FILE__, __LINE__, name + ": " + out.signed_json.error().describe());
      continue;
    }
    auto signed_value = json::parse(*out.signed_json);
    REQUIRE_OK(signed_value);
    if (const auto* elements = vec.find("elements")) {
      CHECK_MSG(signer.seen.size() == elements->items.size(), name + ": one signature per element");
      for (std::size_t i = 0; i < elements->items.size(); ++i) {
        const auto& el = elements->items[i];
        const auto& sig = *signed_value->find("orders")->items[i].find("signature");
        check_steps(name + " " + str(el.find("path")), signer, i, str(el.find("signed_type")), *el.find("steps"), sig);
      }
      CHECK_MSG(json_equal(*signed_value, *vec.find("signed_request")), name + ": signed request");
      continue;
    }
    const auto& steps = *vec.find("steps");
    const auto& sig = rpc == "order.create_order" ? *signed_value->find("order")->find("signature")
                                                  : *signed_value->find("signature");
    check_steps(name, signer, 0, str(vec.find("signed_type")), steps, sig);
    CHECK_MSG(json_equal(*signed_value, *steps.find("signed_request")), name + ": signed request " + *out.signed_json);
  }
  const std::set<std::string> expected = {"derisk_mm_ratio.set_derisk_mm_ratio",
                                          "position.add_position_margin",
                                          "position.set_position_config",
                                          "vault.vault_burn_tokens",
                                          "vault.vault_invest",
                                          "vault.vault_redeem",
                                          "order.bulk_orders",
                                          "order.create_order",
                                          "transfer.transfer",
                                          "transfer.withdrawal",
                                          "edge.wallet_login"};
  CHECK(rpcs == expected);
}

namespace {
// Signs other bytes than it is asked to.
class Liar : public Signer {
 public:
  std::string_view address() const override { return key.address(); }
  Result<Signature> sign(const SigningRequest&) override {
    Bytes32 other{};
    other.fill(7);
    return key.sign_digest(other);
  }
  PrivateKeySigner key = test_key();
};

// Returns a high-s signature, which the server would reject.
class HighS : public Signer {
 public:
  std::string_view address() const override { return key.address(); }
  Result<Signature> sign(const SigningRequest& request) override {
    Signature sig = key.sign_digest(request.digest);
    sig.s = "0xffffffffffffffffffffffffffffffffbaaedce6af48a03bbfd25e8cd0364140";
    return sig;
  }
  PrivateKeySigner key = test_key();
};
}  // namespace

TEST(wrong_external_signature_is_refused) {
  for (const auto& vec : signing_cases().root.find("cases")->items) {
    if (str(vec.find("rpc")) != "edge.wallet_login") continue;
    Liar liar;
    const auto& inputs = *vec.find("inputs");
    const auto meta = metadata_of(*inputs.find("metadata"));
    // Without recovery only the shape is checked, which a well-formed wrong signature passes.
    CHECK(sign_wire<api::edge_wallet_login>(*inputs.find("wire_request"), liar, meta).signed_json);
    Outcome out = sign_wire<api::edge_wallet_login>(*inputs.find("wire_request"), liar, meta, true, true);
    CHECK(!out.signed_json);
    if (!out.signed_json)
      CHECK(out.signed_json.error().message.find("invalid signature: it recovers to") != std::string::npos);
    HighS high;
    Outcome shape = sign_wire<api::edge_wallet_login>(*inputs.find("wire_request"), high, meta);
    CHECK(!shape.signed_json);
    if (!shape.signed_json) CHECK(shape.signed_json.error().message.find("s is not low-s") != std::string::npos);
    return;
  }
  test::fail(__FILE__, __LINE__, "no wallet_login signing case");
}

TEST(signing_without_signer_or_metadata) {
  auto order = decode<models::ApiCreateOrderRequestInput>(
      R"({"order":{"sub_account_id":"1","time_in_force":"GOOD_TILL_TIME","legs":[{"instrument":"BTC_USDT_Perp","size":"1","limit_price":"1","is_buying_asset":true}]}})");
  REQUIRE_OK(order);
  SignContext ctx;
  ctx.chain_id = 326;
  auto r = api::create_order::sign(*order, ctx);
  CHECK(!r && r.error().kind == ErrorKind::config);
  auto key = test_key();
  ctx.signer = &key;
  order->order.signature.emplace();
  order->order.signature->nonce = 1;
  order->order.signature->expiration = timestamp_from_ns(100);
  auto missing = api::create_order::sign(*order, ctx);
  CHECK(!missing && missing.error().message == "no metadata for instrument \"BTC_USDT_Perp\"");
  CHECK(order->order.signature && !order->order.signature->r);
}

namespace {
const json::Value* bulk_case() {
  for (const auto& vec : signing_cases().root.find("cases")->items) {
    if (str(vec.find("rpc")) == "order.bulk_orders" && str(vec.find("expect")) != "reject") return &vec;
  }
  return nullptr;
}
}  // namespace

TEST(bulk_orders_in_two_steps) {
  // digests_ + signing elsewhere + attach_ writes the same request as sign_order_bulk_orders.
  const auto* vec = bulk_case();
  if (!vec) {
    test::fail(__FILE__, __LINE__, "no bulk_orders signing case");
    return;
  }
  const auto& inputs = *vec->find("inputs");
  const SigningMetadata meta = metadata_of(*inputs.find("metadata"));
  auto key = test_key();
  SignContext ctx{&key, &meta, 326};
  ctx.verify = &verify_signature;
  auto one = decode<models::ApiBulkOrdersRequestInput>(inputs.find("wire_request")->raw);
  REQUIRE_OK(one);
  auto two = *one;
  auto bare = *one;
  REQUIRE_OK(signing::sign_order_bulk_orders(*one, ctx));

  // attach_ before digests_: the elements have no prepared signature.
  for (auto& o : *bare.orders) o.signature.reset();
  const auto bare_before = bare;
  std::vector<RawSignature> none(bare.orders->size());
  auto early = signing::attach_order_bulk_orders(bare, ctx, none);
  CHECK(!early && early.error().kind == ErrorKind::config);
  CHECK(bare == bare_before);

  // attach_ checks signers even when the context does not ask for recovery.
  std::vector<SigningRequest> requests;
  REQUIRE_OK(signing::digests_order_bulk_orders(two, ctx, requests));
  CHECK_EQ(requests.size(), two.orders->size());
  // Typed data lives only while a signer runs inside sign_*.
  CHECK(!requests.empty() && !requests[0].typed_data() && requests[0].typed_data().error().kind == ErrorKind::config);
  std::vector<RawSignature> sigs;
  for (const auto& r : requests) sigs.push_back(key.sign_digest_raw(r.digest));
  const auto prepared = two;

  // Wrong count, and a signature of other bytes, are refused without writing anything.
  auto short_list =
      signing::attach_order_bulk_orders(two, ctx, std::span<const RawSignature>(sigs).first(sigs.size() - 1));
  CHECK(!short_list && short_list.error().kind == ErrorKind::config);
  auto swapped = sigs;
  Bytes32 other{};
  other.fill(9);
  swapped.back() = key.sign_digest_raw(other);
  CHECK(!signing::attach_order_bulk_orders(two, ctx, swapped));
  CHECK(two == prepared);
  // Signatures in the wrong order are refused too.
  if (sigs.size() > 1) {
    auto reordered = sigs;
    std::swap(reordered.front(), reordered.back());
    CHECK(!signing::attach_order_bulk_orders(two, ctx, reordered));
    CHECK(two == prepared);
  }

  REQUIRE_OK(signing::attach_order_bulk_orders(two, ctx, sigs));
  CHECK_EQ(encode(two), encode(*one));
}

TEST(raw_and_hex_signatures_agree) {
  auto key = test_key();
  Bytes32 digest = keccak256(std::string_view("grvt"));
  const RawSignature raw = key.sign_digest_raw(digest);
  const Signature hex = key.sign_digest(digest);
  const Signature converted = to_signature(raw);
  CHECK_EQ(converted.r, hex.r);
  CHECK_EQ(converted.s, hex.s);
  CHECK_EQ(int(converted.v), int(hex.v));
  CHECK(recover_address(digest, raw) == std::optional<std::string>(std::string(key.address())));
  CHECK(verify_signature(digest, raw, key.address()));
}
