#include "../examples/inputs.hpp"
#include "sign_support.hpp"
#include "test.hpp"
TEST(digest_without_signer) {
  auto order = reference::order();
  auto meta = reference::metadata();
  grvt::SignContext ctx;
  ctx.chain_id = 326;
  ctx.metadata = &meta;
  const auto before = order;
  auto digest = grvt::signing::digest_order_create_order(order, ctx);
  REQUIRE_OK(digest);
  CHECK_EQ(grvt::hex0x(digest->digest), "0x7f8fecb8997024f85a5a9a44730f79d2cef290688d6a022d8e98e95ccc1f98c9");
  CHECK(order == before);
  order.order.signature->nonce.reset();
  CHECK(!grvt::signing::digest_order_create_order(order, ctx));
  order = before;
  order.order.signature->expiration.reset();
  CHECK(!grvt::signing::digest_order_create_order(order, ctx));
  order = before;
  order.order.signature->chain_id.reset();
  ctx.chain_id = 0;
  CHECK(!grvt::signing::digest_order_create_order(order, ctx));
}
TEST(exact_decimal_scaling) {
  using grvt::detail::sign::scale_decimal;
  CHECK(scale_decimal("65000.1", 9) && *scale_decimal("65000.1", 9) == 65000100000000LL);
  CHECK(scale_decimal("-0.1", 9) && *scale_decimal("-0.1", 9) == -100000000);
  CHECK(scale_decimal("1.0000000000", 9) && *scale_decimal("1.0000000000", 9) == 1000000000);
  CHECK(!scale_decimal("1.0000000001", 9));
  CHECK(!scale_decimal("1e3", 9));
  CHECK(!scale_decimal("0", UINT32_MAX));
  CHECK(grvt::scaled_decimal("65000.1", 9) && *grvt::scaled_decimal("65000.1", 9) == "65000100000000");
}

#include "json.hpp"
#include "test_bindings.hpp"
namespace {
using namespace grvt;
namespace json = grvt::detail::json;
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

template <class Op>
Result<std::vector<SigningRequest>> digest_wire(const json::Value& wire, const SignContext& ctx) {
  auto req = decode<typename Op::Request>(wire.raw);
  if (!req) return req.error();
  if constexpr (requires { Op::digest(*req, ctx); }) {
    auto r = Op::digest(*req, ctx);
    if (!r) return r.error();
    return std::vector<SigningRequest>{*r};
  } else {
    std::vector<SigningRequest> out;
    auto r = signing::digests_order_bulk_orders(*req, ctx, out);
    if (!r) return r.error();
    return out;
  }
}
Result<std::vector<SigningRequest>> digest_case(std::string_view rpc, const json::Value& wire, const SignContext& ctx) {
  if (rpc == "order.create_order") return digest_wire<api::create_order>(wire, ctx);
  if (rpc == "order.bulk_orders") return digest_wire<api::bulk_orders>(wire, ctx);
  if (rpc == "transfer.transfer") return digest_wire<api::transfer>(wire, ctx);
  if (rpc == "transfer.withdrawal") return digest_wire<api::withdrawal>(wire, ctx);
  if (rpc == "edge.wallet_login") return digest_wire<api::edge_wallet_login>(wire, ctx);
  if (rpc == "derisk_mm_ratio.set_derisk_mm_ratio") return digest_wire<api::set_derisk_mm_ratio>(wire, ctx);
  if (rpc == "position.add_position_margin") return digest_wire<api::add_position_margin>(wire, ctx);
  if (rpc == "position.set_position_config") return digest_wire<api::set_position_config>(wire, ctx);
  if (rpc == "vault.vault_burn_tokens") return digest_wire<api::vault_burn_tokens>(wire, ctx);
  if (rpc == "vault.vault_invest") return digest_wire<api::vault_invest>(wire, ctx);
  if (rpc == "vault.vault_redeem") return digest_wire<api::vault_redeem>(wire, ctx);
  return Error::config("unknown fixture binding");
}
}  // namespace
TEST(shared_digest_cases_without_signer) {
  const auto text = test::read_file(GRVT_SIGNING_CASES_FILE);
  auto root = grvt::detail::json::parse(text);
  REQUIRE_OK(root);
  std::size_t count = 0;
  for (const auto& vec : root->find("cases")->items) {
    const auto& inputs = *vec.find("inputs");
    auto meta = metadata_of(*inputs.find("metadata"));
    grvt::SignContext ctx;
    ctx.chain_id = num(inputs.find("env_chain_id"));
    ctx.metadata = &meta;
    auto out = digest_case(str(vec.find("rpc")), *inputs.find("wire_request"), ctx);
    const auto name = str(vec.find("name"));
    if (str(vec.find("expect")) == "reject") {
      CHECK_MSG(!out, name);
      continue;
    }
    CHECK_MSG(bool(out), name + (out ? "" : ": " + out.error().message));
    if (!out) continue;
    const auto* steps = vec.find("steps");
    for (std::size_t i = 0; i < out->size(); ++i) {
      const auto& step = steps ? *steps : *vec.find("elements")->items[i].find("steps");
      CHECK_MSG(grvt::hex0x((*out)[i].digest) == str(step.find("digest")), name + ": digest");
      CHECK_MSG(grvt::hex0x((*out)[i].struct_hash) == str(step.find("struct_hash")), name + ": struct hash");
      CHECK_MSG(grvt::hex0x((*out)[i].domain_separator) == str(step.find("domain_separator")), name + ": domain");
      ++count;
    }
  }
  CHECK(count > 15);
}
TEST(signature_shape_rejects_invalid_scalars) {
  grvt::RawSignature sig;
  sig.r[31] = 1;
  sig.s[31] = 1;
  sig.v = 27;
  constexpr auto address = "0x1267c6181aee40f5ddbd70c56ecf4613117326b5";
  CHECK(grvt::check_signature_shape(sig, address));
  auto bad = sig;
  bad.r.fill(0);
  CHECK(!grvt::check_signature_shape(bad, address));
  bad = sig;
  bad.r.fill(255);
  CHECK(!grvt::check_signature_shape(bad, address));
  bad = sig;
  bad.s.fill(0);
  CHECK(!grvt::check_signature_shape(bad, address));
  CHECK(!grvt::check_signature_shape(sig, "0x123"));
}
TEST(malformed_builder_is_rejected) {
  auto order = reference::order();
  auto meta = reference::metadata();
  grvt::SignContext ctx;
  ctx.chain_id = 326;
  ctx.metadata = &meta;
  order.order.builder = "0xgg";
  CHECK(!grvt::signing::digest_order_create_order(order, ctx));
}

namespace {
class RawTestSigner : public grvt::Signer {
 public:
  grvt::RawSignature signature;
  std::string signer_address = "0x1267c6181aee40f5ddbd70c56ecf4613117326b5";
  std::string_view address() const override { return signer_address; }
  grvt::Result<grvt::Signature> sign(const grvt::SigningRequest&) override { return grvt::to_signature(signature); }
  // External byte signers can override the default shape check. The core must still enforce it.
  grvt::Result<grvt::RawSignature> sign_raw(const grvt::SigningRequest&) override { return signature; }
};
int verification_calls = 0;
grvt::Result<void> accepting_verifier(const grvt::Bytes32&, const grvt::RawSignature&, std::string_view) {
  ++verification_calls;
  return {};
}
}  // namespace

TEST(custom_verifier_cannot_bypass_signature_invariants) {
  RawTestSigner signer;
  signer.signature.r[31] = 1;
  signer.signature.s[31] = 1;
  signer.signature.v = 27;
  auto meta = reference::metadata();
  grvt::SignContext ctx{&signer, &meta, 326, accepting_verifier};
  const auto good = signer.signature;
  for (int invalid = 0; invalid < 6; ++invalid) {
    signer.signature = good;
    signer.signer_address = "0x1267c6181aee40f5ddbd70c56ecf4613117326b5";
    switch (invalid) {
      case 0: signer.signature.v = 1; break;
      case 1: signer.signature.r.fill(0); break;
      case 2: signer.signature.s.fill(255); break;
      case 3: signer.signature.signer = "0x0000000000000000000000000000000000000001"; break;
      case 4: signer.signer_address = "0x123"; break;
      case 5: signer.signature.s.fill(0); break;
    }
    auto request = reference::order();
    const auto before = request;
    verification_calls = 0;
    CHECK(!grvt::signing::sign_order_create_order(request, ctx));
    CHECK(request == before);
    CHECK_EQ(verification_calls, 0);
  }
  signer.signature = good;
  signer.signer_address = "0x1267c6181aee40f5ddbd70c56ecf4613117326b5";
  auto request = reference::order();
  REQUIRE_OK(grvt::signing::sign_order_create_order(request, ctx));
  CHECK_EQ(verification_calls, 1);
}

TEST(bulk_attach_checks_shape_before_custom_verification) {
  RawTestSigner signer;
  signer.signature.r[31] = 1;
  signer.signature.s[31] = 1;
  signer.signature.v = 27;
  auto meta = reference::metadata();
  grvt::SignContext ctx{&signer, &meta, 326, accepting_verifier};
  grvt::models::ApiBulkOrdersRequestInput request(*reference::order().order.sub_account_id);
  request.orders = std::vector<grvt::models::OrderInput>{reference::order().order};
  std::vector<grvt::SigningRequest> digests;
  REQUIRE_OK(grvt::signing::digests_order_bulk_orders(request, ctx, digests));
  const auto before = request;
  auto bad = signer.signature;
  bad.s.fill(255);
  verification_calls = 0;
  CHECK(!grvt::signing::attach_order_bulk_orders(request, ctx, std::span(&bad, 1)));
  CHECK(request == before);
  CHECK_EQ(verification_calls, 0);
  ctx.verify = nullptr;
  CHECK(!grvt::signing::attach_order_bulk_orders(request, ctx, std::span(&signer.signature, 1)));
  CHECK(request == before);
}
