#include <grvt/grvt.hpp>
#ifdef GRVT_WITH_SIGNER
#include <grvt/signer.hpp>
#endif
int main() {
  auto req = grvt::decode<grvt::models::EdgeWalletLoginRequestInput>(
      R"({"address":"0x1267c6181aee40f5ddbd70c56ecf4613117326b5","signature":{"nonce":1,"expiration":"4102444800000000000","chain_id":"326"}})");
  if (!req) return 1;
  grvt::SignContext ctx;
  ctx.chain_id = 326;
  auto digest = grvt::signing::digest_edge_wallet_login(*req, ctx);
  if (!digest) return 2;
#ifdef GRVT_WITH_SIGNER
  auto key = grvt::PrivateKeySigner::from_hex("0xbfe25ff07bd38cb3fbc28a2a296d41aabd68a78c929d257935906489fc9c6d89");
  if (!key) return 3;
  ctx.signer = &*key;
  if (!grvt::signing::sign_edge_wallet_login(*req, ctx)) return 4;
#endif
  return 0;
}
