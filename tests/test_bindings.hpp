#pragma once
namespace grvt::api {
struct create_order {
  using Request = models::ApiCreateOrderRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"create_order"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_order_create_order(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_order_create_order(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_order_create_order(req, ctx);
  }
};
struct bulk_orders {
  using Request = models::ApiBulkOrdersRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"bulk_orders"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_order_bulk_orders(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_order_bulk_orders(req); }
};
struct transfer {
  using Request = models::ApiTransferRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"transfer"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_transfer_transfer(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_transfer_transfer(req); }
  static auto digest(const Request& req, const SignContext& ctx) { return signing::digest_transfer_transfer(req, ctx); }
};
struct withdrawal {
  using Request = models::ApiWithdrawalRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"withdrawal"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_transfer_withdrawal(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_transfer_withdrawal(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_transfer_withdrawal(req, ctx);
  }
};
struct edge_wallet_login {
  using Request = models::EdgeWalletLoginRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"edge_wallet_login"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_edge_wallet_login(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_edge_wallet_login(req); }
  static auto digest(const Request& req, const SignContext& ctx) { return signing::digest_edge_wallet_login(req, ctx); }
};
struct set_derisk_mm_ratio {
  using Request = models::ApiSetDeriskToMaintenanceMarginRatioRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"set_derisk_mm_ratio"};
  static auto sign(Request& req, const SignContext& ctx) {
    return signing::sign_derisk_mm_ratio_set_derisk_mm_ratio(req, ctx);
  }
  static auto needs(const Request& req) { return signing::needs_derisk_mm_ratio_set_derisk_mm_ratio(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_derisk_mm_ratio_set_derisk_mm_ratio(req, ctx);
  }
};
struct add_position_margin {
  using Request = models::ApiAddIsolatedPositionMarginRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"add_position_margin"};
  static auto sign(Request& req, const SignContext& ctx) {
    return signing::sign_position_add_position_margin(req, ctx);
  }
  static auto needs(const Request& req) { return signing::needs_position_add_position_margin(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_position_add_position_margin(req, ctx);
  }
};
struct set_position_config {
  using Request = models::ApiSetSubAccountPositionMarginConfigRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"set_position_config"};
  static auto sign(Request& req, const SignContext& ctx) {
    return signing::sign_position_set_position_config(req, ctx);
  }
  static auto needs(const Request& req) { return signing::needs_position_set_position_config(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_position_set_position_config(req, ctx);
  }
};
struct vault_burn_tokens {
  using Request = models::ApiVaultBurnTokensRequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"vault_burn_tokens"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_vault_vault_burn_tokens(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_vault_vault_burn_tokens(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_vault_vault_burn_tokens(req, ctx);
  }
};
struct vault_invest {
  using Request = models::ApiVaultInvestV2RequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"vault_invest"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_vault_vault_invest(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_vault_vault_invest(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_vault_vault_invest(req, ctx);
  }
};
struct vault_redeem {
  using Request = models::ApiVaultRedeemV2RequestInput;
  struct {
    std::string_view id;
  } static constexpr spec{"vault_redeem"};
  static auto sign(Request& req, const SignContext& ctx) { return signing::sign_vault_vault_redeem(req, ctx); }
  static auto needs(const Request& req) { return signing::needs_vault_vault_redeem(req); }
  static auto digest(const Request& req, const SignContext& ctx) {
    return signing::digest_vault_vault_redeem(req, ctx);
  }
};
}  // namespace grvt::api
