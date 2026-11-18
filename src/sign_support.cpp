#include "sign_support.hpp"

#include <algorithm>
#include <cstring>

#include "hex.hpp"
#include "json.hpp"

namespace grvt::detail::sign {

namespace {

Error at_error(std::string_view at, const std::string& why) { return Error::signing(std::string(at) + ": " + why); }

std::string in_quotes(std::string_view s) { return "\"" + std::string(s) + "\""; }

// Hex digits (no 0x) right-aligned in N bytes, odd length allowed.
template <std::size_t N>
std::optional<std::array<std::uint8_t, N>> hex_right(std::string_view h) {
  if (h.size() > 2 * N) return std::nullopt;
  std::array<std::uint8_t, N> out{};
  std::size_t pos = N;
  std::size_t i = h.size();
  while (i > 0) {
    auto lo = nibble(h[i - 1]);
    std::optional<std::uint8_t> hi = std::uint8_t{0};
    if (i >= 2) hi = nibble(h[i - 2]);
    if (!lo || !hi) return std::nullopt;
    out[--pos] = static_cast<std::uint8_t>(*hi << 4 | *lo);
    i = i >= 2 ? i - 2 : 0;
  }
  return out;
}

bool has_0x(std::string_view s) { return s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'); }

Result<Value> to_int(std::string_view s, std::string_view at) {
  if (has_0x(s)) {
    auto w = hex_right<32>(s.substr(2));
    if (!w) return at_error(at, "not a hex integer: " + in_quotes(s));
    return Value::u256(*w);
  }
  std::string_view d = s;
  bool neg = false;
  if (!d.empty() && (d[0] == '-' || d[0] == '+')) {
    neg = d[0] == '-';
    d.remove_prefix(1);
  }
  if (d.empty() || d.size() > 38) return at_error(at, "not an integer: " + in_quotes(s));
  i128 n = 0;
  for (char c : d) {
    if (c < '0' || c > '9') return at_error(at, "not an integer: " + in_quotes(s));
    n = n * 10 + (c - '0');
  }
  return Value::integer(neg ? -n : n);
}

Result<Value> to_address(std::string_view s, std::string_view at) {
  const auto h = strip_0x(s);
  std::optional<std::array<std::uint8_t, 20>> a;
  if (h.size() == 40) a = hex_right<20>(h);
  if (!a) return at_error(at, "not an address: " + in_quotes(s));
  return Value::address(*a);
}

bool equal_fold(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           auto low = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; };
           return low(x) == low(y);
         });
}

}  // namespace

std::string to_string(u128 v) {
  if (v == 0) return "0";
  std::string s;
  while (v > 0) {
    s += static_cast<char>('0' + static_cast<int>(v % 10));
    v /= 10;
  }
  std::reverse(s.begin(), s.end());
  return s;
}

std::string to_string(i128 v) {
  return v < 0 ? "-" + to_string(static_cast<u128>(-(v + 1)) + 1) : to_string(static_cast<u128>(v));
}

Value Value::boolean(bool v) {
  Value x;
  x.kind = Kind::boolean;
  x.b = v;
  return x;
}
Value Value::integer(i128 v) {
  Value x;
  x.kind = Kind::integer;
  x.i = v;
  return x;
}
Value Value::u256(const std::array<std::uint8_t, 32>& v) {
  Value x;
  x.kind = Kind::u256;
  x.word = v;
  return x;
}
Value Value::address(const std::array<std::uint8_t, 20>& v) {
  Value x;
  x.kind = Kind::address;
  x.addr = v;
  return x;
}
Value Value::string(std::string_view v) {
  Value x;
  x.kind = Kind::string;
  x.s = v;
  return x;
}

Result<Value> copy(std::optional<Scalar> v, std::string_view eip_type, std::string_view at, std::optional<Scalar> def) {
  if (!v || (v->kind == Scalar::Kind::str && v->s.empty())) {
    if (!def) return Error::signing(std::string(at) + " is required for signing");
    v = def;
  }
  const Scalar x = *v;
  if (eip_type == "bool") {
    switch (x.kind) {
      case Scalar::Kind::boolean: return Value::boolean(x.b);
      case Scalar::Kind::str: return Value::boolean(equal_fold(x.s, "true"));
      case Scalar::Kind::integer: return Value::boolean(x.i != 0);
    }
  }
  if (eip_type == "address") {
    if (x.kind != Scalar::Kind::str) return at_error(at, "not an address");
    return to_address(x.s, at);
  }
  if (eip_type == "string") {
    if (x.kind != Scalar::Kind::str) return at_error(at, "not a string");
    return Value::string(x.s);
  }
  if (eip_type.starts_with("uint") || eip_type.starts_with("int")) {
    switch (x.kind) {
      case Scalar::Kind::integer: return Value::integer(x.i);
      case Scalar::Kind::str: return to_int(x.s, at);
      case Scalar::Kind::boolean: return Value::integer(x.b ? 1 : 0);
    }
  }
  return at_error(at, "unsupported copy type " + std::string(eip_type));
}

Result<Value> address(const std::string* v, std::string_view at) {
  if (!v || v->empty()) return Value::address({});
  return to_address(*v, at);
}

bool address_set(const std::string* v) noexcept {
  if (!v || v->empty()) return false;
  const auto h = strip_0x(*v);
  if (h.size() % 2 != 0) return false;
  bool nonzero = false;
  for (char c : h) {
    if (!nibble(c)) return false;
    nonzero = nonzero || c != '0';
  }
  return nonzero;
}

Result<i128> scale_decimal(std::string_view s, std::uint32_t decimals) {
  if (decimals > 38) return Error::signing("decimal scale exceeds the supported range (38)");
  while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
  while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
  std::string_view d = s;
  bool neg = false;
  if (!d.empty() && (d[0] == '-' || d[0] == '+')) {
    neg = d[0] == '-';
    d.remove_prefix(1);
  }
  const auto dot = d.find('.');
  std::string_view whole = d.substr(0, dot);
  std::string_view frac = dot == std::string_view::npos ? std::string_view() : d.substr(dot + 1);
  auto digits = [](std::string_view x) {
    return std::all_of(x.begin(), x.end(), [](char c) { return c >= '0' && c <= '9'; });
  };
  if ((whole.empty() && frac.empty()) || !digits(whole) || !digits(frac) ||
      (dot != std::string_view::npos && frac.empty() && whole.empty())) {
    return Error::signing("not a decimal: " + in_quotes(s));
  }
  while (!frac.empty() && frac.back() == '0') frac.remove_suffix(1);
  if (frac.size() > decimals) {
    return Error::signing(std::string(s) + " has more than " + std::to_string(decimals) + " decimal places");
  }
  constexpr i128 max = static_cast<i128>((static_cast<u128>(1) << 127) - 1);
  i128 n = 0;
  auto push = [&](char c) {
    if (n > (max - (c - '0')) / 10) return false;
    n = n * 10 + (c - '0');
    return true;
  };
  for (char c : whole) {
    if (!push(c)) return Error::signing(std::string(s) + " is too large");
  }
  for (char c : frac) {
    if (!push(c)) return Error::signing(std::string(s) + " is too large");
  }
  for (std::size_t i = frac.size(); i < decimals; ++i) {
    if (!push('0')) return Error::signing(std::string(s) + " is too large");
  }
  return neg ? -n : n;
}

Result<Value> scaled(const std::string* v, std::uint32_t decimals, std::string_view at,
                     std::optional<std::string_view> def) {
  std::string_view s;
  if (!v || v->empty()) {
    if (!def) return Error::signing(std::string(at) + " is required for signing");
    s = *def;
  } else {
    s = *v;
  }
  auto n = scale_decimal(s, decimals);
  if (!n) return at_error(at, n.error().message);
  return Value::integer(*n);
}

Result<Value> scaled(const Decimal* v, std::uint32_t decimals, std::string_view at,
                     std::optional<std::string_view> def) {
  if (!v) return scaled(static_cast<const std::string*>(nullptr), decimals, at, def);
  auto n = scale_decimal(v->text(), decimals);
  if (!n) return at_error(at, n.error().message);
  return Value::integer(*n);
}

const SigningMetadata& Meta::empty() {
  static const SigningMetadata none;
  return none;
}

Result<const InstrumentMeta*> Meta::instrument(const std::string* name) const {
  const std::string_view n = name ? std::string_view(*name) : std::string_view();
  auto it = m_.instruments.find(n);
  if (it == m_.instruments.end()) return Error::signing("no metadata for instrument " + in_quotes(n));
  return &it->second;
}

Result<const CurrencyMeta*> Meta::currency(const std::string* symbol) const {
  const std::string_view n = symbol ? std::string_view(*symbol) : std::string_view();
  auto it = m_.currencies.find(n);
  if (it == m_.currencies.end()) return Error::signing("no metadata for currency " + in_quotes(n));
  return &it->second;
}

Result<Value> Meta::asset_key(const std::string* name) const {
  auto inst = instrument(name);
  if (!inst) return std::move(inst).error();
  return to_int((*inst)->instrument_hash, "instrument_hash");
}

Result<Value> Meta::currency_id(const std::string* symbol) const {
  auto c = currency(symbol);
  if (!c) return std::move(c).error();
  return Value::integer((*c)->id);
}

Result<Value> Meta::main_account() const {
  if (!m_.main_account) return Error::signing("no main account loaded");
  return to_address(*m_.main_account, "main account");
}

void present(std::vector<std::string>& out, const std::string* v) {
  if (v && !v->empty() && std::find(out.begin(), out.end(), *v) == out.end()) out.push_back(*v);
}

// --- hashing ------------------------------------------------------------------------------------

namespace {

std::string describe(const Value& v) {
  switch (v.kind) {
    case Value::Kind::integer: return to_string(v.i);
    case Value::Kind::u256: return hex0x(v.word);
    case Value::Kind::boolean: return v.b ? "true" : "false";
    case Value::Kind::address: return hex0x(v.addr);
    case Value::Kind::string: return in_quotes(v.s);
  }
  return "?";
}

void put_u128(std::uint8_t* word, u128 u) {
  for (int i = 0; i < 16; ++i) word[31 - i] = static_cast<std::uint8_t>(u >> (8 * i));
}

}  // namespace

Result<void> put(std::uint8_t* word, const FieldDef& f, const Value& v, std::string_view st) {
  auto where = [&] { return std::string(st) + "." + std::string(f.name); };
  auto doesnt_fit = [&] {
    return Error::signing(where() + ": value " + describe(v) + " does not fit " + std::string(f.type));
  };
  switch (f.kind) {
    case FieldKind::boolean:
      if (v.kind != Value::Kind::boolean) return doesnt_fit();
      word[31] = v.b ? 1 : 0;
      return {};
    case FieldKind::address:
      if (v.kind != Value::Kind::address) return doesnt_fit();
      std::memcpy(word + 12, v.addr.data(), 20);
      return {};
    case FieldKind::string: {
      if (v.kind != Value::Kind::string) return doesnt_fit();
      const Bytes32 h = keccak256(v.s);
      std::memcpy(word, h.data(), 32);
      return {};
    }
    case FieldKind::uint: {
      const std::uint32_t bits = f.bits;
      if (v.kind == Value::Kind::integer && v.i >= 0 && (bits >= 128 || v.i < (static_cast<i128>(1) << bits))) {
        put_u128(word, static_cast<u128>(v.i));
        return {};
      }
      if (v.kind == Value::Kind::u256) {
        std::uint32_t lead = 0;
        while (lead < 32 && v.word[lead] == 0) ++lead;
        if (256 - lead * 8 <= bits) {
          std::memcpy(word, v.word.data(), 32);
          return {};
        }
      }
      if (v.kind == Value::Kind::integer || v.kind == Value::Kind::u256) {
        return Error::signing(where() + ": value " + describe(v) + " out of range for uint" + std::to_string(bits));
      }
      return doesnt_fit();
    }
    case FieldKind::sint: {
      const std::uint32_t bits = f.bits;
      if (v.kind == Value::Kind::integer && (bits >= 128 || (v.i >= -(static_cast<i128>(1) << (bits - 1)) &&
                                                             v.i < (static_cast<i128>(1) << (bits - 1))))) {
        std::memset(word, v.i < 0 ? 0xff : 0, 16);
        put_u128(word, static_cast<u128>(v.i));
        return {};
      }
      if (v.kind == Value::Kind::integer)
        return Error::signing(where() + ": value " + describe(v) + " out of range for int" + std::to_string(bits));
      return doesnt_fit();
    }
    case FieldKind::list: break;
  }
  return Error::signing(where() + ": EIP-712 type " + std::string(f.type) + " has no encoder");
}

namespace {

void json_string(std::string& out, std::string_view s) {
  static constexpr char hex[] = "0123456789abcdef";
  out.push_back('"');
  for (char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out.push_back(hex[c >> 4]);
          out.push_back(hex[c & 15]);
        } else {
          out.push_back(ch);
        }
    }
  }
  out.push_back('"');
}

// A 32-byte big-endian unsigned integer in decimal.
std::string word_decimal(const std::uint8_t* word) {
  std::array<std::uint8_t, 32> n{};
  std::memcpy(n.data(), word, 32);
  std::string digits;
  for (;;) {
    bool zero = true;
    unsigned rem = 0;
    for (auto& b : n) {
      const unsigned cur = (rem << 8) | b;
      b = static_cast<std::uint8_t>(cur / 10);
      rem = cur % 10;
      zero = zero && b == 0;
    }
    digits.push_back(static_cast<char>('0' + rem));
    if (zero) break;
  }
  return std::string(digits.rbegin(), digits.rend());
}

void type_fields(std::string& out, const TypeDef& t) {
  json_string(out, t.name);
  out += ":[";
  for (std::size_t i = 0; i < t.fields.size(); ++i) {
    if (i) out.push_back(',');
    out += "{\"name\":";
    json_string(out, t.fields[i].name);
    out += ",\"type\":";
    json_string(out, t.fields[i].type);
    out.push_back('}');
  }
  out.push_back(']');
}

}  // namespace

std::string checksum_address(std::span<const std::uint8_t, 20> addr) {
  static constexpr char hex[] = "0123456789abcdef";
  char lower[40];
  for (std::size_t i = 0; i < 20; ++i) {
    lower[2 * i] = hex[addr[i] >> 4];
    lower[2 * i + 1] = hex[addr[i] & 15];
  }
  const Bytes32 h = keccak256(std::string_view(lower, 40));
  std::string out = "0x";
  for (std::size_t i = 0; i < 40; ++i) {
    const unsigned nibble = (h[i / 2] >> (i % 2 == 0 ? 4 : 0)) & 15;
    const char c = lower[i];
    out.push_back(c >= 'a' && nibble >= 8 ? static_cast<char>(c - 'a' + 'A') : c);
  }
  return out;
}

void JsonStruct::key(std::size_t field) {
  out_.push_back(out_.empty() ? '{' : ',');
  json_string(out_, t_.fields[field].name);
  out_.push_back(':');
}

Result<void> JsonStruct::put(std::size_t field, const Value& v) {
  const FieldDef& f = t_.fields[field];
  std::uint8_t word[32] = {};
  if (auto r = sign::put(word, f, v, t_.name); !r) return r;  // the same checks as hashing
  key(field);
  switch (f.kind) {
    case FieldKind::boolean: out_ += v.b ? "true" : "false"; break;
    case FieldKind::address: json_string(out_, checksum_address(std::span<const std::uint8_t, 20>(v.addr))); break;
    case FieldKind::string: json_string(out_, v.s); break;
    case FieldKind::uint: json_string(out_, word_decimal(word)); break;
    case FieldKind::sint: json_string(out_, to_string(v.i)); break;
    case FieldKind::list: break;  // put() refused it
  }
  return {};
}

void JsonStruct::end_list(std::size_t field, JsonList& items) {
  key(field);
  out_ += items.finish();
}

std::string JsonStruct::finish() {
  if (out_.empty()) out_.push_back('{');
  out_.push_back('}');
  return std::move(out_);
}

void JsonList::close(JsonStruct& item) {
  out_.push_back(out_.empty() ? '[' : ',');
  out_ += item.finish();
}

std::string JsonList::finish() {
  if (out_.empty()) out_.push_back('[');
  out_.push_back(']');
  return std::move(out_);
}

std::string typed_document(const TypeDef& primary, std::uint64_t chain_id, std::string_view message) {
  std::string out =
      "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},"
      "{\"name\":\"chainId\",\"type\":\"uint256\"}],";
  type_fields(out, primary);
  std::vector<const TypeDef*> seen;
  for (const auto& f : primary.fields) {
    if (f.nested == nullptr || std::find(seen.begin(), seen.end(), f.nested) != seen.end()) continue;
    seen.push_back(f.nested);
    out.push_back(',');
    type_fields(out, *f.nested);
  }
  out += "},\"primaryType\":";
  json_string(out, primary.name);
  out += ",\"domain\":{\"name\":\"GRVT Exchange\",\"version\":\"0\",\"chainId\":\"";
  out += std::to_string(chain_id);
  out += "\"},\"message\":";
  out += message;
  out.push_back('}');
  return out;
}

SigningRequest signing_request(const SignContext& ctx, std::uint64_t chain_id, const TypeDef& t,
                               const Bytes32& struct_hash) noexcept {
  SigningRequest req;
  req.chain_id = chain_id != 0 ? chain_id : ctx.chain_id;
  req.domain_separator = domain_separator(req.chain_id);
  req.struct_hash = struct_hash;
  req.primary_type = t.name;
  std::uint8_t buf[66];
  buf[0] = 0x19;
  buf[1] = 0x01;
  std::memcpy(buf + 2, req.domain_separator.data(), 32);
  std::memcpy(buf + 34, struct_hash.data(), 32);
  req.digest = keccak256(std::span<const std::uint8_t>(buf, sizeof buf));
  return req;
}

Result<void> check(const SignContext& ctx, const SigningRequest& req, const RawSignature& sig) {
  if (ctx.signer == nullptr) return Error::config("this call needs a signer: set SignContext::signer");
  if (ctx.verify) return check_recovered(ctx, req, sig);
  return check_signature_shape(sig, ctx.signer->address());
}

Result<void> check_recovered(const SignContext& ctx, const SigningRequest& req, const RawSignature& sig) {
  if (ctx.signer == nullptr) return Error::config("this call needs a signer: set SignContext::signer");
  if (auto ok = check_signature_shape(sig, ctx.signer->address()); !ok) return ok;
  if (!ctx.verify) return Error::config("signature recovery requires an explicit verification callback");
  return ctx.verify(req.digest, sig, ctx.signer->address());
}

Result<RawSignature> sign_hashed(const SignContext& ctx, std::uint64_t chain_id, const TypeDef& t,
                                 const Bytes32& struct_hash, const void* typed_source, TypedRender typed_render) {
  if (ctx.signer == nullptr) return Error::config("this call needs a signer: set SignContext::signer");
  // The typed-data pointers are set on this object only (copies drop them), so they never outlive the call.
  SigningRequest req = signing_request(ctx, chain_id, t, struct_hash);
  req.typed_source = typed_source;
  req.typed_render = typed_render;
  auto s = ctx.signer->sign_raw(req);
  if (!s) return s;
  if (auto ok = check(ctx, req, *s); !ok) return std::move(ok).error();
  return s;
}

void set_hex(std::optional<std::string>& out, const Bytes32& bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  if (!out) out.emplace();
  std::string& s = *out;
  s.resize(66);
  s[0] = '0';
  s[1] = 'x';
  for (std::size_t i = 0; i < 32; ++i) {
    s[2 + 2 * i] = digits[bytes[i] >> 4];
    s[3 + 2 * i] = digits[bytes[i] & 0xF];
  }
}

}  // namespace grvt::detail::sign

namespace grvt {
Result<std::string> scaled_decimal(std::string_view value, std::uint32_t decimals) {
  auto scaled = detail::sign::scale_decimal(value, decimals);
  if (!scaled) return std::move(scaled).error();
  return detail::sign::to_string(*scaled);
}
}  // namespace grvt
