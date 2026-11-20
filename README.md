# Grvt C++ signing core

Tested C++20 code to encode, hash and sign Grvt API requests, for trading systems that already have their own
HTTP client, WebSocket client and event loop. It is not a client: your application owns login, sessions,
networking, timers, retries, order books and recovery.

> **Preview.** Any 0.x release can change the API. Pin the exact source revision you build from.

## Install

Not published as a package: build it from source. You need CMake 3.24+ and GCC or Clang with C++20 or newer, on
Linux or macOS (MSVC is not supported: the core uses `__int128`).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /opt/grvt
```

```cmake
find_package(grvt_signing REQUIRED)
target_link_libraries(app PRIVATE grvt::signing)
# Also link grvt::signer for the optional private-key signer.
```

**Dependencies.** The core needs only the C++ standard library. The optional in-process signer needs
libsecp256k1 with its recovery module (`apt install libsecp256k1-dev` or `brew install secp256k1`); turn it on
with `-DGRVT_SIGNING_WITH_SECP256K1=ON`.

## Quickstart

Sign an order and encode it as wire JSON (from [examples/reference.cpp](examples/reference.cpp)):

```cpp
#include "grvt/grvt.hpp"
#include "grvt/signer.hpp"  // only for the optional private-key signer

// order is a grvt::models::ApiCreateOrderRequestInput (build it as in the example)
grvt::SigningMetadata meta;  // from the API: instrument_hash, base_decimals, quote_decimals
meta.instruments["BTC_USDT_Perp"] = {"0x030501", 9, 6};

grvt::SignContext ctx;
ctx.chain_id = 326;  // testnet; you choose the environment
ctx.metadata = &meta;

auto digest = grvt::signing::digest_order_create_order(order, ctx);  // for an external signer (HSM, KMS)
if (!digest) return 1;  // digest.error().kind and .message say why

// Or sign in-process with the optional signer, then send the JSON with your own HTTP client:
auto signer = grvt::PrivateKeySigner::from_hex(key);
if (!signer) return 2;  // a bad key; *signer would be undefined
ctx.signer = &*signer;
if (!grvt::signing::sign_order_create_order(order, ctx)) return 3;
std::string body = grvt::encode(order);
```

Run the full offline example:

```sh
cmake -S . -B build -DGRVT_SDK_BUILD_EXAMPLES=ON
cmake --build build --target grvt_signing_reference
./build/grvt_signing_reference
```

It uses fixed test values and sends nothing. Don't submit its output as a live order: a live order needs a fresh
nonce, a real expiration and current metadata.

## Documentation

- [C++ guide](https://developers.grvt.io/sdks/cpp): connecting a live application, step by step
- [Signing](https://developers.grvt.io/guides/signing): nonces, expiration, builder fees
- [Errors and retries](https://developers.grvt.io/guides/errors-and-retries): what to do when a write's outcome is unknown
- [API reference](https://developers.grvt.io/reference/index)
- [Signing test cases](https://developers.grvt.io/downloads/signing.json) to test your integration against
  (installed at `share/grvt_signing/signing.json`)

## C++ notes

- **Errors:** every function that can fail returns `grvt::Result<T>`, holding the value or a `grvt::Error`
  (`kind`: `signing`, `decode` or `config`, plus a `message`). Nothing throws.
- **Threads:** the sign and digest functions only read the `SignContext`. Threads can share one if your
  `Signer` is thread-safe (`PrivateKeySigner` is) and the metadata doesn't change meanwhile.
- **Allocation:** `digest_order_create_order`, and `sign_order_create_order` with `PrivateKeySigner`, allocate
  nothing after the first few calls when you reuse the request object. Errors and `typed_data()` do allocate.
  `examples/benchmark.cpp` measures the signing path.
- **Exact values:** prices, sizes and amounts are exact decimals. A value that can't be represented at the
  required scale is rejected, never rounded.
- **You choose:** the environment, chain ID, metadata, nonce and expiration. The core loads and invents none of
  them.

## Known limitations

See [Not supported yet](https://developers.grvt.io/sdks/cpp#not-supported-yet) on the C++ guide page.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [RUNTIME_API.md](RUNTIME_API.md).

## License

MIT. See [LICENSE](LICENSE).
