# Grvt C++ signing core and reference

This source preview helps firms connect their own trading systems to Grvt.
Use it when your application already owns its HTTP client, WebSocket client and event loop.
It supplies exact decimal values, EIP-712 encoding and hashing, and tested reference examples.
The optional libsecp256k1 signer signs with a private key in the same process.

The application owns login, sessions, networking, timers, retries, order books and recovery.
There is no client runtime or generated wrapper for every RPC and stream.
The API can change in any 0.x release. Pin an exact source revision.

## Build and install

Use CMake 3.24+ and a C++20 GCC or Clang on Linux or macOS.
MSVC is not supported because the core uses `__int128` arithmetic.
The public source repo includes generated code and signing cases. In the platform monorepo, run
`make sdk-gen-cpp` from its root before building. From the C++ source directory:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /opt/grvt
```

The default build contains the core without libsecp256k1.
For in-process keys, install libsecp256k1 with its recovery module
(`apt install libsecp256k1-dev` or `brew install secp256k1`) and enable the optional signer:

```sh
cmake -S . -B build -DGRVT_SIGNING_WITH_SECP256K1=ON
```

Consume the installed core through CMake:

```cmake
find_package(grvt_signing REQUIRED)
target_link_libraries(app PRIVATE grvt::signing)
# For in-process private keys, also link grvt::signer.
```

## Follow the reference

[examples/reference.cpp](examples/reference.cpp) is the canonical executable reference.
It separates the authentication wire request, signing inputs and caller-owned transport.
The [integration guide](https://developers.grvt.io/sdks/cpp) explains the ownership boundary and the steps for a live application.

```sh
cmake -S . -B build -DGRVT_SDK_BUILD_EXAMPLES=ON
cmake --build build --target grvt_signing_reference
./build/grvt_signing_reference
```

The example uses fixed inputs and makes no network calls.
Its output is reference data, not a fresh order to submit to the exchange.
For a live order, load current instrument and currency metadata. Generate a fresh uint32 nonce with an OS secure random source for each new signed action.
Set expiration to a future Unix timestamp in nanoseconds, usually one day ahead and at most 30 days ahead, as described in the [signing guide](https://developers.grvt.io/guides/signing).
The fixed nonce and far-future expiration in the reference are conformance fixtures, not live settings.
Match the explicit chain ID to the request destination.

## Signing with external keys

The generated `grvt::signing::digest_<call>` functions return the request digest separately from private-key signing.
Use these functions with an external wallet, HSM or KMS.
Inside a `Signer` callback, `SigningRequest::typed_data()` supplies typed data for a signer that requires it.
Digest results and copies do not retain typed data.
Use `grvt::signing::sign_<call>` with a `grvt::Signer` to attach a signature.
Bulk orders expose separate digest and signature attachment functions.
`attach_order_bulk_orders` requires `SignContext::verify`: supply a callback that checks that each digest and signature recover to the expected signer address.
The optional adapter provides `grvt::verify_signature`. The core always checks signature shape, low-s and the signer field before calling your verifier.
An accepting callback alone does not prove that the expected key signed the digest.

Generated request models and signing functions come from the shared API contract.
[RUNTIME_API.md](RUNTIME_API.md) describes the generator boundary.
The core does not choose an environment, load metadata, invent nonces or read a clock for expiration.

## Validate changes

```sh
ctest --test-dir build --output-on-failure
```

The tests cover shared signing cases, the installed package and the executable reference. In the platform
monorepo, `make sdk-check-cpp` also runs compiler warning and sanitizer checks.

The core validates encoding inputs and required signing metadata.
It rejects values that cannot be represented exactly at the required scale and never rounds.
Your application and the exchange own business checks such as tick size, minimum size and minimum notional.
A valid digest does not prove that the exchange will accept an order.

Use the shared [server signing test cases](https://developers.grvt.io/downloads/signing.json) to test your integration.
The public source repo includes the fixture at `scenarios/signing.json`. The C++ tests use the same data.
Installation includes it at `share/grvt_signing/signing.json`.
For a build from a source copy without the fixture, set `-DGRVT_SIGNING_CASES_FILE=/path/to/signing.json` to the downloaded file.
Tests require that fixture. A build with tests disabled can omit it.
