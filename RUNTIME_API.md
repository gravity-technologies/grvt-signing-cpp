# C++ signing core boundary

The C++ artifact supplies exact signing behavior for applications that own their integration runtime.
Use this page when changing the generator or the reusable core.
The generator and core must agree on every name and ownership rule here.

`sdk/generator/cpp` generates public headers in `include/grvt/generated/` and private sources in `src/generated/`.
Run `make sdk-gen-cpp` after a contract change.
Generated output is build output and is not committed.

## Generated and reusable parts

| Generated from the contract | Reusable core |
|---|---|
| Signed request models and their nested types | Exact decimal values, timestamps, JSON codecs and result values |
| Enums used by those models | EIP-712 encoding support and Keccak hashing |
| Signing field mappings and typed data | Metadata containers and signer interface |
| Per-call digest and signing functions | Optional libsecp256k1 private-key signer |
| Bulk digest and signature attachment functions | Local signing failures |

Only types reachable from supported signed requests belong in the generated model set.
Do not generate RPC descriptors, response adapters, stream feeds or wrappers for unsigned calls.
The shared contract remains the source for signing fields and model names.

## Inputs and results

`SignContext::chain_id` and metadata are caller inputs.
The request signature supplies nonce and expiration explicitly.
The core must reject missing signing inputs instead of choosing a chain, reading a clock or generating a nonce.
The core must reject values that cannot be represented exactly at the required scale.
Trailing zeros do not add precision. The core must never round prices, sizes or amounts.

Generate `digest_<call>` (a `Result<SigningRequest>`, no private key needed) and `sign_<call>` for every
signed call, plus separate digest and attachment functions for bulk requests; [README.md](README.md#signing-with-external-keys)
describes how applications use them. Shared server signing cases check encoded fields, digests and signatures.

## Build boundary

`find_package(grvt_signing REQUIRED)` exposes `grvt::signing`.
`GRVT_SIGNING_WITH_SECP256K1=ON` also exposes `grvt::signer` and `signer.hpp`.
A core-only build must not require libsecp256k1 headers or libraries.
An installed consumer must compile and run outside the source checkout.

## Application ownership

Everything listed under "What you build yourself" on the [C++ SDK page](https://developers.grvt.io/sdks/cpp) belongs to the
application: networking, TLS, login, sessions, threads, timers, streams, order books, reconnects, retries,
outcome reconciliation, redirect handling, and business checks such as tick size and minimum notional.
Do not add these to the signing core. Executable references show integration seams without turning them into
library interfaces, and a scripted host response is demonstration data, not evidence of a deployed login or order.
The core validates only encoding inputs (exact precision, required signing metadata), so a valid digest does
not prove that the exchange will accept an order.
