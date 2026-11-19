# Contributing to the C++ signing core

This directory is developed in the Grvt platform repository and copied to the public `grvt-signing-cpp`
repository. Edit it in the platform repository.

## How the source is made

The request models and the `grvt::signing::digest_<call>` / `sign_<call>` functions are generated from the
shared API contract by the platform repository's generator. [RUNTIME_API.md](RUNTIME_API.md) describes what the
generated code expects from the hand-written core. Regenerate after a contract change, from the platform root:

```sh
make sdk-gen-cpp
```

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DGRVT_SDK_BUILD_EXAMPLES=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests cover the shared signing cases, the installed package (the digest path and the optional signer
separately) and the executable reference. They need the signing cases file: in the platform repository it is
found automatically; elsewhere it is `scenarios/signing.json`, or pass
`-DGRVT_SIGNING_CASES_FILE=/path/to/signing.json` (download it from
https://developers.grvt.io/downloads/signing.json). A build with tests turned off doesn't need it.

From the platform root, `make sdk-check-cpp` also runs the compiler warning and sanitizer checks.

`./build/grvt_signing_benchmark` (built with the examples) times the signing path locally. It excludes the
network, metadata loading, parsing and request construction.

## Rules the core keeps

- Values are exact: anything that can't be represented at the required scale is rejected, never rounded.
- The core never chooses an environment, loads metadata, invents nonces or reads a clock for expiration.
- Before a verifier runs, the core checks the signature shape, low-s and the signer field.
- Digest results and their copies don't keep the typed data; `SigningRequest::typed_data()` is only available
  inside a `Signer` callback.
