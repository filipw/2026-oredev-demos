# 2026-oredev-demos

## Notes on PQC algorithms demo

### BouncyCastle

The demo should worked on all platforms because it is fully managed code.

### LibOQS.NET

The demo should work on:

- Windows x64 and arm64
- Linux x64 and arm64
- macOS arm64

### System.Security.Cryptography

The demo should work on:

- Windows x64 and arm64 - but only if you are on Windows higher than Build 27852
- Linux x64 and arm64 - but only if you are on a distro that supports OpenSSL 3.5 or higher

If your Linux has lower version of OpenSSL, you can try the following:

```bash
export OPENSSL_ROOT=/path/to/your/openssl-3.5
export LD_LIBRARY_PATH="$OPENSSL_ROOT/lib:${LD_LIBRARY_PATH}"
export OPENSSL_MODULES="$OPENSSL_ROOT/lib/ossl-modules"
export PATH="$OPENSSL_ROOT/bin:$PATH"
```

## TLS demos

For the TLS demos, make sure you have Docker installed. Run them in this order:

1. [`src/tls-hybrid-pqc`](src/tls-hybrid-pqc/README.md) - hybrid X25519MLKEM768 (today)
    - Step 1: classical baseline on Windows
    - Step 2: enable hybrid in Schannel, no code changes
    - Step 3: the same app in a Linux container (OpenSSL 3.5)
2. [`src/tls-pure-pqc`](src/tls-pure-pqc/README.md) - pure ML-KEM-768 + ML-DSA-65 (future)
    - Steps 1-3: policy, server and .NET client
    - Step 4: hybrid and classical clients are rejected