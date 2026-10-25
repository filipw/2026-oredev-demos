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

For the TLS demos, make sure you have Docker installed.

- `src/tls-hybrid-pqc` - hybrid X25519MLKEM768, same code natively on Windows (Schannel) and in a Linux container (OpenSSL 3.5)
- `src/tls-pure-pqc` - pure ML-KEM-768 + ML-DSA-65, server and client both .NET, in Linux containers via `docker compose`