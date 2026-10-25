# ASP.NET Core Pure Post-Quantum TLS Example

This sample shows a pure post-quantum TLS 1.3 connection, with no classical cryptography anywhere in the handshake:

- **ML-KEM-768** for key exchange (`draft-ietf-tls-mlkem`)
- **ML-DSA-65** for authentication: a root CA and a server certificate (`draft-ietf-tls-mldsa`)

All of it is .NET 10:

- On startup the server creates its own ML-DSA PKI with `MLDsa`, `CertificateRequest` and `X509SignatureGenerator.CreateForMLDsa`. There is no OpenSSL CLI and no `openssl req`.
- The client is a .NET `HttpClient` that trusts **only** that ML-DSA root (`X509ChainPolicy.CustomTrustStore`). The server certificate is properly validated, without `-k` or `--insecure`.
- The pure PQC policy lives in [`openssl-pqc.cnf`](openssl-pqc.cnf) (`Groups = MLKEM768`, `SignatureAlgorithms = mldsa65`), loaded through `OPENSSL_CONF`. It is not in the C# code.

Server and client use the same image, the official `aspnet:10.0-resolute-chiseled` (Ubuntu 26.04 LTS, OpenSSL 3.5).

> Windows: Schannel has pure ML-KEM only as a preview (KB5120998), and ML-DSA certificates in Schannel TLS are a later phase, so this demo is Linux-only for now. Browsers don't support either yet.

## 1. Build and start the server

```bash
docker compose up -d --build pqc-server
```

## 2. .NET client

```bash
docker compose run --rm client
```

```
[Client] Server certificate: CN=pqc-server
[Client]   chain: CN=pqc-server (ML-DSA-65)
[Client]   chain: CN=PQC Demo Root CA (ML-DSA-65)
[Client] Validation result: None
Pure post-quantum TLS connection established.

TLS version:    Tls13
Cipher suite:   TLS_AES_256_GCM_SHA384
Authentication: ML-DSA-65 certificate, issued by PQC Demo Root CA
Key exchange:   restricted by OpenSSL config (/etc/ssl/openssl-pqc.cnf)
```

## 3. Inspect the handshake with OpenSSL

```bash
docker compose run --rm -T openssl s_client -connect pqc-server:8443 -groups MLKEM768 -CAfile /certs/root-ca.pem -verify_return_error -verify_hostname pqc-server -brief
```

```
Protocol version: TLSv1.3
Signature type: mldsa65
Verification: OK
Verified peername: pqc-server
Negotiated TLS1.3 group: MLKEM768
```

> Git Bash on Windows rewrites `/certs/...` into a Windows path. Prefix the command with `MSYS_NO_PATHCONV=1`, or use PowerShell.

## 4. Everything else is rejected

A hybrid client (what browsers send today) gets `handshake failure`:

```bash
docker compose run --rm -T openssl s_client -connect pqc-server:8443 -groups X25519MLKEM768 -brief
```

A classical client also gets `handshake failure`:

```bash
docker compose run --rm -T openssl s_client -connect pqc-server:8443 -groups X25519:P-256 -brief
```

A client that doesn't trust the ML-DSA root gets `certificate verify failed`:

```bash
docker compose run --rm -T openssl s_client -connect pqc-server:8443 -groups MLKEM768 -verify_return_error -brief
```

## Notes

- For CNSA 2.0, switch to `Groups = MLKEM1024`, `SignatureAlgorithms = mldsa87` and `MLDsaAlgorithm.MLDsa87`.
- `MLDsa` is stable in .NET 10, but its X.509 integration (`CertificateRequest(..., MLDsa)`, `CopyWithPrivateKey(MLDsa)`, `GetMLDsaPublicKey()`) is still `[Experimental]` (SYSLIB5006), which is suppressed in the project file. `CertificateRequest.Create(issuerCertificate, ...)` doesn't accept an ML-DSA issuer yet, so the server certificate is signed through `X509SignatureGenerator.CreateForMLDsa`.

Clean up with `docker compose down -v`.
