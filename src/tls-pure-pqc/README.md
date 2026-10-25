# Pure Post-Quantum TLS with ASP.NET Core (ML-KEM-768 + ML-DSA-65)

Pure TLS 1.3 with no classical cryptography in the handshake:

- **ML-KEM-768** for key exchange (`draft-ietf-tls-mlkem`)
- **ML-DSA-65** for authentication: a root CA and a server certificate (`draft-ietf-tls-mldsa`)

Both ends are .NET 10:

- The server creates its own ML-DSA PKI on startup with `MLDsa`, `CertificateRequest` and `X509SignatureGenerator.CreateForMLDsa`.
- The client is an `HttpClient` that trusts only that root.
- The pure PQC policy lives in OpenSSL config, not in code.

One image, two modes: the server (default) and `client <url>`. The image is `aspnet:10.0-resolute-chiseled` (Ubuntu 26.04 LTS, OpenSSL 3.5).

Linux only:

- Schannel has pure ML-KEM only as a preview (KB5120998), and ML-DSA certificates in Schannel TLS are a later phase.
- Browsers support neither.

All commands run from this folder.

## Prerequisites

- Docker with Compose

## Step 1: The policy

[`openssl-pqc.cnf`](openssl-pqc.cnf), loaded by both server and client through `OPENSSL_CONF`:

```ini
[tls_system_default]
MinProtocol = TLSv1.3
Groups = MLKEM768
SignatureAlgorithms = mldsa65
```

## Step 2: Start the server

```bash
docker compose up -d --build pqc-server
docker compose logs pqc-server
```

```
[PKI] Root CA (ML-DSA-65) written to /certs/root-ca.pem
```

## Step 3: .NET client

```bash
docker compose run --rm client
```

Expected:

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

To confirm the handshake from outside:

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

## Step 4: Everything else is rejected

A hybrid client, which is what every browser sends today, gets `handshake failure`:

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

## Clean up

```bash
docker compose down -v
```

## Notes

- Git Bash on Windows rewrites `/certs/...` into a Windows path. Prefix the commands with `MSYS_NO_PATHCONV=1`, or use PowerShell.
- For CNSA 2.0, switch to `Groups = MLKEM1024`, `SignatureAlgorithms = mldsa87` and `MLDsaAlgorithm.MLDsa87`.
- `MLDsa` is stable in .NET 10, but its X.509 integration (`CertificateRequest(..., MLDsa)`, `CopyWithPrivateKey(MLDsa)`, `GetMLDsaPublicKey()`) is still `[Experimental]` (SYSLIB5006), which is suppressed in the project file.
- `CertificateRequest.Create(issuerCertificate, ...)` doesn't accept an ML-DSA issuer yet, so the server certificate is signed through `X509SignatureGenerator.CreateForMLDsa`.
