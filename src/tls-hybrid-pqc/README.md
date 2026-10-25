# Hybrid Post-Quantum TLS with ASP.NET Core (X25519MLKEM768)

Hybrid TLS 1.3 key exchange (X25519 + ML-KEM-768, RFC 10024) with a classical ECDSA P-256 certificate.

The code sets no TLS versions, cipher suites or groups. .NET hands TLS to the OS (Schannel on Windows, OpenSSL on Linux), so PQC is switched on in the platform, not in code.

One project, two modes:

- `dotnet run -c Release` - Kestrel server on https://localhost:8443
- `dotnet run -c Release -- client <url>` - `HttpClient` caller

All commands run from this folder.

## Prerequisites

- .NET 10 SDK
- For steps 1-2, one of:
  - Windows 11 24H2/25H2 with KB5089573
  - Windows 11 26H1 with KB5095091
  - Windows Server 2025 with KB5099536
- An elevated PowerShell for `*-TlsEccCurve`
- Docker, for step 3

## Step 1: Classical baseline (Windows)

Hybrid groups are disabled by default in Schannel. Make sure that is the case:

```powershell
Disable-TlsEccCurve -Name "X25519_MLKEM768"
Get-TlsEccCurve
```

```
curve25519
NistP256
NistP384
```

Start the server in one terminal:

```bash
dotnet run -c Release
```

Call it from a second terminal:

```bash
dotnet run -c Release -- client https://localhost:8443
```

Expected:

```
[Client] Schannel (Microsoft Windows 10.0.26200), key exchange: X25519 (classical)
Secure connection established.

TLS stack:      Schannel (Microsoft Windows 10.0.26200)
TLS version:    Tls13
Cipher suite:   TLS_AES_256_GCM_SHA384
Authentication: ECDSA P-256 certificate (classical)
Key exchange:   X25519 (classical)
```

## Step 2: Enable hybrid PQC (Windows)

Enable the hybrid group and put it first in the preference list:

```powershell
Enable-TlsEccCurve -Name "X25519_MLKEM768" -Position 0
Get-TlsEccCurve
```

```
X25519_MLKEM768
curve25519
NistP256
NistP384
```

Restart the server (Ctrl+C, then `dotnet run -c Release`) and call it again:

```bash
dotnet run -c Release -- client https://localhost:8443
```

Expected (no code changes):

```
[Client] Schannel (Microsoft Windows 10.0.26200), key exchange: X25519MLKEM768 (hybrid post-quantum)
Secure connection established.

TLS stack:      Schannel (Microsoft Windows 10.0.26200)
TLS version:    Tls13
Cipher suite:   TLS_AES_256_GCM_SHA384
Authentication: ECDSA P-256 certificate (classical)
Key exchange:   X25519MLKEM768 (hybrid post-quantum)
```

Check it in the browser: open https://localhost:8443 in Edge or Chrome and accept the self-signed certificate. DevTools (F12) -> `Security` shows `TLS 1.3, X25519MLKEM768, and AES_256_GCM`.

Check it against a real-world server. The same client shows that outbound calls are PQC too:

```bash
dotnet run -c Release -- client https://www.cloudflare.com/cdn-cgi/trace
```

```
[Client] Schannel (Microsoft Windows 10.0.26200), key exchange: X25519MLKEM768 (hybrid post-quantum)
...
kex=X25519MLKEM768
```

Stop the server (Ctrl+C) before step 3, which uses the same port.

## Step 3: Linux container (OpenSSL 3.5)

The image is `aspnet:10.0-resolute-chiseled` (Ubuntu 26.04 LTS, OpenSSL 3.5). OpenSSL 3.5 offers X25519MLKEM768 first by default, so nothing needs configuring.

```bash
docker build -t tls-hybrid-pqc .
docker network create pqc-net
docker run -d --rm --name tls-hybrid-pqc --network pqc-net -p 8443:8443 tls-hybrid-pqc
docker run --rm --network pqc-net tls-hybrid-pqc client https://tls-hybrid-pqc:8443
```

Expected:

```
[Client] OpenSSL 3.5.5 (Ubuntu 26.04.1 LTS), key exchange: not reported by this TLS stack - see DevTools -> Security
Secure connection established.

TLS stack:      OpenSSL 3.5.5 (Ubuntu 26.04.1 LTS)
...
Key exchange:   not reported by this TLS stack - see DevTools -> Security
```

OpenSSL does not report the group to .NET, so check it from outside with OpenSSL 3.5, which ships in the .NET SDK image:

```bash
docker run --rm --network pqc-net mcr.microsoft.com/dotnet/sdk:10.0-resolute sh -c "openssl s_client -connect tls-hybrid-pqc:8443 -brief </dev/null"
```

```
Protocol version: TLSv1.3
Signature type: ecdsa_secp256r1_sha256
Negotiated TLS1.3 group: X25519MLKEM768
```

The group is negotiated, not forced. A classical-only client still connects:

```bash
docker run --rm --network pqc-net mcr.microsoft.com/dotnet/sdk:10.0-resolute sh -c "openssl s_client -connect tls-hybrid-pqc:8443 -groups X25519 -brief </dev/null"
```

```
Peer Temp Key: X25519, 253 bits
```

What it costs, in ClientHello size (hex): `0x5be` = 1470 bytes hybrid, against `0x126` = 294 bytes classical.

```bash
docker run --rm --network pqc-net mcr.microsoft.com/dotnet/sdk:10.0-resolute sh -c "for g in X25519MLKEM768 X25519; do openssl s_client -connect tls-hybrid-pqc:8443 -groups \$g -msg </dev/null 2>/dev/null | grep -m1 ClientHello; done"
```

```
>>> TLS 1.3, Handshake [length 05be], ClientHello
>>> TLS 1.3, Handshake [length 0126], ClientHello
```

## Clean up

```bash
docker rm -f tls-hybrid-pqc
docker network rm pqc-net
```

To restore the Windows default (elevated):

```powershell
Disable-TlsEccCurve -Name "X25519_MLKEM768"
```

Group Policy overrides the cmdlets if both are used.

## Note: how the app knows the group

.NET has no API for the negotiated TLS 1.3 group. The cipher suite (`TLS_AES_256_GCM_SHA384`) is the same with or without PQC.

On Windows, Schannel still reports the client's key-share size through the obsolete `KeyExchangeStrength` (SYSLIB0058) on `SslStream` and `ITlsHandshakeFeature`:

- `255` for X25519 (bits)
- `1216` for X25519MLKEM768 (32 + 1184 bytes)

This is undocumented, so treat it as a demo aid, not an API. OpenSSL reports `0`.
