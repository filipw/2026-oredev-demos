# ASP.NET Core Hybrid X25519MLKEM768 TLS Example

This sample shows hybrid post-quantum TLS 1.3 key exchange (X25519MLKEM768, RFC 10024) with a classical ECDSA P-256 certificate.

The code contains no TLS versions, cipher suites or groups. Kestrel hands TLS to the platform: Schannel on Windows, OpenSSL on Linux. The same binary therefore gets PQC from whichever stack it runs on, with no code changes.

## Option A: natively on Windows (Schannel)

Requires Windows 11 24H2/25H2 with KB5089573 (26H1: KB5095091), or Windows Server 2025 with KB5099536. Hybrid groups are **disabled by default**.

1. Run the app and open https://localhost:8443 in Edge or Chrome (accept the self-signed certificate):

    ```bash
    dotnet run -c Release
    ```

    DevTools (F12) -> `Security` shows `X25519` - classical key exchange.

2. Enable the hybrid group from an **elevated** PowerShell and put it first:

    ```powershell
    Enable-TlsEccCurve -Name "X25519_MLKEM768" -Position 0
    Get-TlsEccCurve
    ```

3. Restart the app and reload the page. DevTools -> `Security` now shows `X25519MLKEM768`. Nothing in the app changed.

To revert: `Disable-TlsEccCurve -Name "X25519_MLKEM768"`. Group Policy overrides the cmdlet if both are used.

## Option B: Linux container (OpenSSL 3.5)

The image is the official `aspnet:10.0-resolute-chiseled` (Ubuntu 26.04 LTS, OpenSSL 3.5). OpenSSL 3.5 puts X25519MLKEM768 first in its default groups, so no configuration is needed.

```bash
docker build -t tls-hybrid-pqc .
docker network create pqc-net
docker run -d --rm --name tls-hybrid-pqc --network pqc-net -p 8443:8443 tls-hybrid-pqc
```

Open https://localhost:8443 and check DevTools -> `Security`: `TLS 1.3, X25519MLKEM768, and AES_256_GCM`.

## Inspecting the handshake with OpenSSL 3.5

`openssl s_client` needs OpenSSL 3.5+. The .NET SDK image ships it:

```bash
docker run --rm --network pqc-net mcr.microsoft.com/dotnet/sdk:10.0-resolute sh -c "openssl s_client -connect tls-hybrid-pqc:8443 -brief </dev/null"
```

```
Protocol version: TLSv1.3
Signature type: ecdsa_secp256r1_sha256
Negotiated TLS1.3 group: X25519MLKEM768
```

Against the native Windows server use `-connect host.docker.internal:8443` (no `--network`).

The group is negotiated, not forced. A classical-only client still connects:

```bash
docker run --rm --network pqc-net mcr.microsoft.com/dotnet/sdk:10.0-resolute sh -c "openssl s_client -connect tls-hybrid-pqc:8443 -groups X25519 -brief </dev/null"
```

```
Peer Temp Key: X25519, 253 bits
```

The price is visible in the ClientHello: about 1.5 KB with X25519MLKEM768 against about 300 bytes with X25519 alone (add `-msg` to see it).

## Note

ASP.NET Core cannot tell you which group was negotiated. `ITlsHandshakeFeature` and `SslStream` expose the TLS version and cipher suite (`TLS_AES_256_GCM_SHA384`), and neither changes with PQC. To see the group, check from the client side: browser DevTools, `openssl s_client` or Wireshark (`tls.handshake.extensions_key_share_group`).
