using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections.Features;

if (args is ["client", var url])
{
    await RunClient(url);
    return;
}

// classical ECDSA P-256 certificate - hybrid TLS changes the key exchange, not the authentication
var cert = CreateEcdsaCertificate();

var builder = WebApplication.CreateBuilder(args);

// crypto-agile by design: no TLS versions, cipher suites or groups in code
// the platform's TLS stack (Schannel on Windows, OpenSSL 3.5+ on Linux) negotiates X25519MLKEM768
builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8443, l => l.UseHttps(cert)));

var app = builder.Build();

app.MapGet("/", (HttpContext ctx) =>
{
    var tls = ctx.Features.Get<ITlsHandshakeFeature>()!;
#pragma warning disable SYSLIB0058
    var keyExchange = DescribeKeyExchange(tls.KeyExchangeStrength);
#pragma warning restore SYSLIB0058
    Console.WriteLine($"[Server] {tls.Protocol} {tls.NegotiatedCipherSuite} {keyExchange}");

    return Results.Text($"""
        Secure connection established.

        TLS stack:      {TlsStack()}
        TLS version:    {tls.Protocol}
        Cipher suite:   {tls.NegotiatedCipherSuite}
        Authentication: ECDSA P-256 certificate (classical)
        Key exchange:   {keyExchange}
        """);
});

app.Run();

static async Task RunClient(string url)
{
    var handler = new SocketsHttpHandler
    {
        SslOptions = new SslClientAuthenticationOptions
        {
            // demo only: the server uses a throwaway self-signed certificate
            RemoteCertificateValidationCallback = (sender, _, _, _) =>
            {
                var ssl = (SslStream)sender;
#pragma warning disable SYSLIB0058
                Console.WriteLine($"[Client] {TlsStack()}, key exchange: {DescribeKeyExchange(ssl.KeyExchangeStrength)}");
#pragma warning restore SYSLIB0058
                return true;
            }
        }
    };

    using var client = new HttpClient(handler);
    Console.WriteLine(await client.GetStringAsync(url));
}

// .NET has no API for the negotiated TLS 1.3 group. on Windows, Schannel still reports the client's key share
// size through the obsolete KeyExchangeStrength: X25519 = 255 (bits), X25519MLKEM768 = 1216 (32 + 1184 bytes)
// OpenSSL reports nothing (0), so on Linux use DevTools -> Security or openssl s_client instead
static string DescribeKeyExchange(int strength) => strength switch
{
    1216 => "X25519MLKEM768 (hybrid post-quantum)",
    255 => "X25519 (classical)",
    0 => "not reported by this TLS stack - see DevTools -> Security",
    _ => $"unknown (Schannel reports {strength})"
};

static string TlsStack()
{
    if (OperatingSystem.IsWindows())
    {
        return $"Schannel ({RuntimeInformation.OSDescription})";
    }

    var v = SafeEvpPKeyHandle.OpenSslVersion;
    return $"OpenSSL {v >> 28}.{(v >> 20) & 0xFF}.{(v >> 4) & 0xFF} ({RuntimeInformation.OSDescription})";
}

static X509Certificate2 CreateEcdsaCertificate()
{
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName("localhost");
    san.AddDnsName("tls-hybrid-pqc");
    san.AddIpAddress(System.Net.IPAddress.Loopback);
    request.CertificateExtensions.Add(san.Build());
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

    using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
    // round-trip through PFX - Schannel cannot use ephemeral keys
    return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
}
