using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections.Features;

// classical ECDSA P-256 certificate - hybrid TLS changes the key exchange, not the authentication
var cert = CreateEcdsaCertificate();

var builder = WebApplication.CreateBuilder(args);

// crypto-agile by design: no TLS versions, cipher suites or groups in code
// the platform's TLS stack (Schannel on Windows, OpenSSL 3.5+ on Linux) negotiates X25519MLKEM768
builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8443, l => l.UseHttps(cert)));

var app = builder.Build();

var tlsStack = OperatingSystem.IsWindows()
    ? $"Schannel ({RuntimeInformation.OSDescription})"
    : $"OpenSSL {SafeEvpPKeyHandle.OpenSslVersion >> 28}.{(SafeEvpPKeyHandle.OpenSslVersion >> 20) & 0xFF}.{(SafeEvpPKeyHandle.OpenSslVersion >> 4) & 0xFF} ({RuntimeInformation.OSDescription})";

app.MapGet("/", (HttpContext ctx) =>
{
    var tls = ctx.Features.Get<ITlsHandshakeFeature>();
    Console.WriteLine($"[Connected] {tls?.Protocol} {tls?.NegotiatedCipherSuite}");

    return Results.Text($"""
        Secure connection established.

        TLS stack:      {tlsStack}
        TLS version:    {tls?.Protocol}
        Cipher suite:   {tls?.NegotiatedCipherSuite}
        Authentication: ECDSA P-256 certificate (classical)
        Key exchange:   chosen by the TLS stack, not visible to the app - see DevTools -> Security
        """);
});

app.Run();

static X509Certificate2 CreateEcdsaCertificate()
{
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName("localhost");
    san.AddIpAddress(System.Net.IPAddress.Loopback);
    request.CertificateExtensions.Add(san.Build());
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

    using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
    // round-trip through PFX - Schannel cannot use ephemeral keys
    return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
}
