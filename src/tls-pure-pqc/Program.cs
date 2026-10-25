using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections.Features;

const string CertsDir = "/certs";
var rootCaPath = Path.Combine(CertsDir, "root-ca.pem");

if (args is ["client", var url])
{
    await RunClient(url, rootCaPath);
    return;
}

// mint a pure ML-DSA-65 PKI (root CA + server certificate) with the .NET 10 APIs - no OpenSSL CLI involved
var (rootCa, serverCert) = CreatePqcPki();
File.WriteAllText(rootCaPath, rootCa.ExportCertificatePem());
Console.WriteLine($"[PKI] Root CA ({rootCa.GetMLDsaPublicKey()!.Algorithm.Name}) written to {rootCaPath}");

var builder = WebApplication.CreateBuilder(args);

// no TLS versions, cipher suites or groups in code - pure ML-KEM is enforced by OpenSSL config (see openssl-pqc.cnf)
builder.WebHost.ConfigureKestrel(o => o.ListenAnyIP(8443, l => l.UseHttps(serverCert)));

var app = builder.Build();

app.MapGet("/", (HttpContext ctx) =>
{
    var tls = ctx.Features.Get<ITlsHandshakeFeature>();
    Console.WriteLine($"[Connected] {tls?.Protocol} {tls?.NegotiatedCipherSuite}");

    return Results.Text($"""
        Pure post-quantum TLS connection established.

        TLS version:    {tls?.Protocol}
        Cipher suite:   {tls?.NegotiatedCipherSuite}
        Authentication: {serverCert.GetMLDsaPublicKey()!.Algorithm.Name} certificate, issued by {rootCa.GetNameInfo(X509NameType.SimpleName, false)}
        Key exchange:   restricted by OpenSSL config ({Environment.GetEnvironmentVariable("OPENSSL_CONF")})
        """);
});

app.Run();

static (X509Certificate2 RootCa, X509Certificate2 ServerCert) CreatePqcPki()
{
    var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
    var notAfter = notBefore.AddDays(30);

    using var rootKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    var rootRequest = new CertificateRequest("CN=PQC Demo Root CA", rootKey);
    rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
    var rootCa = rootRequest.CreateSelfSigned(notBefore, notAfter);

    using var serverKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    var serverRequest = new CertificateRequest("CN=pqc-server", serverKey);
    serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
    serverRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(rootCa, true, false));
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName("pqc-server");
    san.AddDnsName("localhost");
    serverRequest.CertificateExtensions.Add(san.Build());

    // Create(issuerCertificate, ...) does not know ML-DSA issuers yet, so sign with an explicit ML-DSA generator
    using var serverPublic = serverRequest.Create(rootCa.SubjectName, X509SignatureGenerator.CreateForMLDsa(rootKey),
        notBefore, notAfter.AddMinutes(-1), RandomNumberGenerator.GetBytes(16));
    return (rootCa, serverPublic.CopyWithPrivateKey(serverKey));
}

static async Task RunClient(string url, string rootCaPath)
{
    // trust only the demo's ML-DSA root - the server certificate is properly validated, no "-k"
    var rootCa = X509CertificateLoader.LoadCertificateFromFile(rootCaPath);
    var handler = new SocketsHttpHandler
    {
        SslOptions = new SslClientAuthenticationOptions
        {
            CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                CustomTrustStore = { rootCa },
                RevocationMode = X509RevocationMode.NoCheck
            },
            RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
            {
                Console.WriteLine($"[Client] Server certificate: {cert?.Subject}");
                foreach (var element in chain!.ChainElements)
                {
                    Console.WriteLine($"[Client]   chain: {element.Certificate.Subject} ({element.Certificate.GetMLDsaPublicKey()?.Algorithm.Name ?? "not ML-DSA"})");
                }
                Console.WriteLine($"[Client] Validation result: {errors}");
                return errors == SslPolicyErrors.None;
            }
        }
    };

    using var client = new HttpClient(handler);
    Console.WriteLine(await client.GetStringAsync(url));
}
