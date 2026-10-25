#pragma warning disable SYSLIB5006 // ML-DSA is experimental
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using LibOQS.NET;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Spectre.Console;
using BcMLDsaParameters = Org.BouncyCastle.Crypto.Parameters.MLDsaParameters;
using BcMLKemParameters = Org.BouncyCastle.Crypto.Parameters.MLKemParameters;

public static class CompareDemo
{
    private const int Iterations = 50;
    private static readonly byte[] Message = Encoding.ASCII.GetBytes("Hello, ML-DSA!");

    private record KemResult(int PublicKey, int PrivateKey, int CipherText, int SharedSecret, bool Ok);
    private record SigResult(int PublicKey, int PrivateKey, int Signature, bool Ok);
    private record Stack(string Name, string Kind, Func<bool> IsSupported, Func<KemResult> Kem, Func<SigResult> Sig);

    private static readonly Stack[] Stacks =
    [
        new("System.Security.Cryptography", "OS (CNG / OpenSSL)", () => MLKem.IsSupported && MLDsa.IsSupported, SystemKem, SystemSig),
        new("BouncyCastle", "fully managed", () => true, BouncyCastleKem, BouncyCastleSig),
        new("LibOQS.NET", "native liboqs", () => KemAlgorithm.MlKem768.IsEnabled() && SigAlgorithm.MlDsa65.IsEnabled(), LibOqsKem, LibOqsSig)
    ];

    public static void Run()
    {
        var kemTable = new Table().Title("ML-KEM-768: keygen + encapsulate + decapsulate")
            .AddColumns("Stack", "Backend", "Public key", "Private key", "Ciphertext", "Shared secret", "Secrets equal", "Avg time");
        var sigTable = new Table().Title("ML-DSA-65: keygen + sign + verify")
            .AddColumns("Stack", "Backend", "Public key", "Private key", "Signature", "Verified", "Avg time");

        foreach (var stack in Stacks)
        {
            if (!stack.IsSupported())
            {
                kemTable.AddRow(stack.Name, stack.Kind, "[red]not supported on this platform[/]", "", "", "", "", "");
                sigTable.AddRow(stack.Name, stack.Kind, "[red]not supported on this platform[/]", "", "", "", "");
                continue;
            }

            var (kem, kemTime) = Measure(stack.Kem);
            kemTable.AddRow(stack.Name, stack.Kind, Bytes(kem.PublicKey), Bytes(kem.PrivateKey), Bytes(kem.CipherText), Bytes(kem.SharedSecret), Check(kem.Ok), kemTime);

            var (sig, sigTime) = Measure(stack.Sig);
            sigTable.AddRow(stack.Name, stack.Kind, Bytes(sig.PublicKey), Bytes(sig.PrivateKey), Bytes(sig.Signature), Check(sig.Ok), sigTime);
        }

        AnsiConsole.Write(kemTable);
        AnsiConsole.Write(sigTable);
        AnsiConsole.MarkupLine($"[grey]Avg time = mean of {Iterations} runs after one warm-up run.[/]");
    }

    private static (T Result, string Time) Measure<T>(Func<T> run)
    {
        // warm up (JIT, native library load) before timing
        var result = run();
        var stopwatch = Stopwatch.StartNew();
        for (var i = 0; i < Iterations; i++)
        {
            run();
        }
        return (result, $"{stopwatch.Elapsed.TotalMilliseconds / Iterations:F2} ms");
    }

    private static string Bytes(int length) => $"{length:N0} B";

    private static string Check(bool ok) => ok ? ":check_mark_button:" : ":cross_mark:";

    private static KemResult SystemKem()
    {
        using var alice = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        var alicePublic = alice.ExportEncapsulationKey();
        var alicePrivate = alice.ExportDecapsulationKey();

        using var bob = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, alicePublic);
        bob.Encapsulate(out var cipherText, out var bobSecret);
        var aliceSecret = alice.Decapsulate(cipherText);

        return new(alicePublic.Length, alicePrivate.Length, cipherText.Length, bobSecret.Length, bobSecret.SequenceEqual(aliceSecret));
    }

    private static SigResult SystemSig()
    {
        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var publicKey = key.ExportMLDsaPublicKey();
        var privateKey = key.ExportMLDsaPrivateKey();
        var signature = key.SignData(Message);

        using var verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey);
        return new(publicKey.Length, privateKey.Length, signature.Length, verifier.VerifyData(Message, signature));
    }

    private static KemResult BouncyCastleKem()
    {
        var random = new SecureRandom();
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, BcMLKemParameters.ml_kem_768));
        var aliceKeyPair = generator.GenerateKeyPair();
        var alicePublic = (MLKemPublicKeyParameters)aliceKeyPair.Public;
        var alicePrivate = (MLKemPrivateKeyParameters)aliceKeyPair.Private;

        var encapsulator = new MLKemEncapsulator(BcMLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(alicePublic, random));
        var cipherText = new byte[encapsulator.EncapsulationLength];
        var bobSecret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(cipherText, 0, cipherText.Length, bobSecret, 0, bobSecret.Length);

        var decapsulator = new MLKemDecapsulator(BcMLKemParameters.ml_kem_768);
        decapsulator.Init(alicePrivate);
        var aliceSecret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(cipherText, 0, cipherText.Length, aliceSecret, 0, aliceSecret.Length);

        return new(alicePublic.GetEncoded().Length, alicePrivate.GetEncoded().Length, cipherText.Length, bobSecret.Length, bobSecret.SequenceEqual(aliceSecret));
    }

    private static SigResult BouncyCastleSig()
    {
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), BcMLDsaParameters.ml_dsa_65));
        var keyPair = generator.GenerateKeyPair();
        var publicKey = (MLDsaPublicKeyParameters)keyPair.Public;
        var privateKey = (MLDsaPrivateKeyParameters)keyPair.Private;

        var signer = new MLDsaSigner(BcMLDsaParameters.ml_dsa_65, deterministic: true);
        signer.Init(true, privateKey);
        signer.BlockUpdate(Message, 0, Message.Length);
        var signature = signer.GenerateSignature();

        var verifier = new MLDsaSigner(BcMLDsaParameters.ml_dsa_65, deterministic: true);
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(Message, 0, Message.Length);

        return new(publicKey.GetEncoded().Length, privateKey.GetEncoded().Length, signature.Length, verifier.VerifySignature(signature));
    }

    private static KemResult LibOqsKem()
    {
        using var kem = new KemInstance(KemAlgorithm.MlKem768);
        var (alicePublic, alicePrivate) = kem.GenerateKeypair();
        var (cipherText, bobSecret) = kem.Encapsulate(alicePublic);
        var aliceSecret = kem.Decapsulate(alicePrivate, cipherText);

        return new(alicePublic.Length, alicePrivate.Length, cipherText.Length, bobSecret.Length, bobSecret.SequenceEqual(aliceSecret));
    }

    private static SigResult LibOqsSig()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa65);
        var (publicKey, secretKey) = sig.GenerateKeypair();
        var signature = sig.Sign(Message, secretKey);

        return new(publicKey.Length, secretKey.Length, signature.Length, sig.Verify(Message, signature, publicKey));
    }
}
