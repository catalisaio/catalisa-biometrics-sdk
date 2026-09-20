using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Catalisa.Biometrics;

/// <summary>
/// RSA-SHA256 verification for webhook deliveries.
///
/// It goes through BouncyCastle instead of System.Security.Cryptography because
/// the package also targets the older .NET, where RSA cannot read a PEM. Using
/// the same library the Ed25519 receipt already needs keeps one crypto path for
/// every target, rather than two that could drift.
/// </summary>
internal static class Rsa
{
    public static bool VerifySha256(string publicKeyPem, byte[] message, byte[] signature)
    {
        var parameters = ReadPublicKey(publicKeyPem);
        var verifier = SignerUtilities.GetSigner("SHA-256withRSA");
        verifier.Init(false, parameters);
        verifier.BlockUpdate(message, 0, message.Length);

        return verifier.VerifySignature(signature);
    }

    private static AsymmetricKeyParameter ReadPublicKey(string pem)
    {
        using var reader = new StringReader(pem);
        var parsed = new PemReader(reader).ReadObject();

        return parsed switch
        {
            AsymmetricKeyParameter key when !key.IsPrivate => key,
            _ => throw new InvalidKeyException("not an RSA public key in PEM form"),
        };
    }
}
