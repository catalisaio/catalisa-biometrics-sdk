using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Catalisa.Biometrics;

/// <summary>
/// Ed25519 verification.
///
/// .NET has no Ed25519 of its own, and the evidence receipt is signed with it —
/// so this is the SDK's single dependency, BouncyCastle, chosen because it is
/// fully managed: no native library to ship, nothing to build per platform.
/// </summary>
internal static class Ed25519
{
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        // 32-byte key, 64-byte signature: RFC 8032 fixes both, and a wrong length
        // would throw inside BouncyCastle instead of answering "not valid".
        if (publicKey.Length != Ed25519PublicKeyParameters.KeySize || signature.Length != 64)
        {
            return false;
        }
        var parameters = new Ed25519PublicKeyParameters(publicKey, 0);
        var verifier = new Ed25519Signer();
        verifier.Init(false, parameters);
        verifier.BlockUpdate(message, 0, message.Length);

        return verifier.VerifySignature(signature);
    }
}
