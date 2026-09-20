#if !NET5_0_OR_GREATER
// `init` accessors are a compiler feature that needs this marker type. .NET 5 and
// later ship it; .NET Standard 2.1 does not, so the SDK declares its own —
// internal, so it never collides with a consumer's copy. Without it the whole
// library fails to build for that target, which is the older .NET the package
// still supports.
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit
    {
    }
}
#endif
