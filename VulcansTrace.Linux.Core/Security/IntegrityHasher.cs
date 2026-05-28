using System.Security.Cryptography;

namespace VulcansTrace.Linux.Core.Security;

/// <summary>
/// Provides cryptographic hash functions for data integrity verification.
/// </summary>
/// <remarks>
/// Used by the evidence system to compute SHA-256 hashes for files and HMAC-SHA256 signatures for manifests.
/// </remarks>
public sealed class IntegrityHasher
{
    /// <summary>
    /// Computes a SHA-256 hash of the specified data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>A 32-byte SHA-256 hash.</returns>
    public byte[] ComputeSha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    /// <summary>
    /// Computes an HMAC-SHA256 signature of the specified data.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="key">The secret key for HMAC computation.</param>
    /// <returns>A 32-byte HMAC-SHA256 signature.</returns>
    public byte[] ComputeHmacSha256(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }
}