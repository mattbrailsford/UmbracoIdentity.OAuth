using System;
using System.Security.Cryptography;

namespace UmbracoIdentity.OAuth.Extensions
{
    public static class StringExtensions
    {
        internal static string GenerateHash(this string input)
        {
            HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider();
            var byteValue = System.Text.Encoding.UTF8.GetBytes(input);
            var byteHash = hashAlgorithm.ComputeHash(byteValue);
            return Convert.ToBase64String(byteHash);
        }
    }
}