using UmbracoIdentity.OAuth.Models;

namespace UmbracoIdentity.OAuth
{
    /// <summary>
    /// Interface for an OAuth store
    /// </summary>
    public interface IOAuthStore
    {
        /// <summary>
        /// Finds the client.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <returns></returns>
        OAuthClient FindClient(string clientId);

        /// <summary>
        /// Adds the refresh token.
        /// </summary>
        /// <param name="token">The token.</param>
        void AddRefreshToken(OAuthRefreshToken token);

        /// <summary>
        /// Removes the refresh token.
        /// </summary>
        /// <param name="refreshTokenId">The refresh token identifier.</param>
        void RemoveRefreshToken(string refreshTokenId);

        /// <summary>
        /// Finds the refresh token.
        /// </summary>
        /// <param name="refreshTokenId">The refresh token identifier.</param>
        /// <returns></returns>
        OAuthRefreshToken FindRefreshToken(string refreshTokenId);
    }
}
