using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using UmbracoIdentity.OAuth.DataFormats;

namespace UmbracoIdentity.OAuth
{   
    public static class AppBuilderExtensions
    {
        /// <summary>
        /// Configure OAuth authentication using umbraco members.
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <param name="app">The application.</param>
        /// <param name="options">The options.</param>
        public static void UseUmbracoMembersOAuthAuthentication<TUser>(this IAppBuilder app,
            UmbracoMembersOAuthAuthenticationOptions options)
            where TUser : UmbracoIdentityMember, new()
        {
            app.UseUmbracoMembersOAuthAuthentication<TUser, UmbracoDbOAuthStore>(options);
        }

        /// <summary>
        /// Configure OAuth authentication using umbraco members with custom OAuth store
        /// </summary>
        /// <typeparam name="TUser">The type of the user.</typeparam>
        /// <typeparam name="TOAuthStore">The type of the o authentication store.</typeparam>
        /// <param name="app">The application.</param>
        /// <param name="options">The options.</param>
        public static void UseUmbracoMembersOAuthAuthentication<TUser, TOAuthStore>(this IAppBuilder app,
            UmbracoMembersOAuthAuthenticationOptions options)
            where TUser : UmbracoIdentityMember, new()
            where TOAuthStore : IOAuthStore, new()
        {
            var oauthStore = new TOAuthStore();
            var oauthServerProvider = new UmbracoIdentityMembersOAuthServerProvider<TUser>(oauthStore);
            var oauthRefreshTokenProvider = new UmbracoIdentityMembersOAuthRefreshTokenProvider<TUser>(oauthStore);

            app.UseUmbracoIdentityOAuthAuthentication(options, oauthServerProvider, oauthRefreshTokenProvider);
        }

        /// <summary>
        /// Uses the umbraco identity o authentication authentication.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <param name="options">The options.</param>
        /// <param name="oAuthServerProvider">The o authentication server provider.</param>
        /// <param name="oAuthRefreshTokenProvider">The o authentication refresh token provider.</param>
        private static void UseUmbracoIdentityOAuthAuthentication(
            this IAppBuilder app,
            UmbracoMembersOAuthAuthenticationOptions options,
            UmbracoIdentityOAuthServerProvider oAuthServerProvider,
            UmbracoIdentityOAuthRefreshTokenProvider oAuthRefreshTokenProvider)
        {
            // Decode audience secret
            var audienceSecretBytes = TextEncodings.Base64Url.Decode(options.AudienceSecret);

            // Define OAuth server
            var oAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = options.AllowInsecureHttp,
                TokenEndpointPath = new PathString(options.TokenEndpointPath),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(options.AccessTokenLifeTime),
                AccessTokenFormat = new JwtDataFormat(options.Issuer, options.AudienceId, audienceSecretBytes),
                Provider = oAuthServerProvider,
                RefreshTokenProvider = oAuthRefreshTokenProvider
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(oAuthServerOptions);
            app.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AllowedAudiences = new[] { options.AudienceId },
                IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                    {
                        new SymmetricKeyIssuerSecurityTokenProvider(options.Issuer, audienceSecretBytes)
                    }
            });
        }
    }
}
