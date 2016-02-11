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
            var store = new TOAuthStore();

            // Decode audience secret
            var audienceSecretBytes = TextEncodings.Base64Url.Decode(options.AudienceSecret);

            // Define OAuth server
            var oAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = options.AllowInsecureHttp,
                TokenEndpointPath = new PathString(options.TokenEndpointPath),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(options.AccessTokenLifeTime),
                AccessTokenFormat = new JwtDataFormat(options.Issuer, options.AudienceId, audienceSecretBytes),
                Provider = new UmbracoMembersOAuthServerProvider<TUser>(store),
                RefreshTokenProvider = new UmbracoMembersOAuthRefreshTokenProvider(store)
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
