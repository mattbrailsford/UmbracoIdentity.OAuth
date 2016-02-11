using System;
using System.Threading.Tasks;
using ClientDependency.Core;
using Microsoft.Owin.Security.Infrastructure;
using UmbracoIdentity.OAuth.Models;

namespace UmbracoIdentity.OAuth
{
    public class UmbracoMembersOAuthRefreshTokenProvider : IAuthenticationTokenProvider
    {
        private IOAuthStore _oauthStore;

        public UmbracoMembersOAuthRefreshTokenProvider(IOAuthStore oauthStore)
        {
            this._oauthStore = oauthStore;
        }

        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var clientId = context.Ticket.Properties.Dictionary["as:client_id"];
            if (string.IsNullOrEmpty(clientId))
                return;

            var refreshTokenId = Guid.NewGuid().ToString("n");

            await Task.Run(() => {

                var refreshTokenLifeTime = context.OwinContext.Get<string>("as:clientRefreshTokenLifeTime");

                var token = new OAuthRefreshToken()
                {
                    Key = refreshTokenId.GenerateHash(),
                    ClientId = clientId,
                    Subject = context.Ticket.Identity.Name,
                    IssuedUtc = DateTime.UtcNow,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(refreshTokenLifeTime))
                };

                context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
                context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

                token.ProtectedTicket = context.SerializeTicket();

                this._oauthStore.AddRefreshToken(token);

            });

            context.SetToken(refreshTokenId);
        }

        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            var hashedTokenId = context.Token.GenerateHash();

            await Task.Run(() => {

                var token = this._oauthStore.FindRefreshToken(hashedTokenId);
                if (token != null)
                {
                    context.DeserializeTicket(token.ProtectedTicket);
                    this._oauthStore.RemoveRefreshToken(hashedTokenId);
                }
            
            });
        }

        public void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }
    }
}