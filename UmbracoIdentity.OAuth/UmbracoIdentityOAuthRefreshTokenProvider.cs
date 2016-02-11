using System;
using System.Threading.Tasks;
using ClientDependency.Core;
using Microsoft.Owin.Security.Infrastructure;
using UmbracoIdentity.OAuth.Models;

namespace UmbracoIdentity.OAuth
{
    internal abstract class UmbracoIdentityOAuthRefreshTokenProvider : IAuthenticationTokenProvider
    {
        private IOAuthStore _oauthStore;

        protected UmbracoIdentityOAuthRefreshTokenProvider(IOAuthStore oauthStore)
        {
            this._oauthStore = oauthStore;
        }

        protected abstract Type UserType { get;  }

        public virtual async Task CreateAsync(AuthenticationTokenCreateContext context)
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
                    UserType = UserType.Name,
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

        public virtual async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
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

        public virtual void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        public virtual void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }
    }

    internal abstract class UmbracoIdentityOAuthRefreshTokenProvider<TUser> : UmbracoIdentityOAuthRefreshTokenProvider
    {
        protected UmbracoIdentityOAuthRefreshTokenProvider(IOAuthStore oauthStore)
            : base(oauthStore)
        { }

        protected override Type UserType
        {
            get { return typeof(TUser); }
        }
    }
}