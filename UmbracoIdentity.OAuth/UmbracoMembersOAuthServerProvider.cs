using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using UmbracoIdentity.OAuth.Extensions;
using UmbracoIdentity.OAuth.Models;

namespace UmbracoIdentity.OAuth
{
    public class UmbracoMembersOAuthServerProvider<TUser> : OAuthAuthorizationServerProvider
        where TUser : UmbracoIdentityMember, new()
    {
        private IOAuthStore _oauthStore;

        public UmbracoMembersOAuthServerProvider(IOAuthStore oauthStore)
        {
            this._oauthStore = oauthStore;
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Validate that the data is in the request
            string clientId;
            string clientSecret;

            // Parse client credentials
            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            // Ensure a client id was passed in
            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            // Lookup the client id
            var client = this._oauthStore.FindClient(context.ClientId);

            // Make sure we find a client
            if (client == null)
            {
                context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            // Validate client secret for secure applications
            if (client.SecurityLevel == SecurityLevel.Secure)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError("invalid_clientId", "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }

                if (client.Secret != clientSecret.GenerateHash())
                {
                    context.SetError("invalid_clientId", "Client secret is invalid.");
                    return Task.FromResult<object>(null);
                }
            }

            // Make sure client is active
            if (!client.Active)
            {
                context.SetError("invalid_clientId", "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            // Stash allowed origin / refresh token life span for easy access later on
            context.OwinContext.Set("as:clientAllowedOrigin", client.AllowedOrigin);
            context.OwinContext.Set("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());
 
            // Validate the request
            context.Validated();
            return Task.FromResult(0);

        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            // Set cors headers
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin") ?? "*";
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            // Validate user
            var userManager = context.OwinContext.GetUserManager<UmbracoMembersUserManager<TUser>>();
            var user = await userManager.FindAsync(context.UserName, context.Password);
            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }

            // Set user claims
            var identity = await userManager.ClaimsIdentityFactory.CreateAsync(userManager, user, context.Options.AuthenticationType);
 
            // TODO: Add roles claims once roles manager is added to UmbracoIdentity package
            //var roleManager = context.OwinContext.Get<RoleManager<IdentityRole>>()
            //foreach (var role in Roles.GetRolesForUser(user.UserName)) // Not sure if we should be using RolesManager here?
            //{
            //    identity.AddClaim(new Claim(ClaimTypes.Role, role));
            //}

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { "as:client_id", context.ClientId ?? string.Empty },
                    { "userName", context.UserName }
                });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);
            
        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);

            // Update claims if needed here
            // newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }
    }
}