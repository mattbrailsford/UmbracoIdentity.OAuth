using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.OAuth;
using UmbracoIdentity.Models;

namespace UmbracoIdentity.OAuth
{
    internal class UmbracoIdentityMembersOAuthServerProvider<TUser> : UmbracoIdentityOAuthServerProvider
        where TUser : UmbracoIdentityMember, new ()
    {
        public UmbracoIdentityMembersOAuthServerProvider(IOAuthStore oauthStore)
            : base(oauthStore)
        { }

        public override async Task<ClaimsIdentity> DoGrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            // Validate user
            var userManager = context.OwinContext.GetUserManager<UmbracoMembersUserManager<TUser>>();
            var user = await userManager.FindAsync(context.UserName, context.Password);
            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return null;
            }

            // Set user claims
            var identity = await userManager.ClaimsIdentityFactory.CreateAsync(userManager, user, context.Options.AuthenticationType);

            return identity;
        }

        public override async Task<ClaimsIdentity> DoGrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);

            // Update claims if needed here
            // newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            return newIdentity;
        }
    }
}