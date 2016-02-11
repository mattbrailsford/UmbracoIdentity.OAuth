using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.OAuth;

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

            //// Set user claims
            var identity = await userManager.ClaimsIdentityFactory.CreateAsync(userManager, user, context.Options.AuthenticationType);

            // TODO: Add roles claims once roles manager is added to UmbracoIdentity package
            //var roleManager = context.OwinContext.Get<RoleManager<IdentityRole>>()
            //foreach (var role in Roles.GetRolesForUser(user.UserName)) // Not sure if we should be using RolesManager here?
            //{
            //    identity.AddClaim(new Claim(ClaimTypes.Role, role));
            //}

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