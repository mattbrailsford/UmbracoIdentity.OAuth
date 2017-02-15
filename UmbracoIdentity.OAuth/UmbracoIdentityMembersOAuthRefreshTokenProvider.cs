using UmbracoIdentity.Models;

namespace UmbracoIdentity.OAuth
{
    internal class UmbracoIdentityMembersOAuthRefreshTokenProvider<TUser> : UmbracoIdentityOAuthRefreshTokenProvider<TUser>
        where TUser : UmbracoIdentityMember
    {
        public UmbracoIdentityMembersOAuthRefreshTokenProvider(IOAuthStore oauthStore)
            : base(oauthStore)
        { }
    }
}