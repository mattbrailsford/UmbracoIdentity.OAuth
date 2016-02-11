namespace UmbracoIdentity.OAuth
{
    internal class UmbracoIdentityMembersOAuthRefreshTokenProvider<TUser> : UmbracoIdentityOAuthRefreshTokenProvider<TUser>
        where TUser : UmbracoIdentityMember, new()
    {
        public UmbracoIdentityMembersOAuthRefreshTokenProvider(IOAuthStore oauthStore)
            : base(oauthStore)
        { }
    }
}