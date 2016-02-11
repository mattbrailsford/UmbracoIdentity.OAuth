using System.Configuration;
using Microsoft.Owin;
using Owin;
using Umbraco.Web;
using UmbracoIdentity.OAuth.Web;
using UmbracoOAuthApi.Models.UmbracoIdentity;

[assembly: OwinStartup("UmbracoIdentityStartup", typeof(UmbracoIdentityStartup))]

namespace UmbracoIdentity.OAuth.Web
{
    /// <summary>
    /// OWIN Startup class for UmbracoIdentity 
    /// </summary>
    public class UmbracoIdentityStartup : UmbracoDefaultOwinStartup
    {
        public override void Configuration(IAppBuilder app)
        {
            base.Configuration(app);

            //Single method to configure the Identity user manager for use with Umbraco
            app.ConfigureUserManagerForUmbracoMembers<UmbracoApplicationMember>();

            // Enable the application to use a cookie to store information for the 
            // signed in user and to use a cookie to temporarily store information 
            // about a user logging in with a third party login provider 
            // Configure the sign in cookie
            app.UseCookieAuthentication(new FrontEndCookieAuthenticationOptions());

            // Enable using OAuth authentication
            app.UseUmbracoMembersOAuthAuthentication<UmbracoApplicationMember>(
                new UmbracoMembersOAuthAuthenticationOptions
                    {
                        Issuer = "http://localhost:65214",
                        AudienceId = ConfigurationManager.AppSettings["as:AudienceId"],
                        AudienceSecret = ConfigurationManager.AppSettings["as:AudienceSecret"],
                        AllowInsecureHttp = true
                    });
        }

        
    }
}

