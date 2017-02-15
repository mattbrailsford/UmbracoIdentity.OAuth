UmbracoIdentity.OAuth for Umbraco has been installed.

Before you begin however, addition configuration is required. Firstly, you'll need to add 2 new app settings to your web.config

<add key="as:AudienceId" value="xbQUxahU1VuXfDQZ90Qh4pr3r8fkaBn3OQUZEsPtF8k2OvYN" />
<add key="as:AudienceSecret" value="YXVpOWlmUWpDSWxpZTRUeVZ6MkpJUVFQZmlxOVI0YW0=" />

It is advised that you change these default values on installation. AudienceId can be any string, whereas AudienceSecret must be a string of either 32, 48 or 64 characters long and BASE64 encoded. The length of the string dictates the Hmac signing algorithm used when encrypting the JWT token. A string of length 32 will be encoded using Sha256, 48 will be Sha384 and 64 will be Sha512. The length you choose will probably be dictated by the connecting framework you use. Sha256 is most widely supported, but Sha512 is the most secure. Choose the highest strength you can.

Next, you'll need to hookup the OAuth midldleware in your UmbracoIdentityStartup.cs class. To do this, inside the ConfigureMiddleware, before the final UseUmbracoPreviewAuthentication call, insert the following code:

app.UseUmbracoMembersOAuthAuthentication<UmbracoApplicationMember>(
    new UmbracoMembersOAuthAuthenticationOptions
    {
        Issuer = "http://localhost",
        AudienceId = ConfigurationManager.AppSettings["as:AudienceId"],
        AudienceSecret = ConfigurationManager.AppSettings["as:AudienceSecret"],
        AllowInsecureHttp = true
    });

You should update the issuer to the end domain of your application, and it is recommended to set AllowInsecureHttp to false when you deploy to live, at which point all requests should be sent over https.