===============================================================
 UmbracoIdentity.OAuth
===============================================================

UmbracoIdentity.OAuth for Umbraco has been installed.

Before you begin however, addition configuration is required. Firstly, please make sure you follow any configuration instructions for UmbracoIdentity before configuring UmbracoIdentity.OAuth.

Next, you'll need to add the ~/oauth2/ path to your umbracoReservedPaths app setting in the web.config, then add 2 new app settings as follows:

<add key="as:AudienceId" value="xbQUxahU1VuXfDQZ90Qh4pr3r8fkaBn3OQUZEsPtF8k2OvYN" />
<add key="as:AudienceSecret" value="YXVpOWlmUWpDSWxpZTRUeVZ6MkpJUVFQZmlxOVI0YW0=" />

It is advised that you change these default values on installation. AudienceId can be any string, whereas AudienceSecret must be a string of either 32, 48 or 64 characters long and BASE64 encoded. The length of the string dictates the Hmac signing algorithm used when encrypting the JWT token. A string of length 32 will be encoded using Sha256, 48 will be Sha384 and 64 will be Sha512. The length you choose will probably be dictated by the connecting framework you use. Sha256 is most widely supported, but Sha512 is the most secure. Choose the highest strength you can.

Next, you'll need to hookup the OAuth midldleware in your UmbracoIdentityStartup.cs class. To do this, inside the ConfigureMiddleware method, before the final UseUmbracoPreviewAuthentication call, insert the following code:

app.UseUmbracoMembersOAuthAuthentication<UmbracoApplicationMember>(
    new UmbracoMembersOAuthAuthenticationOptions
    {
        Issuer = "http://localhost",
        AudienceId = ConfigurationManager.AppSettings["as:AudienceId"],
        AudienceSecret = ConfigurationManager.AppSettings["as:AudienceSecret"],
        AllowInsecureHttp = true
    });

You should update the issuer to the end domain of your application, and it is strongly recommended to set AllowInsecureHttp to false when you deploy to live, at which point all requests should be sent over https.

Once installed, you'll need to configure an OAuthClient in the database (a demo one is created on install). An OAuthClient consists of the following keys:

* Id = Database id column
* ClientId = A unique alias for the client. Will be used within auth requests to identify the associated client
* Name = A friendly name for the client
* Secret = An SHA256 hashed random string used to validate authentication requests from secure applications
* SecurityLevel = Indentifies whether the client is a secure, compiled app = 1, or insecure, noncompiled app, such as javascript = 0
* Active = Flag to easily enable / disable the client
* RefreshTokenLifeTime = Time in minutes a refresh token is valid for, the shorter the more secure, but requires member to login more if left for longer periods
* AllowedOrigin = Sets the Access-Control-Allow-Origin header on auth requests, restricting requests to specific domains. If configuring an insecure app, it's strongly recommended this is configured to allowed domains only. Wildcard * allows all origins.

To authenticate a member, a post request should be made to /oauth2/token with a body containing the following key values:

* grant_type = password
* username = member user name
* password = member password
* client_id = a valid client id

If a token expires, you can request a refresh token by posting to /oauth2/token with a body containing the following key values:

* grant_type = refresh_token
* refresh_token = the refresh token from the original token auth request
* client_id = a valid client id

From this point, you can secure your API controllers by simply using the [Authorize] attribure, and making sure all requests include the following header:

* Authorization = "Bearer " + the access_token returned from the last auth token request