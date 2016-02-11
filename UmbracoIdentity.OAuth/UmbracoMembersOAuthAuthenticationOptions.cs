namespace UmbracoIdentity.OAuth
{
    public class UmbracoMembersOAuthAuthenticationOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UmbracoMembersOAuthAuthenticationOptions"/> class.
        /// </summary>
        public UmbracoMembersOAuthAuthenticationOptions()
        {
            TokenEndpointPath = "/oauth2/token";
            AccessTokenLifeTime = 30;
            AllowInsecureHttp = false;
        }

        /// <summary>
        /// Gets or sets the issuer.
        /// </summary>
        /// <value>
        /// The issuer.
        /// </value>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the audience identifier.
        /// </summary>
        /// <value>
        /// The audience identifier.
        /// </value>
        public string AudienceId { get; set; }

        /// <summary>
        /// Gets or sets the audience secret.
        /// </summary>
        /// <value>
        /// The audience secret.
        /// </value>
        public string AudienceSecret { get; set; }

        /// <summary>
        /// Gets or sets the token endpoint path.
        /// </summary>
        /// <value>
        /// The token endpoint path.
        /// </value>
        public string TokenEndpointPath { get; set; }


        /// <summary>
        /// Gets or sets the access token life time.
        /// </summary>
        /// <value>
        /// The access token life time.
        /// </value>
        public int AccessTokenLifeTime { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [allow insecure HTTP].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [allow insecure HTTP]; otherwise, <c>false</c>.
        /// </value>
        public bool AllowInsecureHttp { get; set; }
    }
}
