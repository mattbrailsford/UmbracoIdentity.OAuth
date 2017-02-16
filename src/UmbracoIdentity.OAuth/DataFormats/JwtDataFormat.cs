using System;
using System.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using UmbracoIdentity.OAuth.Tokens;

namespace UmbracoIdentity.OAuth.DataFormats
{
    internal class JwtDataFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly string _issuer;
        private readonly string _audienceId;
        private readonly byte[] _audienceSecret;

        public JwtDataFormat(string issuer, string audienceId, byte[] audienceSecret)
        {
            this._issuer = issuer;
            this._audienceId = audienceId;
            this._audienceSecret = audienceSecret;
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            var signingKey = new HmacSigningCredentials(this._audienceSecret);

            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;

            var token = new JwtSecurityToken(this._issuer, this._audienceId, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingKey);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);

            return jwt;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}