using Umbraco.Core;
using Umbraco.Core.Logging;
using Umbraco.Core.Persistence;
using UmbracoIdentity.OAuth.Models;

namespace UmbracoIdentity.OAuth
{
    public class UmbracoDbOAuthStore : IOAuthStore
    {
        protected Database Db
        {
            get { return ApplicationContext.Current.DatabaseContext.Database; }
        }

        public UmbracoDbOAuthStore()
        {
            this.EnsureTablesExist();
        }

        public OAuthClient FindClient(string clientId)
        {
            return this.Db.SingleOrDefault<OAuthClient>("SELECT * FROM [OAuthClient] WHERE [ClientId] = @0",
                clientId);
        }

        public void AddRefreshToken(OAuthRefreshToken token)
        {
            this.Db.Execute("DELETE FROM [OAuthRefreshToken] WHERE [Subject] = @0 AND [ClientId] = @1 AND [UserType] = @2",
                token.Subject,
                token.ClientId,
                token.UserType);

            this.Db.Save(token);
        }

        public void RemoveRefreshToken(string refreshTokenId)
        {
            this.Db.Execute("DELETE FROM [OAuthRefreshToken] WHERE [Key] = @0",
                refreshTokenId);
        }

        public OAuthRefreshToken FindRefreshToken(string refreshTokenId)
        {
            return this.Db.SingleOrDefault<OAuthRefreshToken>("SELECT * FROM [OAuthRefreshToken] WHERE [Key] = @0",
                refreshTokenId);
        }
         
        protected void EnsureTablesExist()
        {
            // TODO: Should this be stored in UmbracoIdentity SQL CE database?
            var dbCtx = ApplicationContext.Current.DatabaseContext;
            var dbSchemaHelper = new DatabaseSchemaHelper(dbCtx.Database, LoggerResolver.Current.Logger, dbCtx.SqlSyntax);

            if (!dbSchemaHelper.TableExist(typeof(OAuthClient).Name))
            {
                // Create table
                dbSchemaHelper.CreateTable(false, typeof(OAuthClient));

                // Seed the table
                dbCtx.Database.Save(new OAuthClient
                {
                    ClientId = "DemoClient",
                    Name = "Demo Client",
                    Secret = "demo",
                    SecurityLevel = SecurityLevel.Insecure,
                    RefreshTokenLifeTime = 14400,
                    AllowedOrigin = "*"
                });
            }

            if (!dbSchemaHelper.TableExist(typeof(OAuthRefreshToken).Name))
            {
                // Create table
                dbSchemaHelper.CreateTable(false, typeof(OAuthRefreshToken));
            }
        }
    }
}
