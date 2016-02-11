using System.Web.Http;
using System.Web.Mvc;
using Umbraco.Core;

namespace UmbracoIdentity.OAuth.Web
{
    public class Boostrap : ApplicationEventHandler
    {
        protected override void ApplicationStarted(UmbracoApplicationBase umbracoApplication, ApplicationContext applicationContext)
        {
            // Define custom API route
            GlobalConfiguration.Configuration.Routes.MapHttpRoute(
                "MyApi",
                "api/v1/{action}/{id}", 
                new
                {
                    controller = "MyApi",
                    action = UrlParameter.Optional,
                    id = UrlParameter.Optional
                });
        }
    }
}