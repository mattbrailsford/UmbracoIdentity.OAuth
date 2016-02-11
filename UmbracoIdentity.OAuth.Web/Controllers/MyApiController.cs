using System.Net.Http;
using System.Web.Http;

namespace UmbracoIdentity.OAuth.Web.Controllers
{
    public class MyApiController : ApiController
    {
        [Authorize]
        [HttpGet]
        [ActionName("Layouts")]
        public HttpResponseMessage GetLayouts()
        {
            return new HttpResponseMessage()
            {
                Content = new StringContent("GET: Test message")
            };
        }
    }
}