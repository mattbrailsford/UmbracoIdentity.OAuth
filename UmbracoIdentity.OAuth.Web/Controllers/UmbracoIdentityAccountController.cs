using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Umbraco.Core;
using Umbraco.Web;
using Umbraco.Web.Models;
using Umbraco.Web.Mvc;
using UmbracoOAuthApi.Models.UmbracoIdentity;

namespace UmbracoIdentity.OAuth.Web.Controllers
{
    [Authorize]
    public class UmbracoIdentityAccountController : SurfaceController
    {
        private UmbracoMembersUserManager<UmbracoApplicationMember> _userManager;

        protected IOwinContext OwinContext
        {
            get { return this.Request.GetOwinContext(); }
        }

        public UmbracoMembersUserManager<UmbracoApplicationMember> UserManager
        {
            get
            {
                return this._userManager ?? (this._userManager = this.OwinContext
                    .GetUserManager<UmbracoMembersUserManager<UmbracoApplicationMember>>());
            }
        }

        #region External login and registration

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            if (returnUrl.IsNullOrWhiteSpace())
            {
                returnUrl = this.Request.RawUrl;
            }

            // Request a redirect to the external login provider
            return new ChallengeResult(provider,
                this.Url.SurfaceAction<UmbracoIdentityAccountController>("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await this.OwinContext.Authentication.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                //go home, invalid callback
                return this.RedirectToLocal(returnUrl);
            }

            // Sign in the user with this external login provider if the user already has a login
            var user = await this.UserManager.FindAsync(loginInfo.Login);
            if (user != null)
            {
                await this.SignInAsync(user, isPersistent: false);
                return this.RedirectToLocal(returnUrl);
            }
            else
            {
                // If the user does not have an account, then prompt the user to create an account
                this.ViewBag.ReturnUrl = returnUrl;
                this.ViewBag.LoginProvider = loginInfo.Login.LoginProvider;

                return this.View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (this.User.Identity.IsAuthenticated)
            {
                //go home, already authenticated
                return this.RedirectToLocal(returnUrl);
            }

            if (this.ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await this.OwinContext.Authentication.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return this.View("ExternalLoginFailure");
                }

                var user = new UmbracoApplicationMember()
                {
                    Name = info.ExternalIdentity.Name,
                    UserName = model.Email,
                    Email = model.Email
                };

                var result = await this.UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await this.UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await this.SignInAsync(user, isPersistent: false);

                        // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                        // Send an email with this link
                        // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                        // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                        // SendEmail(user.Email, callbackUrl, "Confirm your account", "Please confirm your account by clicking this link");

                        return this.RedirectToLocal(returnUrl);
                    }
                }
                this.AddModelErrors(result);
            }

            this.ViewBag.ReturnUrl = returnUrl;
            return this.View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider, string returnUrl = null)
        {
            if (returnUrl.IsNullOrWhiteSpace())
            {
                returnUrl = this.Request.RawUrl;
            }

            // Request a redirect to the external login provider to link a login for the current user
            return new ChallengeResult(provider,
                this.Url.SurfaceAction<UmbracoIdentityAccountController>("LinkLoginCallback", new { ReturnUrl = returnUrl }),
                this.User.Identity.GetUserId());
        }

        [HttpGet]
        public async Task<ActionResult> LinkLoginCallback(string returnUrl)
        {
            var loginInfo = await this.AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, this.User.Identity.GetUserId());
            if (loginInfo == null)
            {
                this.TempData["LinkLoginError"] = new[] { "An error occurred, could not get external login info" };
                return this.RedirectToLocal(returnUrl);
            }
            var result = await this.UserManager.AddLoginAsync(IdentityExtensions.GetUserId<int>(this.User.Identity), loginInfo.Login);
            if (result.Succeeded)
            {
                return this.RedirectToLocal(returnUrl);
            }

            this.TempData["LinkLoginError"] = result.Errors.ToArray();
            return this.RedirectToLocal(returnUrl);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Disassociate(string loginProvider, string providerKey)
        {
            var result = await this.UserManager.RemoveLoginAsync(
                IdentityExtensions.GetUserId<int>(this.User.Identity),
                new UserLoginInfo(loginProvider, providerKey));

            if (result.Succeeded)
            {
                var user = await this.UserManager.FindByIdAsync(IdentityExtensions.GetUserId<int>(this.User.Identity));
                await this.SignInAsync(user, isPersistent: false);
                return this.RedirectToCurrentUmbracoPage();
            }
            else
            {
                this.AddModelErrors(result);
                return this.CurrentUmbracoPage();
            }
        }

        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return this.View();
        }

        [ChildActionOnly]
        public ActionResult RemoveAccountList()
        {
            var linkedAccounts = this.UserManager.GetLogins(IdentityExtensions.GetUserId<int>(this.User.Identity));
            this.ViewBag.ShowRemoveButton = this.HasPassword() || linkedAccounts.Count > 1;
            return this.PartialView(linkedAccounts);
        }

        #endregion

        [ChildActionOnly]
        public ActionResult ManagePassword()
        {
            this.ViewBag.HasLocalPassword = this.HasPassword();
            return this.View();
        }

        [NotChildAction]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ManagePassword([Bind(Prefix = "managePasswordModel")] UserPasswordModel model)
        {
            bool hasPassword = this.HasPassword();
            this.ViewBag.HasLocalPassword = hasPassword;

            //vaidate their passwords match
            if (model.NewPassword != model.ConfirmPassword)
            {
                this.ModelState.AddModelError("managePasswordModel.ConfirmPassword", "Passwords do not match");
            }

            if (hasPassword)
            {
                if (this.ModelState.IsValid)
                {
                    IdentityResult result = await this.UserManager.ChangePasswordAsync(IdentityExtensions.GetUserId<int>(this.User.Identity), model.OldPassword, model.NewPassword);
                    if (result.Succeeded)
                    {
                        var user = await this.UserManager.FindByIdAsync(IdentityExtensions.GetUserId<int>(this.User.Identity));
                        await this.SignInAsync(user, isPersistent: false);
                        this.TempData["ChangePasswordSuccess"] = true;
                        return this.RedirectToCurrentUmbracoPage();
                    }
                    else
                    {
                        this.AddModelErrors(result, "managePasswordModel");
                    }
                }
            }
            else
            {
                // User does not have a password so remove any validation errors caused by a missing OldPassword field
                var state = this.ModelState["managePasswordModel.OldPassword"];
                if (state != null)
                {
                    state.Errors.Clear();
                }

                if (this.ModelState.IsValid)
                {
                    IdentityResult result = await this.UserManager.AddPasswordAsync(IdentityExtensions.GetUserId<int>(this.User.Identity), model.NewPassword);
                    if (result.Succeeded)
                    {
                        this.TempData["ChangePasswordSuccess"] = true;
                        return this.RedirectToCurrentUmbracoPage();
                    }
                    else
                    {
                        this.AddModelErrors(result, "managePasswordModel");
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return this.CurrentUmbracoPage();
        }

        #region Standard login and registration

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> HandleLogin([Bind(Prefix = "loginModel")] LoginModel model)
        {
            if (this.ModelState.IsValid)
            {
                var user = await this.UserManager.FindAsync(model.Username, model.Password);
                if (user != null)
                {
                    await this.SignInAsync(user, true);
                    return this.RedirectToCurrentUmbracoPage();
                }
                this.ModelState.AddModelError("loginModel", "Invalid username or password");
            }

            return this.CurrentUmbracoPage();
        }

        [HttpPost]
        public ActionResult HandleLogout([Bind(Prefix = "logoutModel")]PostRedirectModel model)
        {
            if (this.ModelState.IsValid == false)
            {
                return this.CurrentUmbracoPage();
            }

            if (this.Members.IsLoggedIn())
            {
                //ensure to only clear the default cookies
                this.OwinContext.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie, DefaultAuthenticationTypes.ExternalCookie);
            }

            //if there is a specified path to redirect to then use it
            if (model.RedirectUrl.IsNullOrWhiteSpace() == false)
            {
                return this.Redirect(model.RedirectUrl);
            }

            //redirect to current page by default
            this.TempData["LogoutSuccess"] = true;
            return this.RedirectToCurrentUmbracoPage();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> HandleRegisterMember([Bind(Prefix = "registerModel")]RegisterModel model)
        {

            if (this.ModelState.IsValid == false)
            {
                return this.CurrentUmbracoPage();
            }

            var user = new UmbracoApplicationMember()
            {
                UserName = model.UsernameIsEmail || model.Username == null ? model.Email : model.Username,
                Email = model.Email,
                MemberProperties = model.MemberProperties
            };

            var result = await this.UserManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await this.SignInAsync(user, isPersistent: false);

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                this.TempData["FormSuccess"] = true;

                //if there is a specified path to redirect to then use it
                if (model.RedirectUrl.IsNullOrWhiteSpace() == false)
                {
                    return this.Redirect(model.RedirectUrl);
                }
                //redirect to current page by default                
                return this.RedirectToCurrentUmbracoPage();
            }
            else
            {
                this.AddModelErrors(result, "registerModel");
            }

            return this.CurrentUmbracoPage();
        }

        #endregion

        #region Helpers

        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return this.HttpContext.GetOwinContext().Authentication;
            }
        }

        private async Task SignInAsync(UmbracoApplicationMember member, bool isPersistent)
        {
            this.OwinContext.Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            this.OwinContext.Authentication.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent },
                await member.GenerateUserIdentityAsync(this.UserManager));
        }

        private void AddModelErrors(IdentityResult result, string prefix = "")
        {
            foreach (var error in result.Errors)
            {
                this.ModelState.AddModelError(prefix, error);
            }
        }

        private bool HasPassword()
        {
            var user = this.UserManager.FindById(IdentityExtensions.GetUserId<int>(this.User.Identity));
            if (user != null)
            {
                return !user.PasswordHash.IsNullOrWhiteSpace();
            }
            return false;
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (this.Url.IsLocalUrl(returnUrl))
            {
                return this.Redirect(returnUrl);
            }
            return this.Redirect("/");
        }

        private class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri, string userId = null)
            {
                this.LoginProvider = provider;
                this.RedirectUri = redirectUri;
                this.UserId = userId;
            }

            private string LoginProvider { get; set; }
            private string RedirectUri { get; set; }
            private string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties() { RedirectUri = this.RedirectUri };
                if (this.UserId != null)
                {
                    properties.Dictionary[XsrfKey] = this.UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, this.LoginProvider);
            }
        }

        #endregion

    }

}
