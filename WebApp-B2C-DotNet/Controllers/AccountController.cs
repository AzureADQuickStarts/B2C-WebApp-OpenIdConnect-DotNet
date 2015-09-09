using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

// The following using statements were added for this sample.
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Cookies;
using WebApp_OpenIDConnect_DotNet_B2C.Policies;
using System.Security.Claims;

namespace WebApp_OpenIDConnect_DotNet_B2C.Controllers
{
    public class AccountController : Controller
    {
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {
                // To execute a policy, you simply need to trigger an OWIN challenge.
                // You can indicate which policy to use by adding it to the response header using the PolicyKey provided.
                // The PolicyOpenIdConnectAuthenticationMiddleware will pick it up and send the right request.

                Response.Headers.Add(PolicyOpenIdConnectAuthenticationHandler.PolicyKey, Startup.SignInPolicyId);
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        public void SignUp()
        {
            if (!Request.IsAuthenticated)
            {
                Response.Headers.Add(PolicyOpenIdConnectAuthenticationHandler.PolicyKey, Startup.SignUpPolicyId);
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }


        public void Profile()
        {
            if (Request.IsAuthenticated)
            {
                Response.Headers.Add(PolicyOpenIdConnectAuthenticationHandler.PolicyKey, Startup.ProfilePolicyId);
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        public void SignOut()
        {
            // To sign out the user, you should issue an OpenIDConnect sign out request using the last policy that the user executed.
            // This is as easy as looking up the current value of the ACR claim, adding it to the response header, and making an OWIN SignOut call.

            Response.Headers.Add(PolicyOpenIdConnectAuthenticationHandler.PolicyKey, ClaimsPrincipal.Current.FindFirst(Startup.AcrClaimType).Value);
            HttpContext.GetOwinContext().Authentication.SignOut(OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
        }
	}
}