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
            // TODO: Execute a sign in policy
        }

        public void SignUp()
        {
            // TODO: Execute a sign up policy
        }

        public void Profile()
        {
            // TODO: Execute an edit profile policy
        }

        public void SignOut()
        {
            // TODO: Sign the user out using OWIN.
        }
	}
}