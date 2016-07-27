using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

// The following using statements were added for this sample.
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Cookies;
using System.Security.Claims;

namespace WebApp_OpenIDConnect_DotNet_B2C.Controllers
{
    public class AccountController : Controller
    {
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {
                // TODO: Execute the sign in policy
            }
        }

        public void SignUp()
        {
            if (!Request.IsAuthenticated)
            {
                // TODO: Execute the sign up policy
            }
        }

        public void Profile()
        {
            if (Request.IsAuthenticated)
            {
                // TODO: Execute the edit profile policy
            }
        }

        public void SignOut()
        {
            if (Request.IsAuthenticated)
            {
                // TODO: Sign the user out of the app
            }
        }
	}
}