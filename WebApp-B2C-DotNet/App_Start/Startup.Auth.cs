using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

// The following using statements were added for this sample
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Notifications;
using Microsoft.IdentityModel.Protocols;
using System.Web.Mvc;
using System.Configuration;
using System.IdentityModel.Tokens;
using WebApp_OpenIDConnect_DotNet_B2C.Policies;

namespace WebApp_OpenIDConnect_DotNet_B2C
{
	public partial class Startup
	{
        // The ACR claim is used to indicate which policy was executed
        public const string AcrClaimType = "http://schemas.microsoft.com/claims/authnclassreference";

        // App config settings
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AadInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        // B2C policy identifiers
        public static string SignUpPolicyId = ConfigurationManager.AppSettings["ida:SignUpPolicyId"];
        public static string SignInPolicyId = ConfigurationManager.AppSettings["ida:SignInPolicyId"];
        public static string ProfilePolicyId = ConfigurationManager.AppSettings["ida:UserProfilePolicyId"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            OpenIdConnectAuthenticationOptions options = new OpenIdConnectAuthenticationOptions
            {
                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = clientId,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                { 
                    AuthenticationFailed = AuthenticationFailed,
                },
                Scope = "openid",
                ResponseType = "id_token",

                // The PolicyConfigurationManager takes care of getting the correct Azure AD authentication
                // endpoints from the OpenID Connect metadata endpoint.  It is included in the PolicyAuthHelpers folder.
                ConfigurationManager = new PolicyConfigurationManager("https://login.microsoftonline.com/" + tenant + "/v2.0/.well-known/openid-configuration"),

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {  
                    NameClaimType = "name",
                },
            };

            // The PolicyOpenIdConnectAuthenticationMiddleware is a small extension of the default OpenIdConnectMiddleware
            // included in OWIN.  It is included in this sample in the PolicyAuthHelpers folder, along with a few other
            // supplementary classes related to policies.
            app.Use(typeof(PolicyOpenIdConnectAuthenticationMiddleware), app, options);
                
        }

        // Used for avoiding yellow-screen-of-death
        private Task AuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            return Task.FromResult(0);
        }
    }
}