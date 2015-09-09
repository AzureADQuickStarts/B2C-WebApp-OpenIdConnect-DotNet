using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Extensions;
using System.Web;

namespace WebApp_OpenIDConnect_DotNet_B2C.Policies
{
    // This class is a temporary workaround for AAD B2C,
    // while our current libraries are unable to support B2C
    // out of the box.  For the original source code (with comments)
    // visit http://katanaproject.codeplex.com/SourceControl/latest#src/Microsoft.Owin.Security.OpenIdConnect/OpenidConnectAuthenticationHandler.cs
    public class PolicyOpenIdConnectAuthenticationHandler : OpenIdConnectAuthenticationHandler
    {
        private const string HandledResponse = "HandledResponse";
        private const string NonceProperty = "N";
        public const string PolicyParameter = "p";
        public const string PolicyKey = "policy";
        private const string AuthenticationPropertiesKey = "OpenIdConnect.AuthenticationProperties";

        private readonly ILogger _logger;
        private OpenIdConnectConfiguration _configuration;

        public PolicyOpenIdConnectAuthenticationHandler(ILogger logger) : base(logger)
        {
            _logger = logger;
        }

        private string CurrentUri
        {
            get
            {
                return Request.Scheme +
                       Uri.SchemeDelimiter +
                       Request.Host +
                       Request.PathBase +
                       Request.Path +
                       Request.QueryString;
            }
        }

        protected override async Task ApplyResponseGrantAsync()
        {
            AuthenticationResponseRevoke signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
            if (signout != null)
            {
                AuthenticationProperties properties = signout.Properties;

                // Enable Per-Policy Metadata Retreival
                string[] policy;
                if (Response.Headers.TryGetValue(PolicyKey, out policy))
                {
                    PolicyConfigurationManager mgr = Options.ConfigurationManager as PolicyConfigurationManager;
                    _configuration = await mgr.GetConfigurationAsync(Context.Request.CallCancelled, policy[0]);
                    Response.Headers.Remove(PolicyKey);
                }
                else
                {
                    throw new Exception("For B2C, you must pass a policy parameter in every sign out request.");
                }

                OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage()
                {
                    IssuerAddress = _configuration.EndSessionEndpoint ?? string.Empty,
                    RequestType = OpenIdConnectRequestType.LogoutRequest,
                };

                string redirect = string.Empty;
                if (properties != null && !string.IsNullOrEmpty(properties.RedirectUri))
                {
                    openIdConnectMessage.PostLogoutRedirectUri = properties.RedirectUri;
                    redirect = properties.RedirectUri;
                }
                else if (!string.IsNullOrWhiteSpace(Options.PostLogoutRedirectUri))
                {
                    openIdConnectMessage.PostLogoutRedirectUri = Options.PostLogoutRedirectUri;
                    redirect = Options.RedirectUri;
                }

                if (string.IsNullOrWhiteSpace(openIdConnectMessage.PostLogoutRedirectUri))
                {
                    throw new Exception("For B2C, the PostLogoutRedirectUri is required.");
                }
                if (string.IsNullOrWhiteSpace(redirect))
                {
                    throw new Exception("For B2C, the RedirectUri is required.");
                }

                var notification = new RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage
                };
                await Options.Notifications.RedirectToIdentityProvider(notification);

                if (!notification.HandledResponse)
                {
                    string redirectUri = notification.ProtocolMessage.CreateLogoutRequestUrl();
                    redirectUri = redirectUri + "&" + OpenIdConnectParameterNames.RedirectUri + "=" + HttpUtility.UrlEncode(redirect) + "&" + OpenIdConnectParameterNames.ClientId + "=" + Options.ClientId;
                    if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                    {
                        _logger.WriteWarning("The logout redirect URI is malformed: " + redirectUri);
                    }
                    Response.Redirect(redirectUri);
                }
            }
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge == null)
                {
                    return;
                }

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = CurrentUri;
                }

                if (!string.IsNullOrWhiteSpace(Options.RedirectUri))
                {
                    properties.Dictionary.Add(OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey, Options.RedirectUri);
                }

                // Enable Per-Policy Metadata Retreival
                string[] policy;
                if (Response.Headers.TryGetValue(PolicyKey, out policy))
                {
                    PolicyConfigurationManager mgr = Options.ConfigurationManager as PolicyConfigurationManager;
                    _configuration = await mgr.GetConfigurationAsync(Context.Request.CallCancelled, policy[0]);
                    properties.Dictionary.Add(PolicyKey, policy[0]);
                    Response.Headers.Remove(PolicyKey);
                }
                else
                {
                    throw new Exception("For B2C, you must pass a policy parameter in every challenge.");
                    return;
                }

                OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage
                {
                    ClientId = Options.ClientId,
                    IssuerAddress = _configuration.AuthorizationEndpoint ?? string.Empty,
                    RedirectUri = Options.RedirectUri,
                    RequestType = OpenIdConnectRequestType.AuthenticationRequest,
                    Resource = Options.Resource,
                    ResponseMode = OpenIdConnectResponseModes.FormPost,
                    ResponseType = Options.ResponseType,
                    Scope = Options.Scope,
                    State = AuthenticationPropertiesKey + "=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(properties)),
                };

                if (Options.ProtocolValidator.RequireNonce)
                {
                    AddNonceToMessage(openIdConnectMessage);
                }

                var notification = new RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage
                };

                await Options.Notifications.RedirectToIdentityProvider(notification);

                if (!notification.HandledResponse)
                {
                    string redirectUri = notification.ProtocolMessage.CreateAuthenticationRequestUrl();
                    if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                    {
                        _logger.WriteWarning("The authenticate redirect URI is malformed: " + redirectUri);
                    }
                    Response.Redirect(redirectUri);
                }
            }

            return;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath != (Request.PathBase + Request.Path))
            {
                return null;
            }

            OpenIdConnectMessage openIdConnectMessage = null;

            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
              && !string.IsNullOrWhiteSpace(Request.ContentType)
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                if (!Request.Body.CanSeek)
                {
                    _logger.WriteVerbose("Buffering request body");
                    MemoryStream memoryStream = new MemoryStream();
                    await Request.Body.CopyToAsync(memoryStream);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    Request.Body = memoryStream;
                }

                IFormCollection form = await Request.ReadFormAsync();
                Request.Body.Seek(0, SeekOrigin.Begin);

                openIdConnectMessage = new OpenIdConnectMessage(form);
            }

            if (openIdConnectMessage == null)
            {
                return null;
            }

            ExceptionDispatchInfo authFailedEx = null;
            string policy = null;
            try
            {
                var messageReceivedNotification = new MessageReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage
                };
                await Options.Notifications.MessageReceived(messageReceivedNotification);
                if (messageReceivedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (messageReceivedNotification.Skipped)
                {
                    return null;
                }

                AuthenticationProperties properties = GetPropertiesFromState(openIdConnectMessage.State);
                if (properties == null)
                {
                    _logger.WriteWarning("The state field is missing or invalid.");
                    return null;
                }

                if (!string.IsNullOrWhiteSpace(openIdConnectMessage.Error))
                {
                    throw new OpenIdConnectProtocolException(
                        string.Format(CultureInfo.InvariantCulture,
                                      openIdConnectMessage.Error,
                                      "", openIdConnectMessage.ErrorDescription ?? string.Empty, openIdConnectMessage.ErrorUri ?? string.Empty));
                }

                if (string.IsNullOrWhiteSpace(openIdConnectMessage.IdToken))
                {
                    _logger.WriteWarning("The id_token is missing.");
                    return null;
                }

                var securityTokenReceivedNotification = new SecurityTokenReceivedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage,
                };
                await Options.Notifications.SecurityTokenReceived(securityTokenReceivedNotification);
                if (securityTokenReceivedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (securityTokenReceivedNotification.Skipped)
                {
                    return null;
                }

                // Enable Per-Policy Metadata Retreival
                if (properties.Dictionary.TryGetValue(PolicyKey, out policy))
                {
                    PolicyConfigurationManager mgr = Options.ConfigurationManager as PolicyConfigurationManager;
                    _configuration = await mgr.GetConfigurationAsync(Context.Request.CallCancelled, policy);
                }
                else
                {
                    _logger.WriteWarning("No policy identifier was found in the Authentication Properties of the request.");
                    return null;
                }

                TokenValidationParameters tvp = Options.TokenValidationParameters.Clone();
                IEnumerable<string> issuers = new[] { _configuration.Issuer };
                tvp.ValidIssuers = (tvp.ValidIssuers == null ? issuers : tvp.ValidIssuers.Concat(issuers));
                tvp.IssuerSigningTokens = (tvp.IssuerSigningTokens == null ? _configuration.SigningTokens : tvp.IssuerSigningTokens.Concat(_configuration.SigningTokens));

                SecurityToken validatedToken;
                ClaimsPrincipal principal = Options.SecurityTokenHandlers.ValidateToken(openIdConnectMessage.IdToken, tvp, out validatedToken);
                ClaimsIdentity claimsIdentity = principal.Identity as ClaimsIdentity;

                JwtSecurityToken jwt = validatedToken as JwtSecurityToken;
                AuthenticationTicket ticket = new AuthenticationTicket(claimsIdentity, properties);

                string nonce = null;
                if (Options.ProtocolValidator.RequireNonce)
                {
                    if (String.IsNullOrWhiteSpace(openIdConnectMessage.Nonce))
                    {
                        openIdConnectMessage.Nonce = jwt.Payload.Nonce;
                    }

                    nonce = RetrieveNonce(openIdConnectMessage);
                }

                if (!string.IsNullOrWhiteSpace(openIdConnectMessage.SessionState))
                {
                    ticket.Properties.Dictionary[OpenIdConnectSessionProperties.SessionState] = openIdConnectMessage.SessionState;
                }

                if (!string.IsNullOrWhiteSpace(_configuration.CheckSessionIframe))
                {
                    ticket.Properties.Dictionary[OpenIdConnectSessionProperties.CheckSessionIFrame] = _configuration.CheckSessionIframe;
                }

                if (Options.UseTokenLifetime)
                {
                    DateTime issued = jwt.ValidFrom;
                    if (issued != DateTime.MinValue)
                    {
                        ticket.Properties.IssuedUtc = issued.ToUniversalTime();
                    }
                    DateTime expires = jwt.ValidTo;
                    if (expires != DateTime.MinValue)
                    {
                        ticket.Properties.ExpiresUtc = expires.ToUniversalTime();
                    }
                    ticket.Properties.AllowRefresh = false;
                }

                var securityTokenValidatedNotification = new SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    AuthenticationTicket = ticket,
                    ProtocolMessage = openIdConnectMessage,
                };
                await Options.Notifications.SecurityTokenValidated(securityTokenValidatedNotification);
                if (securityTokenValidatedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (securityTokenValidatedNotification.Skipped)
                {
                    return null;
                }
                ticket = securityTokenValidatedNotification.AuthenticationTicket;

                var protocolValidationContext = new OpenIdConnectProtocolValidationContext
                {
                    AuthorizationCode = openIdConnectMessage.Code,
                    Nonce = nonce,
                };

                Options.ProtocolValidator.Validate(jwt, protocolValidationContext);

                if (openIdConnectMessage.Code != null)
                {
                    var authorizationCodeReceivedNotification = new AuthorizationCodeReceivedNotification(Context, Options)
                    {
                        AuthenticationTicket = ticket,
                        Code = openIdConnectMessage.Code,
                        JwtSecurityToken = jwt,
                        ProtocolMessage = openIdConnectMessage,
                        RedirectUri = ticket.Properties.Dictionary.ContainsKey(OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey) ?
                            ticket.Properties.Dictionary[OpenIdConnectAuthenticationDefaults.RedirectUriUsedForCodeKey] : string.Empty,
                    };
                    await Options.Notifications.AuthorizationCodeReceived(authorizationCodeReceivedNotification);
                    if (authorizationCodeReceivedNotification.HandledResponse)
                    {
                        return GetHandledResponseTicket();
                    }
                    if (authorizationCodeReceivedNotification.Skipped)
                    {
                        return null;
                    }
                    ticket = authorizationCodeReceivedNotification.AuthenticationTicket;
                }

                return ticket;
            }
            catch (Exception exception)
            {
                authFailedEx = ExceptionDispatchInfo.Capture(exception);
            }

            if (authFailedEx != null)
            {
                _logger.WriteError("Exception occurred while processing message: '" + authFailedEx.ToString());

                if (Options.RefreshOnIssuerKeyNotFound && authFailedEx.SourceException.GetType().Equals(typeof(SecurityTokenSignatureKeyNotFoundException)))
                {
                    PolicyConfigurationManager mgr = Options.ConfigurationManager as PolicyConfigurationManager;
                    mgr.RequestRefresh(policy);
                }

                var authenticationFailedNotification = new AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions>(Context, Options)
                {
                    ProtocolMessage = openIdConnectMessage,
                    Exception = authFailedEx.SourceException
                };
                await Options.Notifications.AuthenticationFailed(authenticationFailedNotification);
                if (authenticationFailedNotification.HandledResponse)
                {
                    return GetHandledResponseTicket();
                }
                if (authenticationFailedNotification.Skipped)
                {
                    return null;
                }

                authFailedEx.Throw();
            }

            return null;
        }

        private AuthenticationProperties GetPropertiesFromState(string state)
        {
            int startIndex = 0;
            if (string.IsNullOrWhiteSpace(state) || (startIndex = state.IndexOf(AuthenticationPropertiesKey, StringComparison.Ordinal)) == -1)
            {
                return null;
            }

            int authenticationIndex = startIndex + AuthenticationPropertiesKey.Length;
            if (authenticationIndex == -1 || authenticationIndex == state.Length || state[authenticationIndex] != '=')
            {
                return null;
            }

            authenticationIndex++;
            int endIndex = state.Substring(authenticationIndex, state.Length - authenticationIndex).IndexOf("&", StringComparison.Ordinal);

            if (endIndex == -1)
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex).Replace('+', ' ')));
            }
            else
            {
                return Options.StateDataFormat.Unprotect(Uri.UnescapeDataString(state.Substring(authenticationIndex, endIndex).Replace('+', ' ')));
            }
        }

        private static AuthenticationTicket GetHandledResponseTicket()
        {
            return new AuthenticationTicket(null, new AuthenticationProperties(new Dictionary<string, string>() { { HandledResponse, "true" } }));
        }
    }
}
