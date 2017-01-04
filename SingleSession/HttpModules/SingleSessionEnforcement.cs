using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;

namespace SingleSession.HttpModules
{
    /// <summary>
    /// Enforces a single login session
    /// Needs an entry in Web.Config, exactly where depends on the version of IIS, but you
    /// can safely put it in both places.
    /// 1:
    ///  <system.web>
    ///     <httpModules>
    ///      <add name="SingleSessionEnforcement" type="SingleSessionEnforcement" />
    ///    </httpModules>
    ///  </system.web>
    /// 2:
    ///  <system.webServer>
    ///    <modules runAllManagedModulesForAllRequests="true">
    ///      <add name="SingleSessionEnforcement" type="SingleSessionEnforcement" />
    ///    </modules>
    ///  </system.webServer>
    /// Also, slidingExpiration for the forms must be set to false, also set a 
    /// suitable timeout period (in minutes)
    ///  <authentication mode="Forms">
    ///   <forms protection="All" slidingExpiration="false" loginUrl="login.aspx" timeout="600" />
    ///  </authentication>
    /// </summary>
    public class SingleSessionEnforcement : IHttpModule
    {
        public SingleSessionEnforcement()
        {
            // No construction needed
        }

        private void OnPostAuthenticate(Object sender, EventArgs e)
        {
            Guid sessionToken;

            HttpApplication httpApplication = (HttpApplication)sender;
            HttpContext httpContext = httpApplication.Context;

            // Check user's session token
            if (httpContext.User.Identity.IsAuthenticated)
            {
                FormsAuthenticationTicket authenticationTicket =
                    ((FormsIdentity)httpContext.User.Identity).Ticket;

                if (authenticationTicket.UserData != "")
                {
                    sessionToken = new Guid(authenticationTicket.UserData);
                }
                else
                {
                    // No authentication ticket found so logout this user
                    // Should never hit this code
                    FormsAuthentication.SignOut();
                    FormsAuthentication.RedirectToLoginPage();
                    return;
                }

                var currentUser = MvcApplication.Users.FirstOrDefault(p => p.UserName == httpContext.User.Identity.Name);

                // May want to add a conditional here so we only check
                // if the user needs to be checked. For instance, your business
                // rules for the application may state that users in the Admin
                // role are allowed to have multiple sessions
                if (string.IsNullOrEmpty(currentUser.Comment))
                {
                    FormsAuthentication.SignOut();
                    FormsAuthentication.RedirectToLoginPage();
                }
                else
                {
                    Guid storedToken = new Guid(currentUser.Comment);

                    if (sessionToken != storedToken)
                    {
                        // Stored session does not match one in authentication
                        // ticket so logout the user
                        FormsAuthentication.SignOut();
                        FormsAuthentication.RedirectToLoginPage();
                    }
                }
            }
        }

        public void Dispose()
        {
            // Nothing to dispose
        }

        public void Init(HttpApplication context)
        {
            context.PostAuthenticateRequest += new EventHandler(OnPostAuthenticate);
        }
    }
}