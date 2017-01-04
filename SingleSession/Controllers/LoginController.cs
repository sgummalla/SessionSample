using SingleSession.Models;
using SingleSession.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace SingleSession.Controllers
{
    public class LoginController : Controller
    {
        public ActionResult Index()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        public ActionResult Index(LoginViewModel loginViewModel, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = MvcApplication.Users.FirstOrDefault(p => p.UserName == loginViewModel.UserName
                    && p.Password == loginViewModel.Password);
                if (user != null)
                {
                    FormsAuthentication.SetAuthCookie(loginViewModel.UserName, false);
                    SingleSessionPreparation.CreateAndStoreSessionToken(loginViewModel.UserName);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Invalid UserName/Password");
                }
            }

            return View(loginViewModel);
        }

        public ActionResult LogOut()
        {
            FormsAuthentication.SignOut();
            return RedirectToActionPermanent("Index");
        }
    }
}
