using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace WebApp_OpenIDConnect_DotNet_B2C.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        // TODO: Protect this route with the sign in policy
        public ActionResult Claims()
        {
            // TODO: Extract claims about the user
        }

        public ActionResult Error(string message)
        {
            ViewBag.Message = message;

            return View("Error");
        }
    }
}