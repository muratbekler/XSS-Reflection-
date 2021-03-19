using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using TestWep.Base;
using TestWep.Models;

namespace TestWep.Controllers
{
    public class HomeController : BaseController
    {
        public ActionResult Index()
        {
            AClass model = new AClass
            {
                Id = 1001,
                AName = "Murat",
                ListB = new List<BClass>
                {
                    new BClass
                    {
                        Id = 101,
                        Name = "Ahmet"
                    },
                    new BClass
                    {
                        Id = 102,
                        Name = "Merve"
                    }
                }
            };
            return View(model);
        }
        [HttpPost]
        public ActionResult Index(AClass model)
        {
            return View(model);
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}