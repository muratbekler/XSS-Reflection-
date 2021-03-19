using System.Web.Mvc;

namespace TestWep.Base
{
    public class BaseController : Controller
    {
        protected override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            XssActionController.Instance.InvokeAction(filterContext);
            base.OnActionExecuting(filterContext);
        }
    }
}