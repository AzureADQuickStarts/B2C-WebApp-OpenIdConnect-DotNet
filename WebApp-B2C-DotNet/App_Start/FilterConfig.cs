using System.Web;
using System.Web.Mvc;

namespace WebApp_OpenIDConnect_DotNet_B2C
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
