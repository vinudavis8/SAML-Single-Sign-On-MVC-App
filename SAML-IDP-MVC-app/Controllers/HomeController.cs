using GenerateSAML;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SAML_IDP_MVC_app.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace SAML_IDP_MVC_app.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IHostingEnvironment _hostingEnvironment;


        public HomeController(ILogger<HomeController> logger, IHostingEnvironment hostingEnvironment)
        {
            _logger = logger;
            _hostingEnvironment = hostingEnvironment;
        }
        public IActionResult Login()
        {


            return View();
        }
        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            // string samlResponse=GetSAMLResponse();
            // ViewBag.samlResponse=samlResponse;
            return RedirectToAction("Index");
        }

        public IActionResult Index()
        {

            return View();
        }

        public string GetSAMLResponse()
        {
            SSOParameters parameters = new SSOParameters();
            parameters.Issuer = "https://ExampleIdentityProvider";
            parameters.IssuerFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
            parameters.Audience = "https://samltest.id/saml/sp";
            parameters.Destination = "https://samltest.id/Shibboleth.sso/SAML2/POST";

            parameters.SigniningCertPath = _hostingEnvironment.ContentRootPath + "\\Certificates\\idp.pfx";
            parameters.EncryptionCertPath = _hostingEnvironment.ContentRootPath + "\\Certificates\\shibboleth-enc.cer";
            parameters.SignatureUrl = "http://www.w3.org/2000/09/xmldsig#sha1";
            parameters.SignatureRsaUrl = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            parameters.SigniningCertPass = "password";

            parameters.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

            //attributes
            parameters.NameID = "Testuser@gmail.com";

            SamlResponse samlResponse = new SamlResponse(parameters);
            string response = samlResponse.GetSAMLResponse(false);
            return response;

        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
