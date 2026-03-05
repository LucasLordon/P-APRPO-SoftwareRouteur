using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SoftwareRouteur.Data;
using System.Security.Claims;

namespace SoftwareRouteur.Controllers;

public class AuthController : Controller
{
    private readonly AppDbContext _context;

    public AuthController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public IActionResult Login()
    {
        // Si déjà connecté, rediriger vers le dashboard
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToAction("Index", "Home");

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            ViewBag.Error = "Veuillez remplir tous les champs.";
            return View();
        }

        // Chercher l'utilisateur en base
        var user = _context.AdminUsers
            .FirstOrDefault(u => u.Username == username);

        if (user == null)
        {
            ViewBag.Error = "Nom d'utilisateur ou mot de passe incorrect.";
            return View();
        }

        // Vérifier le mot de passe avec BCrypt
        bool valid = false;
        try
        {
            valid = BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
        }
        catch
        {
            ViewBag.Error = "Erreur de vérification du mot de passe.";
            return View();
        }

        if (!valid)
        {
            ViewBag.Error = "Nom d'utilisateur ou mot de passe incorrect.";
            return View();
        }

        // Créer les claims et le cookie d'authentification
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
            }
        );

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}
