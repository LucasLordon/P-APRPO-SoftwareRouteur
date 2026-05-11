using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using SoftwareRouteur.Data;
using SoftwareRouteur.Filters;
using SoftwareRouteur.Models;
using SoftwareRouteur.ViewModels;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace SoftwareRouteur.Controllers;

[RequireParentProfile]
[Route("parent")]
public class ParentController : Controller
{
    private static readonly Regex PinRegex = new(@"^\d{4}$", RegexOptions.Compiled);
    private static readonly Regex DomainRegex = new(@"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", RegexOptions.Compiled);

    private readonly AppDbContext _context;
    private readonly IStringLocalizer<ParentController> _localizer;
    private readonly IWebHostEnvironment _env;

    public ParentController(AppDbContext context, IStringLocalizer<ParentController> localizer, IWebHostEnvironment env)
    {
        _context = context;
        _localizer = localizer;
        _env = env;
    }

    [HttpGet("dashboard")]
    public IActionResult Dashboard()
    {
        var profileId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var currentProfile = _context.Profiles.Find(profileId)!;

        var children = _context.Profiles
            .Where(p => p.Role == "child")
            .OrderBy(p => p.DisplayName)
            .ToList();

        var childIds = children.Select(c => c.Id).ToList();
        var deviceCounts = _context.Clients
            .Where(c => c.ProfileId != null && childIds.Contains(c.ProfileId.Value))
            .GroupBy(c => c.ProfileId!.Value)
            .ToDictionary(g => g.Key, g => g.Count());

        var vm = new ParentDashboardViewModel
        {
            CurrentProfile = currentProfile,
            ChildProfiles = children.Select(c => new ChildSummary
            {
                Profile = c,
                DeviceCount = deviceCounts.GetValueOrDefault(c.Id, 0)
            }).ToList()
        };

        return View(vm);
    }

    [HttpGet("profils")]
    public IActionResult Profils() => View();

    [HttpGet("challenges")]
    public IActionResult Challenges()
    {
        var profileId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var children = _context.Profiles
            .Where(p => p.Role == "child")
            .OrderBy(p => p.DisplayName)
            .ToList();

        var challenges = _context.Challenges
            .Include(c => c.ChildProfile)
            .Include(c => c.ParentProfile)
            .Include(c => c.Proofs)
            .OrderByDescending(c => c.CreatedAt)
            .ToList();

        var vm = new ParentChallengesViewModel
        {
            ActiveChallenges = challenges.Where(c => c.Status != "submitted").ToList(),
            PendingApproval = challenges.Where(c => c.Status == "submitted").ToList(),
            ChildProfiles = children,
            CurrentParentId = profileId
        };

        return View(vm);
    }

    [HttpPost("challenges/create")]
    public async Task<IActionResult> ChallengeCreate(string title, string? description, int rewardMinutes, string rewardScope, string? rewardSite, bool proofRequired, int childProfileId)
    {
        if (string.IsNullOrWhiteSpace(title) || rewardMinutes <= 0)
        {
            TempData["Error"] = _localizer["Challenge_Error_Required"].Value;
            return RedirectToAction("Challenges");
        }

        if (rewardScope != "global" && rewardScope != "site")
        {
            TempData["Error"] = _localizer["Challenge_Error_InvalidScope"].Value;
            return RedirectToAction("Challenges");
        }

        if (rewardScope == "site" && (string.IsNullOrWhiteSpace(rewardSite) || !DomainRegex.IsMatch(rewardSite)))
        {
            TempData["Error"] = _localizer["Challenge_Error_SiteRequired"].Value;
            return RedirectToAction("Challenges");
        }

        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        if (!_context.Profiles.Any(p => p.Id == childProfileId && p.Role == "child"))
        {
            TempData["Error"] = _localizer["Challenge_Error_InvalidChild"].Value;
            return RedirectToAction("Challenges");
        }

        var challenge = new Challenge
        {
            ParentProfileId = parentId,
            ChildProfileId = childProfileId,
            Title = title.Trim(),
            Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            RewardMinutes = rewardMinutes,
            RewardScope = rewardScope,
            RewardSite = rewardScope == "site" ? rewardSite!.Trim().ToLower() : null,
            ProofRequired = proofRequired,
            Status = "pending",
            CreatedAt = DateTime.Now
        };

        _context.Challenges.Add(challenge);
        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Challenge_Success_Created"].Value;
        return RedirectToAction("Challenges");
    }

    [HttpPost("challenges/edit/{id:int}")]
    public async Task<IActionResult> ChallengeEdit(int id, string title, string? description, int rewardMinutes, string rewardScope, string? rewardSite, bool proofRequired)
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var challenge = await _context.Challenges.FirstOrDefaultAsync(c => c.Id == id && c.ParentProfileId == parentId);

        if (challenge == null)
        {
            TempData["Error"] = _localizer["Challenge_Error_NotFound"].Value;
            return RedirectToAction("Challenges");
        }

        if (challenge.Status != "pending")
        {
            TempData["Error"] = _localizer["Challenge_Error_InvalidStatus"].Value;
            return RedirectToAction("Challenges");
        }

        if (string.IsNullOrWhiteSpace(title) || rewardMinutes <= 0)
        {
            TempData["Error"] = _localizer["Challenge_Error_Required"].Value;
            return RedirectToAction("Challenges");
        }

        if (rewardScope != "global" && rewardScope != "site")
        {
            TempData["Error"] = _localizer["Challenge_Error_InvalidScope"].Value;
            return RedirectToAction("Challenges");
        }

        if (rewardScope == "site" && (string.IsNullOrWhiteSpace(rewardSite) || !DomainRegex.IsMatch(rewardSite)))
        {
            TempData["Error"] = _localizer["Challenge_Error_SiteRequired"].Value;
            return RedirectToAction("Challenges");
        }

        challenge.Title = title.Trim();
        challenge.Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        challenge.RewardMinutes = rewardMinutes;
        challenge.RewardScope = rewardScope;
        challenge.RewardSite = rewardScope == "site" ? rewardSite!.Trim().ToLower() : null;
        challenge.ProofRequired = proofRequired;

        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Challenge_Success_Updated"].Value;
        return RedirectToAction("Challenges");
    }

    [HttpPost("challenges/delete/{id:int}")]
    public async Task<IActionResult> ChallengeDelete(int id)
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var challenge = await _context.Challenges
            .Include(c => c.Proofs)
            .FirstOrDefaultAsync(c => c.Id == id && c.ParentProfileId == parentId);

        if (challenge == null)
        {
            TempData["Error"] = _localizer["Challenge_Error_NotFound"].Value;
            return RedirectToAction("Challenges");
        }

        foreach (var proof in challenge.Proofs)
        {
            if (proof.FilePath != null)
            {
                var fullPath = Path.Combine(_env.WebRootPath, proof.FilePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));
                if (System.IO.File.Exists(fullPath))
                    System.IO.File.Delete(fullPath);
            }
        }

        _context.Challenges.Remove(challenge);
        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Challenge_Success_Deleted"].Value;
        return RedirectToAction("Challenges");
    }

    [HttpPost("challenges/approve/{id:int}")]
    public async Task<IActionResult> ChallengeApprove(int id)
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var challenge = await _context.Challenges.FirstOrDefaultAsync(c => c.Id == id);

        if (challenge == null)
        {
            TempData["Error"] = _localizer["Challenge_Error_NotFound"].Value;
            return RedirectToAction("Challenges");
        }

        if (challenge.Status != "submitted")
        {
            TempData["Error"] = _localizer["Challenge_Error_InvalidStatus"].Value;
            return RedirectToAction("Challenges");
        }

        challenge.Status = "approved";

        var reward = new Reward
        {
            ChallengeId = challenge.Id,
            ChildProfileId = challenge.ChildProfileId,
            TotalMinutes = challenge.RewardMinutes,
            RemainingSeconds = challenge.RewardMinutes * 60,
            Status = "idle"
        };
        _context.Rewards.Add(reward);
        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Challenge_Success_Approved"].Value;
        return RedirectToAction("Challenges");
    }

    [HttpPost("challenges/reject/{id:int}")]
    public async Task<IActionResult> ChallengeReject(int id)
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var challenge = await _context.Challenges.FirstOrDefaultAsync(c => c.Id == id);

        if (challenge == null)
        {
            TempData["Error"] = _localizer["Challenge_Error_NotFound"].Value;
            return RedirectToAction("Challenges");
        }

        if (challenge.Status != "submitted")
        {
            TempData["Error"] = _localizer["Challenge_Error_InvalidStatus"].Value;
            return RedirectToAction("Challenges");
        }

        challenge.Status = "rejected";
        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Challenge_Success_Rejected"].Value;
        return RedirectToAction("Challenges");
    }

    [HttpGet("regles")]
    public IActionResult Regles() => View();

    [HttpGet("security")]
    public IActionResult Security() => View(new ParentSecurityViewModel());

    [HttpPost("security")]
    public async Task<IActionResult> Security(string currentPin, string newPin, string confirmPin)
    {
        var profileId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var profile = _context.Profiles.Find(profileId)!;

        if (!PinRegex.IsMatch(currentPin ?? "") || !PinRegex.IsMatch(newPin ?? "") || !PinRegex.IsMatch(confirmPin ?? ""))
            return View(new ParentSecurityViewModel { ErrorMessage = "Security_Error_InvalidFormat" });

        if (profile.PinHash != null && !BCrypt.Net.BCrypt.Verify(currentPin, profile.PinHash))
            return View(new ParentSecurityViewModel { ErrorMessage = "Security_Error_WrongCurrent" });

        if (newPin != confirmPin)
            return View(new ParentSecurityViewModel { ErrorMessage = "Security_Error_Mismatch" });

        if (profile.PinHash != null && BCrypt.Net.BCrypt.Verify(newPin, profile.PinHash))
            return View(new ParentSecurityViewModel { ErrorMessage = "Security_Error_SamePin" });

        profile.PinHash = BCrypt.Net.BCrypt.HashPassword(newPin);
        await _context.SaveChangesAsync();

        return View(new ParentSecurityViewModel { SuccessMessage = "Security_Success" });
    }
}
