using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using SoftwareRouteur.Data;
using SoftwareRouteur.Filters;
using SoftwareRouteur.Models;
using SoftwareRouteur.Services;
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
    private readonly OPNsenseService _opnsense;

    public ParentController(AppDbContext context, IStringLocalizer<ParentController> localizer, IWebHostEnvironment env, OPNsenseService opnsense)
    {
        _context = context;
        _localizer = localizer;
        _env = env;
        _opnsense = opnsense;
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
    public IActionResult Profils()
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var childProfiles = _context.Profiles
            .Where(p => p.Role == "child")
            .Include(p => p.Clients)
            .Include(p => p.ProfileFirewallRules)
            .OrderBy(p => p.DisplayName)
            .ToList();

        ViewBag.AllClients = _context.Clients.OrderBy(c => c.Hostname).ToList();
        return View(childProfiles);
    }

    [HttpPost("profils/devices/{profileId}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssignProfileDevices(int profileId, [FromForm] List<int> selectedClientIds)
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        
        var profile = _context.Profiles
            .Include(p => p.Clients)
            .FirstOrDefault(p => p.Id == profileId && p.Role == "child");

        if (profile == null)
        {
            TempData["Error"] = _localizer["Error_InvalidProfile"].Value;
            return RedirectToAction("Profils");
        }
        
        var currentlyAssigned = profile.Clients.ToList();
        var currentIds = currentlyAssigned.Select(c => c.Id).ToHashSet();
        var newIds = selectedClientIds == null ? new HashSet<int>() : new HashSet<int>(selectedClientIds);
        
        var toRemove = currentlyAssigned.Where(c => !newIds.Contains(c.Id)).ToList();
        
        var toAdd = _context.Clients.Where(c => newIds.Contains(c.Id) && !currentIds.Contains(c.Id)).ToList();
        
        foreach (var client in toRemove)
        {
            if (!string.IsNullOrEmpty(profile.OpnsenseSrcAliasUuid))
            {
                await _opnsense.RemoveDeviceFromProfileRulesAsync(profile.OpnsenseSrcAliasUuid, client.IpAddress);
            }
            client.ProfileId = null;
        }
        
        foreach (var client in toAdd)
        {
            if (client.ProfileId != null && client.ProfileId != profileId)
            {
                TempData["Warning"] = string.Format(_localizer["Warning_AlreadyAssigned"].Value, client.Hostname);
                continue;
            }
            
            if (string.IsNullOrEmpty(profile.OpnsenseSrcAliasUuid))
            {
                var (srcUuid, blockUuid, allowUuid, blockRuleUuid, allowRuleUuid) =
                    await _opnsense.CreateProfileAliasesAndRulesAsync(profile.Id, profile.DisplayName);

                profile.OpnsenseSrcAliasUuid = srcUuid;
                profile.OpnsenseBlockAliasUuid = blockUuid;
                profile.OpnsenseAllowAliasUuid = allowUuid;
                profile.OpnsenseBlockRuleUuid = blockRuleUuid;
                profile.OpnsenseAllowRuleUuid = allowRuleUuid;
            }
            
            if (!string.IsNullOrEmpty(profile.OpnsenseSrcAliasUuid))
            {
                await _opnsense.AddDeviceToProfileRulesAsync(profile.OpnsenseSrcAliasUuid, client.IpAddress);
            }

            client.ProfileId = profileId;
        }

        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Success_DevicesAssigned"].Value;
        return RedirectToAction("Profils");
    }

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
    public IActionResult Regles()
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var childProfiles = _context.Profiles
            .Where(p => p.Role == "child")
            .Include(p => p.ProfileFirewallRules)
            .Include(p => p.Clients)
            .ThenInclude(c => c.FirewallRules)
            .OrderBy(p => p.DisplayName)
            .ToList();

        var allClients = _context.Clients
            .Include(c => c.FirewallRules)
            .OrderBy(c => c.Hostname)
            .ToList();

        var vm = new ParentReglesViewModel
        {
            ChildProfiles = childProfiles,
            AllClients = allClients
        };

        return View(vm);
    }

    [HttpPost("regles/profile/create")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateProfileRule(int? profileId, int? clientId, string ruleType, string destination, string action)
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        
        if (string.IsNullOrWhiteSpace(destination) || string.IsNullOrWhiteSpace(ruleType) || string.IsNullOrWhiteSpace(action))
        {
            TempData["Error"] = _localizer["Error_FieldsRequired"].Value;
            return RedirectToAction("Regles");
        }
        
        if (profileId.HasValue && profileId > 0)
        {
            var profile = _context.Profiles
                .FirstOrDefault(p => p.Id == profileId && p.Role == "child");

            if (profile == null)
            {
                TempData["Error"] = _localizer["Error_InvalidProfile"].Value;
                return RedirectToAction("Regles");
            }
            
            var conflictRule = _context.ProfileFirewallRules
                .FirstOrDefault(r =>
                    r.ProfileId == profileId &&
                    r.Destination.ToLower() == destination.ToLower());

            if (conflictRule != null)
            {
                if (conflictRule.Action != action)
                {
                    TempData["Error"] = string.Format(_localizer["Error_ConflictOpposite"].Value,
                        conflictRule.Action, destination, profile.DisplayName);
                }
                else
                {
                    TempData["Error"] = string.Format(_localizer["Error_ConflictDuplicate"].Value,
                        destination, profile.DisplayName);
                }
                return RedirectToAction("Regles");
            }
            
            var assignedClientIds = _context.Clients
                .Where(c => c.ProfileId == profileId)
                .Select(c => c.Id)
                .ToList();

            if (assignedClientIds.Any())
            {
                var conflictingDeviceRules = await _context.FirewallRules
                    .Include(r => r.Client)
                    .Where(r =>
                        assignedClientIds.Contains(r.ClientId) &&
                        r.Destination.ToLower() == destination.ToLower() &&
                        r.Action != action)
                    .ToListAsync();

                if (conflictingDeviceRules.Any())
                {
                    var deviceNames = string.Join(", ", conflictingDeviceRules.Select(r => r.Client!.Hostname));
                    TempData["Warning"] = string.Format(_localizer["Warning_DeviceConflictExists"].Value,
                        destination, deviceNames);
                }
            }
            
            var rule = new ProfileFirewallRule
            {
                ProfileId = profileId.Value,
                RuleType = ruleType,
                Destination = destination,
                Action = action,
                CreatedAt = DateTime.Now
            };

            _context.ProfileFirewallRules.Add(rule);
            await _context.SaveChangesAsync();
            
            if (action == "deny" && !string.IsNullOrEmpty(profile.OpnsenseBlockAliasUuid))
            {
                await _opnsense.AddToProfileBlocklistAsync(profile.OpnsenseBlockAliasUuid, destination);
            }
            else if (action == "allow" && !string.IsNullOrEmpty(profile.OpnsenseAllowAliasUuid))
            {
                await _opnsense.AddToProfileWhitelistAsync(profile.OpnsenseAllowAliasUuid, destination);
            }

            TempData["Success"] = _localizer["Success_Created"].Value;
            return RedirectToAction("Regles");
        }
        else if (clientId.HasValue && clientId > 0)
        {
            var client = _context.Clients
                .Include(c => c.Profile)
                .FirstOrDefault(c => c.Id == clientId);

            if (client == null)
            {
                TempData["Error"] = _localizer["Error_InvalidClient"].Value;
                return RedirectToAction("Regles");
            }
            
            var conflictRule = _context.FirewallRules
                .FirstOrDefault(r =>
                    r.ClientId == clientId &&
                    r.Destination.ToLower() == destination.ToLower());

            if (conflictRule != null)
            {
                if (conflictRule.Action != action)
                {
                    TempData["Error"] = string.Format(_localizer["Error_ConflictOpposite"].Value,
                        conflictRule.Action, destination, client.Hostname);
                }
                else
                {
                    TempData["Error"] = string.Format(_localizer["Error_ConflictDuplicate"].Value,
                        destination, client.Hostname);
                }
                return RedirectToAction("Regles");
            }
            
            var rule = new FirewallRule
            {
                ClientId = clientId.Value,
                RuleType = ruleType,
                Destination = destination,
                Action = action,
                CreatedAt = DateTime.Now
            };

            _context.FirewallRules.Add(rule);
            await _context.SaveChangesAsync();
            
            if (action == "deny")
            {
                await _opnsense.AddToAliasAsync(clientId.Value, destination);
            }
            else if (action == "allow")
            {
                await _opnsense.AddToWhitelistAsync(clientId.Value, destination);
            }

            TempData["Success"] = _localizer["Success_Created"].Value;
            return RedirectToAction("Regles");
        }

        TempData["Error"] = _localizer["Error_InvalidRequest"].Value;
        return RedirectToAction("Regles");
    }

    [HttpPost("regles/profile/delete/{id}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteProfileRule(int id)
    {
        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var rule = _context.ProfileFirewallRules
            .Include(r => r.Profile)
            .FirstOrDefault(r => r.Id == id && r.Profile!.Role == "child");

        if (rule == null)
        {
            TempData["Error"] = _localizer["Error_RuleNotFound"].Value;
            return RedirectToAction("Regles");
        }

        var profile = rule.Profile!;
        var action = rule.Action;
        var destination = rule.Destination;

        if (action == "deny" && !string.IsNullOrEmpty(profile.OpnsenseBlockAliasUuid))
        {
            await _opnsense.RemoveFromProfileBlocklistAsync(profile.OpnsenseBlockAliasUuid, destination);
        }
        else if (action == "allow" && !string.IsNullOrEmpty(profile.OpnsenseAllowAliasUuid))
        {
            await _opnsense.RemoveFromProfileWhitelistAsync(profile.OpnsenseAllowAliasUuid, destination);
        }

        _context.ProfileFirewallRules.Remove(rule);
        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Success_Deleted"].Value;
        return RedirectToAction("Regles");
    }

    [HttpPost("regles/device/delete/{id}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteDeviceRule(int id)
    {
        var rule = _context.FirewallRules
            .Include(r => r.Client)
            .FirstOrDefault(r => r.Id == id);

        if (rule == null || rule.Client == null)
        {
            TempData["Error"] = _localizer["Error_RuleNotFound"].Value;
            return RedirectToAction("Regles");
        }

        var parentId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        
        var client = _context.Clients
            .Include(c => c.Profile)
            .FirstOrDefault(c => c.Id == rule.ClientId && c.Profile != null && c.Profile.Role == "child");

        if (client == null)
        {
            TempData["Error"] = _localizer["Error_Unauthorized"].Value;
            return RedirectToAction("Regles");
        }

        var action = rule.Action;
        var destination = rule.Destination;
        
        if (action == "deny")
        {
            await _opnsense.RemoveFromAliasAsync(rule.ClientId, destination);
        }
        else if (action == "allow")
        {
            await _opnsense.RemoveFromWhitelistAsync(rule.ClientId, destination);
        }

        _context.FirewallRules.Remove(rule);
        await _context.SaveChangesAsync();

        TempData["Success"] = _localizer["Success_Deleted"].Value;
        return RedirectToAction("Regles");
    }

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
