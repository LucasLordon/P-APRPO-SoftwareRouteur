using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;
using SoftwareRouteur.Data;
using SoftwareRouteur.Models;
using SoftwareRouteur.Services;
using SoftwareRouteur.ViewModels;

namespace SoftwareRouteur.Controllers;

[Authorize]
[Route("admin/profiles")]
public class AdminProfilesController : Controller
{
    private static readonly System.Text.RegularExpressions.Regex PinRegex =
        new(@"^\d{4}$", System.Text.RegularExpressions.RegexOptions.Compiled);

    private readonly AppDbContext _context;
    private readonly IStringLocalizer<AdminProfilesController> _localizer;
    private readonly OPNsenseService _opnsense;

    public AdminProfilesController(AppDbContext context, IStringLocalizer<AdminProfilesController> localizer, OPNsenseService opnsense)
    {
        _context = context;
        _localizer = localizer;
        _opnsense = opnsense;
    }

    [HttpGet("")]
    public IActionResult Index()
    {
        var profiles = _context.Profiles
            .Include(p => p.CreatedBy)
            .OrderBy(p => p.Role == "child")
            .ThenBy(p => p.DisplayName)
            .ToList();

        var clientCounts = _context.Clients
            .Where(c => c.ProfileId != null)
            .GroupBy(c => c.ProfileId)
            .ToDictionary(g => g.Key!.Value, g => g.Count());

        ViewBag.ClientCounts = clientCounts;
        ViewBag.AllClients = _context.Clients.OrderBy(c => c.Hostname).ToList();
        return View(profiles);
    }

    [HttpPost("create")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(ProfileCreateViewModel vm)
    {
        if (string.IsNullOrWhiteSpace(vm.DisplayName) || string.IsNullOrWhiteSpace(vm.Role))
        {
            TempData["Error"] = _localizer["Error_FieldsRequired"].Value;
            return RedirectToAction("Index");
        }

        if (vm.Role == "parent" && string.IsNullOrWhiteSpace(vm.Pin))
        {
            TempData["Error"] = _localizer["Error_ParentPinRequired"].Value;
            return RedirectToAction("Index");
        }

        if (!string.IsNullOrWhiteSpace(vm.Pin))
        {
            if (!PinRegex.IsMatch(vm.Pin))
            {
                TempData["Error"] = _localizer["Error_PinFormat"].Value;
                return RedirectToAction("Index");
            }
            if (vm.Pin != vm.ConfirmPin)
            {
                TempData["Error"] = _localizer["Error_PinMismatch"].Value;
                return RedirectToAction("Index");
            }
        }

        var profile = new Profile
        {
            DisplayName = vm.DisplayName.Trim(),
            Role = vm.Role,
            PinHash = string.IsNullOrWhiteSpace(vm.Pin) ? null : BCrypt.Net.BCrypt.HashPassword(vm.Pin),
            CreatedById = null,
            CreatedAt = DateTime.Now
        };

        _context.Profiles.Add(profile);
        await _context.SaveChangesAsync();

        TempData["Success"] = string.Format(_localizer["Success_Created"].Value, profile.DisplayName);
        return RedirectToAction("Index");
    }

    [HttpPost("edit/{id}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, ProfileEditViewModel vm)
    {
        var profile = _context.Profiles.Find(id);
        if (profile == null)
            return RedirectToAction("Index");

        if (string.IsNullOrWhiteSpace(vm.DisplayName) || string.IsNullOrWhiteSpace(vm.Role))
        {
            TempData["Error"] = _localizer["Error_FieldsRequired"].Value;
            return RedirectToAction("Index");
        }

        if (!string.IsNullOrWhiteSpace(vm.Pin))
        {
            if (!PinRegex.IsMatch(vm.Pin))
            {
                TempData["Error"] = _localizer["Error_PinFormat"].Value;
                return RedirectToAction("Index");
            }
            if (vm.Pin != vm.ConfirmPin)
            {
                TempData["Error"] = _localizer["Error_PinMismatch"].Value;
                return RedirectToAction("Index");
            }
        }

        profile.DisplayName = vm.DisplayName.Trim();
        profile.Role = vm.Role;

        if (!string.IsNullOrWhiteSpace(vm.Pin))
            profile.PinHash = BCrypt.Net.BCrypt.HashPassword(vm.Pin);

        await _context.SaveChangesAsync();

        TempData["Success"] = string.Format(_localizer["Success_Updated"].Value, profile.DisplayName);
        return RedirectToAction("Index");
    }

    [HttpPost("delete/{id}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(int id)
    {
        var profile = _context.Profiles.Find(id);
        if (profile == null)
            return RedirectToAction("Index");
        
        if (profile.Role == "child" &&
            (!string.IsNullOrEmpty(profile.OpnsenseBlockAliasUuid) ||
             !string.IsNullOrEmpty(profile.OpnsenseAllowAliasUuid)))
        {
            await _opnsense.DeleteProfileAliasesAndRulesAsync(
                profile.Id,
                profile.OpnsenseBlockAliasUuid,
                profile.OpnsenseAllowAliasUuid,
                profile.OpnsenseSrcAliasUuid,
                profile.OpnsenseBlockRuleUuid,
                profile.OpnsenseAllowRuleUuid);
        }
        
        var assignedClients = _context.Clients.Where(c => c.ProfileId == id).ToList();
        foreach (var client in assignedClients)
            client.ProfileId = null;

        _context.Profiles.Remove(profile);
        await _context.SaveChangesAsync();

        TempData["Success"] = string.Format(_localizer["Success_Deleted"].Value, profile.DisplayName);
        return RedirectToAction("Index");
    }

    [HttpPost("devices/{profileId}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssignDevices(int profileId, [FromForm] List<int> selectedClientIds)
    {
        var profile = _context.Profiles.Find(profileId);
        if (profile == null || profile.Role != "child")
        {
            TempData["Error"] = _localizer["Error_InvalidProfile"].Value;
            return RedirectToAction("Index");
        }
        
        var currentlyAssigned = _context.Clients.Where(c => c.ProfileId == profileId).ToList();
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
        return RedirectToAction("Index");
    }
}
