using Microsoft.EntityFrameworkCore;
using SoftwareRouteur.Data;
using SoftwareRouteur.Models;

namespace SoftwareRouteur.Services;

internal static class RewardOPNsenseHelper
{
    internal static async Task SetProfileDevicesBlockedAsync(
        AppDbContext db,
        OPNsenseService opnsense,
        ILogger logger,
        Reward reward,
        bool blocked)
    {
        var profile = await db.Profiles.FirstOrDefaultAsync(p => p.Id == reward.ChildProfileId);

        if (reward.Challenge?.RewardScope == "site" && !string.IsNullOrEmpty(reward.Challenge.RewardSite))
        {
            if (profile?.OpnsenseAllowAliasUuid == null)
            {
                logger.LogWarning(
                    "Site reward {RewardId}: profile {ProfileId} has no allow alias UUID, skipping",
                    reward.Id, reward.ChildProfileId);
                return;
            }

            bool ok;
            if (!blocked)
                ok = await opnsense.AddToProfileWhitelistAsync(profile.OpnsenseAllowAliasUuid, reward.Challenge.RewardSite);
            else
                ok = await opnsense.RemoveFromProfileWhitelistAsync(profile.OpnsenseAllowAliasUuid, reward.Challenge.RewardSite);

            if (!ok)
                logger.LogWarning(
                    "{Action} whitelist failed for site {Site} (reward {RewardId})",
                    blocked ? "Remove from" : "Add to", reward.Challenge.RewardSite, reward.Id);

            return;
        }

        var devices = await db.Clients
            .Where(c => c.ProfileId == reward.ChildProfileId && c.OpnsenseRuleUuid != null)
            .ToListAsync();

        foreach (var device in devices)
        {
            var ok = await opnsense.SetDeviceBlockedAsync(device.OpnsenseRuleUuid!, blocked);
            if (!ok)
                logger.LogWarning(
                    "SetDeviceBlocked({Blocked}) failed for device {DeviceId} (profile {ProfileId})",
                    blocked, device.Id, reward.ChildProfileId);
        }

        if (profile?.OpnsenseBlockRuleUuid != null)
        {
            var ok = await opnsense.SetDeviceBlockedAsync(profile.OpnsenseBlockRuleUuid, blocked);
            if (!ok)
                logger.LogWarning(
                    "SetDeviceBlocked({Blocked}) failed for profile block rule (profile {ProfileId})",
                    blocked, reward.ChildProfileId);
        }
    }
}
