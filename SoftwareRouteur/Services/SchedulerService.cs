using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using SoftwareRouteur.Data;
using SoftwareRouteur.Models;

namespace SoftwareRouteur.Services;

public class SchedulerService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly OPNsenseService _opnsense;
    private readonly ILogger<SchedulerService> _logger;

    // Captures the blocked/unblocked state, the specific destination that was applied,
    // and whether the destination belongs to the allow alias (tempauth) vs block alias (schedule).
    private record ProfileScheduleState(bool IsBlocked, string? SiteDestination, bool UseAllowAlias = false);
    private readonly ConcurrentDictionary<int, ProfileScheduleState?> _lastAppliedState = new();

    // Used to project TempAuthorization rows without loading navigation properties.
    private record TempAuthEntry(int ProfileId, string? AllowDestination);

    public SchedulerService(IServiceScopeFactory scopeFactory, OPNsenseService opnsense, ILogger<SchedulerService> logger)
    {
        _scopeFactory = scopeFactory;
        _opnsense = opnsense;
        _logger = logger;
    }

    /// <summary>
    /// Forces re-evaluation of a profile on the next scheduler tick.
    /// Call after modifying a schedule or temp authorization for this profile.
    /// </summary>
    public void ResetProfileState(int profileId)
    {
        _lastAppliedState.TryRemove(profileId, out _);
        _logger.LogInformation(
            "SchedulerService: reset state for profile {ProfileId}", profileId);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await EvaluateAllProfilesAsync();

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(30_000, stoppingToken);
            await EvaluateAllProfilesAsync();
        }
    }

    private async Task EvaluateAllProfilesAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        try
        {
            var now = DateTime.Now;

            var childProfiles = await db.Profiles
                .Where(p => p.Role == "child")
                .ToListAsync();

            var activeRewardProfileIds = await db.Rewards
                .Where(r => r.Status == "active")
                .Select(r => r.ChildProfileId)
                .ToHashSetAsync();

            var activeTempAuths = await db.TempAuthorizations
                .Where(t => t.ExpiresAt > now)
                .Select(t => new TempAuthEntry(t.ProfileId, t.AllowDestination))
                .ToListAsync();

            var blockingSchedules = await db.Schedules
                .Where(s => s.IsBlocking)
                .ToListAsync();

            _logger.LogInformation(
                "SchedulerService: tick at {Now} — evaluating {Count} child profiles",
                now.ToString("HH:mm:ss"), childProfiles.Count);
            _logger.LogInformation(
                "SchedulerService: active rewards for profiles: [{Ids}]",
                string.Join(", ", activeRewardProfileIds));
            _logger.LogInformation(
                "SchedulerService: active tempauths: [{Entries}]",
                string.Join(", ", activeTempAuths.Select(t => $"profileId={t.ProfileId},dest={t.AllowDestination ?? "global"}")));
            _logger.LogInformation(
                "SchedulerService: blocking schedules loaded: {Count}",
                blockingSchedules.Count);

            foreach (var profile in childProfiles)
            {
                try
                {
                    var profileTempAuths = activeTempAuths
                        .Where(t => t.ProfileId == profile.Id)
                        .ToList();

                    var (shouldBeBlocked, triggeringSchedule, tempAuthDestination) = ComputeShouldBeBlocked(
                        profile, now, activeRewardProfileIds, profileTempAuths, blockingSchedules);

                    ProfileScheduleState? newState;
                    if (shouldBeBlocked == null)
                        newState = null;
                    else if (shouldBeBlocked == false && tempAuthDestination != null)
                        newState = new ProfileScheduleState(false, tempAuthDestination, UseAllowAlias: true);
                    else
                        newState = new ProfileScheduleState(shouldBeBlocked.Value, triggeringSchedule?.BlockDestination, UseAllowAlias: false);

                    _lastAppliedState.TryGetValue(profile.Id, out var lastState);

                    bool stateChanged = newState?.IsBlocked != lastState?.IsBlocked
                        || newState?.SiteDestination != lastState?.SiteDestination
                        || newState?.UseAllowAlias != lastState?.UseAllowAlias;

                    string action = !stateChanged ? "no-change" :
                        shouldBeBlocked == null ? "UNBLOCK" :
                        shouldBeBlocked == true ? "BLOCK" : "ALLOW";

                    _logger.LogInformation(
                        "SchedulerService: profile {Id} ({Name}) — " +
                        "shouldBeBlocked={Should}, destination={Dest}, tempAuthDest={TempDest}, " +
                        "lastState={Last}, stateChanged={Changed}, action={Action}",
                        profile.Id, profile.DisplayName,
                        shouldBeBlocked?.ToString() ?? "null",
                        triggeringSchedule?.BlockDestination ?? "global",
                        tempAuthDestination ?? "none",
                        lastState == null ? "null" : $"blocked={lastState.IsBlocked},dest={lastState.SiteDestination ?? "global"},allowAlias={lastState.UseAllowAlias}",
                        stateChanged,
                        action);

                    if (!stateChanged)
                        continue;

                    if (newState?.IsBlocked == true)
                    {
                        // Activating a blocking schedule
                        _logger.LogInformation("SchedulerService: blocking profile {ProfileId}", profile.Id);
                        await SetProfileBlockedAsync(db, profile, blocked: true, triggeringSchedule, lastState);
                    }
                    else if (newState?.IsBlocked == false && newState.UseAllowAlias && newState.SiteDestination != null)
                    {
                        // TempAuth with site destination → add to allow alias
                        _logger.LogInformation(
                            "SchedulerService: granting site access for profile {ProfileId}: {Dest}",
                            profile.Id, newState.SiteDestination);
                        await SetProfileAllowSiteAsync(profile, newState.SiteDestination, grant: true);
                        // If previously globally blocked, also undo that block
                        if (lastState?.IsBlocked == true)
                            await SetProfileBlockedAsync(db, profile, blocked: false, null, lastState);
                    }
                    else
                    {
                        // Unblock path: schedule ended (newState=null), global tempauth, or tempauth allow expired
                        if (lastState?.UseAllowAlias == true && lastState.SiteDestination != null)
                        {
                            // TempAuth site allow ended → remove from allow alias
                            _logger.LogInformation(
                                "SchedulerService: revoking site access for profile {ProfileId}: {Dest}",
                                profile.Id, lastState.SiteDestination);
                            await SetProfileAllowSiteAsync(profile, lastState.SiteDestination, grant: false);
                        }
                        else
                        {
                            _logger.LogInformation("SchedulerService: unblocking profile {ProfileId}", profile.Id);
                            await SetProfileBlockedAsync(db, profile, blocked: false, null, lastState);
                        }
                    }

                    _lastAppliedState[profile.Id] = newState;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "SchedulerService: error evaluating profile {ProfileId}", profile.Id);
                }
            }

            await CleanupExpiredTempAuthsAsync(db);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SchedulerService: unexpected error in EvaluateAllProfilesAsync");
        }
    }

    private (bool? ShouldBeBlocked, Schedule? TriggeringSchedule, string? TempAuthDestination) ComputeShouldBeBlocked(
        Profile profile, DateTime now,
        HashSet<int> activeRewardProfileIds,
        List<TempAuthEntry> profileTempAuths,
        List<Schedule> blockingSchedules)
    {
        var matchingSchedules = blockingSchedules
            .Where(s => s.ProfileId == profile.Id || s.ProfileId == null)
            .Where(s => IsCurrentlyInWindow(s, now))
            .ToList();

        _logger.LogInformation(
            "SchedulerService: profile {ProfileId} — " +
            "hasActiveReward={Reward}, hasActiveTempAuth={TempAuth}, matchingSchedules={ScheduleCount}",
            profile.Id,
            activeRewardProfileIds.Contains(profile.Id),
            profileTempAuths.Count > 0,
            matchingSchedules.Count);

        if (activeRewardProfileIds.Contains(profile.Id))
            return (false, null, null);

        if (profileTempAuths.Count > 0)
        {
            // Global tempauth (AllowDestination == null) takes priority over site-specific
            var globalTempAuth = profileTempAuths.FirstOrDefault(t => t.AllowDestination == null);
            if (globalTempAuth != null)
                return (false, null, null);

            // Site-specific tempauth: return the destination
            var siteTempAuth = profileTempAuths.First(t => t.AllowDestination != null);
            return (false, null, siteTempAuth.AllowDestination);
        }

        if (matchingSchedules.Count > 0)
            return (true, matchingSchedules[0], null);

        return (null, null, null);
    }

    private async Task CleanupExpiredTempAuthsAsync(AppDbContext db)
    {
        var expired = await db.TempAuthorizations
            .Where(t => t.ExpiresAt <= DateTime.Now)
            .ToListAsync();

        if (expired.Count > 0)
        {
            db.TempAuthorizations.RemoveRange(expired);
            await db.SaveChangesAsync();
            _logger.LogInformation("SchedulerService: removed {Count} expired TempAuthorizations", expired.Count);
        }
    }

    private async Task SetProfileAllowSiteAsync(Profile profile, string destination, bool grant)
    {
        if (profile.OpnsenseAllowAliasUuid == null)
        {
            _logger.LogWarning(
                "SchedulerService: profile {ProfileId} has no allow alias UUID, " +
                "cannot apply site-specific tempauth", profile.Id);
            return;
        }

        if (grant)
        {
            await _opnsense.AddToProfileWhitelistAsync(profile.OpnsenseAllowAliasUuid, destination);
            _logger.LogInformation(
                "SchedulerService: added {Dest} to profile {ProfileId} allow alias",
                destination, profile.Id);
        }
        else
        {
            await _opnsense.RemoveFromProfileWhitelistAsync(profile.OpnsenseAllowAliasUuid, destination);
            _logger.LogInformation(
                "SchedulerService: removed {Dest} from profile {ProfileId} allow alias",
                destination, profile.Id);
        }
    }

    private async Task SetProfileBlockedAsync(
        AppDbContext db,
        Profile profile,
        bool blocked,
        Schedule? triggeringSchedule,
        ProfileScheduleState? previousState)
    {
        // When blocking: site-specific if the new schedule has a destination.
        // When unblocking: site-specific if the previous state had a destination to remove.
        bool isSiteSpecific = blocked
            ? triggeringSchedule?.BlockDestination != null
            : previousState?.SiteDestination != null;

        string? destination = blocked
            ? triggeringSchedule?.BlockDestination
            : previousState?.SiteDestination;

        if (isSiteSpecific && destination != null)
        {
            if (profile.OpnsenseBlockAliasUuid == null)
            {
                _logger.LogWarning(
                    "SchedulerService: profile {ProfileId} has no block alias UUID, " +
                    "cannot apply site-specific schedule", profile.Id);
                return;
            }

            if (blocked)
            {
                await _opnsense.AddToProfileBlocklistAsync(profile.OpnsenseBlockAliasUuid, destination);
                _logger.LogInformation(
                    "SchedulerService: added {Dest} to profile {ProfileId} blocklist alias",
                    destination, profile.Id);
            }
            else
            {
                await _opnsense.RemoveFromProfileBlocklistAsync(profile.OpnsenseBlockAliasUuid, destination);
                _logger.LogInformation(
                    "SchedulerService: removed {Dest} from profile {ProfileId} blocklist alias",
                    destination, profile.Id);
            }
        }
        else
        {
            var devices = await db.Clients
                .Where(c => c.ProfileId == profile.Id && c.OpnsenseRuleUuid != null)
                .ToListAsync();

            _logger.LogInformation(
                "SchedulerService: SetProfileBlockedAsync({Blocked}) for profile {ProfileId} — " +
                "{DeviceCount} devices to process",
                blocked, profile.Id, devices.Count);

            foreach (var device in devices)
            {
                var ok = await _opnsense.SetDeviceBlockedAsync(device.OpnsenseRuleUuid!, blocked);
                if (!ok)
                    _logger.LogWarning(
                        "SchedulerService: SetDeviceBlocked({Blocked}) failed for device {DeviceId} (profile {ProfileId})",
                        blocked, device.Id, profile.Id);
            }

            if (profile.OpnsenseBlockRuleUuid != null)
            {
                var ok = await _opnsense.SetDeviceBlockedAsync(profile.OpnsenseBlockRuleUuid, blocked);
                if (!ok)
                    _logger.LogWarning(
                        "SchedulerService: SetDeviceBlocked({Blocked}) failed for profile block rule (profile {ProfileId})",
                        blocked, profile.Id);
            }
        }
    }

    private bool IsCurrentlyInWindow(Schedule s, DateTime now)
    {
        var dayIndex = ((int)now.DayOfWeek + 6) % 7; // Mon=0 … Sun=6
        var currentTime = TimeOnly.FromDateTime(now);
        var dayActive = s.Days.Length >= 7 && s.Days[dayIndex] == '1';
        var result = dayActive && currentTime >= s.TimeStart && currentTime <= s.TimeEnd;

        _logger.LogInformation(
            "SchedulerService: schedule {ScheduleId} for profile {ProfileId} — " +
            "days={Days}, dayIndex={DayIndex} (today={DayName}), " +
            "dayActive={DayActive}, window={Start}-{End}, currentTime={Now}, inWindow={Result}",
            s.Id, s.ProfileId?.ToString() ?? "global",
            s.Days, dayIndex, now.DayOfWeek.ToString(),
            dayActive,
            s.TimeStart, s.TimeEnd,
            currentTime,
            result);

        return result;
    }
}
