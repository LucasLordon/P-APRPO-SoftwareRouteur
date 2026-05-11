using Microsoft.EntityFrameworkCore;
using SoftwareRouteur.Data;

namespace SoftwareRouteur.Services;

public class RewardTimerService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly OPNsenseService _opnsense;
    private readonly ILogger<RewardTimerService> _logger;

    public RewardTimerService(IServiceScopeFactory scopeFactory, OPNsenseService opnsense, ILogger<RewardTimerService> logger)
    {
        _scopeFactory = scopeFactory;
        _opnsense = opnsense;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await ResumeActiveRewardsAsync();

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(5000, stoppingToken);
            await TickAsync();
        }
    }

    private async Task ResumeActiveRewardsAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var activeRewards = await db.Rewards
            .Where(r => r.Status == "active")
            .ToListAsync();

        foreach (var reward in activeRewards)
            reward.LastUpdatedAt = DateTime.Now;

        if (activeRewards.Count > 0)
            await db.SaveChangesAsync();
    }

    private async Task TickAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var activeRewards = await db.Rewards
            .Include(r => r.Client)
            .Where(r => r.Status == "active")
            .ToListAsync();

        foreach (var reward in activeRewards)
        {
            reward.RemainingSeconds -= 5;

            if (reward.RemainingSeconds <= 0)
            {
                reward.RemainingSeconds = 0;
                reward.Status = "consumed";
                _logger.LogInformation("Reward {Id} consumed — re-blocking client {ClientId}", reward.Id, reward.ClientId);

                if (reward.Client?.OpnsenseRuleUuid != null)
                    await _opnsense.SetDeviceBlockedAsync(reward.Client.OpnsenseRuleUuid, true);
            }
            else
            {
                reward.LastUpdatedAt = DateTime.Now;
            }
        }

        if (activeRewards.Count > 0)
            await db.SaveChangesAsync();
    }
}
