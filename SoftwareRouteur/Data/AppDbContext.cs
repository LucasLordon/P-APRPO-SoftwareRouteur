using Microsoft.EntityFrameworkCore;
using SoftwareRouteur.Models;

namespace SoftwareRouteur.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public DbSet<Client> Clients { get; set; }
    public DbSet<FirewallRule> FirewallRules { get; set; }
    public DbSet<ProfileFirewallRule> ProfileFirewallRules { get; set; }
    public DbSet<AdminUser> AdminUsers { get; set; }
    public DbSet<Monitoring> Monitorings { get; set; }
    public DbSet<BlockedTraffic> BlockedTraffics { get; set; }
    public DbSet<Profile> Profiles { get; set; }
    public DbSet<Challenge> Challenges { get; set; }
    public DbSet<ChallengeProof> ChallengeProofs { get; set; }
    public DbSet<Reward> Rewards { get; set; }
    public DbSet<Schedule> Schedules { get; set; }
    public DbSet<TempAuthorization> TempAuthorizations { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Profile>()
            .HasOne(p => p.CreatedBy)
            .WithMany()
            .HasForeignKey(p => p.CreatedById)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.SetNull);

        modelBuilder.Entity<Client>()
            .HasOne(c => c.Profile)
            .WithMany(p => p.Clients)
            .HasForeignKey(c => c.ProfileId)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.SetNull);

        modelBuilder.Entity<Challenge>()
            .HasOne(c => c.ParentProfile)
            .WithMany()
            .HasForeignKey(c => c.ParentProfileId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Challenge>()
            .HasOne(c => c.ChildProfile)
            .WithMany()
            .HasForeignKey(c => c.ChildProfileId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<ChallengeProof>()
            .HasOne(p => p.Challenge)
            .WithMany(c => c.Proofs)
            .HasForeignKey(p => p.ChallengeId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<Reward>()
            .HasOne(r => r.Challenge)
            .WithOne(c => c.Reward)
            .HasForeignKey<Reward>(r => r.ChallengeId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Reward>()
            .HasOne(r => r.ChildProfile)
            .WithMany()
            .HasForeignKey(r => r.ChildProfileId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Reward>()
            .HasOne(r => r.Client)
            .WithMany()
            .HasForeignKey(r => r.ClientId)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.SetNull);

        modelBuilder.Entity<ProfileFirewallRule>()
            .HasOne(pfr => pfr.Profile)
            .WithMany(p => p.ProfileFirewallRules)
            .HasForeignKey(pfr => pfr.ProfileId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<Schedule>()
            .HasOne(s => s.Profile)
            .WithMany()
            .HasForeignKey(s => s.ProfileId)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.SetNull);

        modelBuilder.Entity<Schedule>()
            .HasOne(s => s.Client)
            .WithMany()
            .HasForeignKey(s => s.ClientId)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.SetNull);

        // TempAuthorization has two FKs to Profile — configure both explicitly
        // to avoid EF cascade conflict (same pattern as Challenge).
        modelBuilder.Entity<TempAuthorization>()
            .HasOne(t => t.Profile)
            .WithMany()
            .HasForeignKey(t => t.ProfileId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<TempAuthorization>()
            .HasOne(t => t.CreatedBy)
            .WithMany()
            .HasForeignKey(t => t.CreatedById)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<TempAuthorization>()
            .HasOne(t => t.Client)
            .WithMany()
            .HasForeignKey(t => t.ClientId)
            .IsRequired(false)
            .OnDelete(DeleteBehavior.SetNull);
    }
}
