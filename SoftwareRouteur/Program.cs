using Microsoft.EntityFrameworkCore;
using SoftwareRouteur.Data;

var builder = WebApplication.CreateBuilder(args);

var password = Environment.GetEnvironmentVariable("DB_PASSWORD")
               ?? builder.Configuration["DB_PASSWORD"];

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    .Replace("${DB_PASSWORD}", password);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();