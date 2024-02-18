
using Microsoft.EntityFrameworkCore;
using TodoApplication.Data;
using TodoApplication.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;

namespace TodoApplication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            //connect to the database

            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ??
                throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            builder.Services.AddDbContext<ApiDbContext>(options => options.UseSqlite(connectionString));

            //configuring auth

            builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));

            var key = Encoding.ASCII.GetBytes(builder.Configuration["JwtConfig:Secret"]);
            var TokenValidationParams = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                RequireExpirationTime = false,
            };
            builder.Services.AddSingleton(TokenValidationParams);

            builder.Services.AddAuthentication(options => {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(jwt=>{
                
                jwt.SaveToken = true;
                jwt.TokenValidationParameters = TokenValidationParams;
            });

            builder.Services.AddDefaultIdentity<IdentityUser> (options => options.SignIn.RequireConfirmedAccount=true)
                .AddEntityFrameworkStores<ApiDbContext>();
            
            // Add services to the container.

            builder.Services.AddControllers();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseAuthentication ();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
