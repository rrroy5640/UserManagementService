using System.Text;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using UserManagementService.Models;
using UserManagementService.Services;

var builder = WebApplication.CreateBuilder(args);

var JwtSettings = builder.Configuration.GetSection("JwtSettings");
var AWSParameterStore = builder.Configuration.GetSection("AWS:ParameterStore");

builder.Services.AddAWSService<IAmazonSimpleSystemsManagement>();
var awsOptions = builder.Configuration.GetAWSOptions();
var ssmClient = awsOptions.CreateServiceClient<IAmazonSimpleSystemsManagement>();

var JwtSecretKeyPath = AWSParameterStore["JwtSecretKeyPath"];
var DbConnectionStringPath = AWSParameterStore["DbConnectionStringPath"];
var DbNamePath = AWSParameterStore["DbNamePath"];

var Issuer = JwtSettings["Issuer"];
var Audience = JwtSettings["Audience"];

if (string.IsNullOrEmpty(JwtSecretKeyPath))
{
    throw new ArgumentNullException(nameof(JwtSecretKeyPath), "JwtSecretKeyPath cannot be null or empty.");
}

if (string.IsNullOrEmpty(DbConnectionStringPath))
{
    throw new ArgumentNullException(nameof(DbConnectionStringPath), "DbConnectionStringPath cannot be null or empty.");
}

if (string.IsNullOrEmpty(DbNamePath))
{
    throw new ArgumentNullException(nameof(DbNamePath), "DbNamePath cannot be null or empty.");
}

if (string.IsNullOrEmpty(Issuer))
{
    throw new ArgumentNullException(nameof(Issuer), "Issuer cannot be null or empty.");
}

if (string.IsNullOrEmpty(Audience))
{
    throw new ArgumentNullException(nameof(Audience), "Audience cannot be null or empty.");
}

await ConfigureJwtAuthentication(builder, ssmClient, JwtSecretKeyPath, Issuer, Audience);
await ConfigureDatabase(builder, ssmClient, DbConnectionStringPath, DbNamePath);

builder.Services.AddAuthorization();

builder.Services.AddSingleton<UserService>();
builder.Services.AddSingleton<IPasswordHasherService, PasswordHasherService>();

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

foreach (var url in app.Urls)
{
    Console.WriteLine($"Listening on: {url}");
}

app.Run();

async Task ConfigureJwtAuthentication(WebApplicationBuilder builder, IAmazonSimpleSystemsManagement ssmClient, string jwtSecretKeyPath, string issuer, string audience)
{
    try
    {
        var parameterResponse = await ssmClient.GetParameterAsync(new GetParameterRequest
        {
            Name = jwtSecretKeyPath,
            WithDecryption = true
        });

        var secretKey = parameterResponse.Parameter.Value;
        builder.Configuration["JWT_SECRET_KEY"] = secretKey;
        builder.Services.AddAuthentication(option =>
            {
                option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = issuer,
                    ValidAudience = audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
                };
            });
    }
    catch (Exception e)
    {
        Console.WriteLine($"Error retrieving JWT secret key: {e.Message}");
        throw;
    }

}

async Task ConfigureDatabase(WebApplicationBuilder builder, IAmazonSimpleSystemsManagement ssmClient, string connectionStringPath, string databaseNamePath)
{
    try
    {
        var connectionStringParameterResponse = await ssmClient.GetParameterAsync(new GetParameterRequest
        {
            Name = connectionStringPath,
            WithDecryption = true
        });

        var databaseStringParameterResponse = await ssmClient.GetParameterAsync(new GetParameterRequest
        {
            Name = databaseNamePath,
            WithDecryption = true
        });

        var connectionString = connectionStringParameterResponse.Parameter.Value;
        var databaseName = databaseStringParameterResponse.Parameter.Value;
        builder.Services.Configure<MongoDBSettings>(option =>
        {
            option.ConnectionString = connectionString;
            option.DatabaseName = databaseName;
        });

        builder.Services.AddSingleton<IMongoDBSettings>(sp =>
         sp.GetRequiredService<IOptions<MongoDBSettings>>().Value
        );

        builder.Services.AddSingleton<IMongoClient>(sp =>
        {
            var settings = sp.GetRequiredService<IMongoDBSettings>();
            return new MongoClient(settings.ConnectionString);
        });

        builder.Services.AddScoped(sp =>
        {
            var client = sp.GetRequiredService<IMongoClient>();
            var settings = sp.GetRequiredService<IMongoDBSettings>();
            return client.GetDatabase(settings.DatabaseName);
        });
    }
    catch (Exception e)
    {
        Console.WriteLine($"Error retrieving database connection string: {e.Message}");
        throw;
    }
}