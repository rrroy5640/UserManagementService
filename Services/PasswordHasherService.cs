using Microsoft.AspNetCore.Identity;

namespace UserManagementService.Models
{
    public interface IPasswordHasherService
    {
        string HashPassword(string password);
        bool VerifyPassword(string hashedPassword, string password);
    }

    public class PasswordHasherService : IPasswordHasherService
    {
        private readonly PasswordHasher<object> _passwordHasher;

        public PasswordHasherService()
        {
            _passwordHasher = new PasswordHasher<object>();
        }

        public string HashPassword(string password)
        {
            return _passwordHasher.HashPassword(null!, password);
        }

        public bool VerifyPassword(string hashedPassword, string password)
        {
            var verificationResult = _passwordHasher.VerifyHashedPassword(null!, hashedPassword, password);
            return verificationResult == PasswordVerificationResult.Success;
        }
    }
}