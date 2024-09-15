using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using UserManagementService.Services;
using UserManagementService.Models;
using UserManagementService.DTOs.Requests;
using UserManagementService.DTOs.Responses;
using Microsoft.AspNetCore.Authorization;

namespace UserManagementService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly UserService _userService;
        private readonly IConfiguration _configuration;
        private readonly IPasswordHasherService _passwordHasherService;

        public UserController(UserService userService, IConfiguration configuration, IPasswordHasherService passwordHasherService)
        {
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _passwordHasherService = passwordHasherService ?? throw new ArgumentNullException(nameof(passwordHasherService));
        }


        private string GenerateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = _configuration["JWT_SECRET_KEY"];
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key!));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Id!.ToString()),
                    new Claim(ClaimTypes.Email, user.Email)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256Signature),
                Issuer = "linyi-dev.com",
                Audience = "linyi-dev.com"
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private bool ValidateTokenEmail(string email)
        {
            var tokenEmail = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(tokenEmail) || !tokenEmail.Equals(email, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        [HttpGet("{email}")]
        public ActionResult<User> Get(string email)
        {
            var user = _userService.Get(email);

            if (user == null)
            {
                return NotFound();
            }

            return Ok(user);
        }

        [HttpPost]
        public ActionResult<User> Register([FromBody] RegisterRequest registerRequest)
        {
            var existingUser = _userService.Get(registerRequest.Email);
            if (existingUser != null)
            {
                return Conflict("A user with that email already exists.");
            }

            var user = new User
            {
                Name = registerRequest.Name,
                Email = registerRequest.Email,
                PasswordHash = _passwordHasherService.HashPassword(registerRequest.Password)
            };

            _userService.Create(user);

            var registerResponse = new RegisterResponse
            {
                Message = "User registered successfully."
            };
            return CreatedAtAction(nameof(Get), new { email = user.Email }, registerResponse);
        }

        [HttpPost("login")]
        public ActionResult<LoginResponse> Login(LoginRequest loginRequest)
        {
            var user = _userService.Get(loginRequest.Email);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (!_passwordHasherService.VerifyPassword(user.PasswordHash, loginRequest.Password))
            {
                return Unauthorized("Invalid password.");
            }

            var token = GenerateToken(user);
            return Ok(new LoginResponse { Token = token });
        }

        [HttpPut("{email}/password")]
        public ActionResult<ChangePasswordResponse> ChangePassword([FromRoute] string email, [FromBody] ChangePasswordRequest changePasswordRequest)
        {
            ValidateTokenEmail(email);

            var user = _userService.Get(email);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (!_passwordHasherService.VerifyPassword(user.PasswordHash, changePasswordRequest.OldPassword))
            {
                return Unauthorized("Invalid password.");
            }

            user.PasswordHash = _passwordHasherService.HashPassword(changePasswordRequest.NewPassword);

            _userService.Update(user.Email, user);
            var changePasswordResponse = new ChangePasswordResponse
            {
                Message = "Password changed successfully."
            };

            return Ok(changePasswordResponse);
        }

        [HttpDelete("{email}")]
        [Authorize]
        public ActionResult Delete([FromRoute] string email)
        {
            var tokenEmail = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(tokenEmail) || !tokenEmail.Equals(email, StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Email claim is missing or invalid.");
            }
            var user = _userService.Get(email);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            _userService.Remove(user);
            return Ok("User deleted successfully.");
        }

        [HttpPut("{email}")]
        [Authorize]
        public ActionResult Update([FromRoute] string email, [FromBody] UpdateUserRequest userIn)
        {
            var tokenEmail = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(tokenEmail) || !tokenEmail.Equals(email, StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Email claim is missing or invalid.");
            }

            var user = _userService.Get(email);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var existingUser = _userService.Get(userIn.Email);

            if (existingUser != null)
            {
                return Conflict("A user with that email already exists.");
            }

            user.Name = userIn.Name;
            user.Email = userIn.Email;

            _userService.Update(email, user);
            return Ok("User updated successfully.");
        }

        [HttpGet("me")]
        [Authorize]
        public ActionResult<GetUserResponse> GetCurrentUser()
        {
            var email = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email claim is missing or invalid.");
            }

            var user = _userService.Get(email);
            var response = new GetUserResponse
            {
                Name = user.Name,
                Email = user.Email
            };

            if (user == null)
            {
                return NotFound("User not found.");
            }

            return Ok(response);
        }

        [HttpGet("search")]
        [Authorize]
        public ActionResult<List<User>> SearchUsers(string query)
        {
            var users = _userService.Search(query);
            return Ok(users);
        }
    }
}