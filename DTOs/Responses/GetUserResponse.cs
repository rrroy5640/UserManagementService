namespace UserManagementService.DTOs.Responses
{
    public class GetUserResponse
    {
        public required string Name { get; set; }
        public required string Email { get; set; }
    }
}