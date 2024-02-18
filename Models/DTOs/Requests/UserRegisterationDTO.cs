using System.ComponentModel.DataAnnotations;

namespace TodoApplication.Models.DTOs.Requests
{
    public class UserRegisterationDTO
    {
        [Required]
        [EmailAddress]
        public String Email { get; set; }
        [Required]
        public string Username { get; set; }
        [Required]
        public String Password { get; set; }
    }
}
