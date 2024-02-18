using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TodoApplication.Configuration;
using TodoApplication.Data;
using TodoApplication.Models;
using TodoApplication.Models.DTOs.Requests;
using TodoApplication.Models.DTOs.Responses;

namespace TodoApplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthManagementController : ControllerBase
    {

        private readonly UserManager<IdentityUser> _userManager;

        private readonly JwtConfig _jwtConfig;

        private readonly TokenValidationParameters _tokenValidationParams;

        private readonly ApiDbContext _dbContext;

        public AuthManagementController(UserManager<IdentityUser> userManager,
            IOptionsMonitor<JwtConfig> optionsMonitor,
            TokenValidationParameters tokenValidationParams,
            ApiDbContext dbContext)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _tokenValidationParams = tokenValidationParams;
            _dbContext = dbContext;
        }
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegisterationDTO user)
        {
            if(ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);
                if (existingUser != null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>()
                            {
                                "Email already in use"
                            },
                        Success = false,

                    });
                }
                var newUser = new IdentityUser()
                {
                    Email = user.Email,
                    UserName = user.Username,
                };
                var isCreated = await _userManager.CreateAsync(newUser,user.Password);
                if(isCreated.Succeeded)
                {
                    var jwtToken = await GenerateJwtToken(newUser);

                    return Ok(jwtToken);
                }
                else
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = isCreated.Errors.Select(x => x.Description).ToList(),                            
                        Success = false,

                    });
                }
            }
            return BadRequest(new RegistrationResponse()
            {
                Errors = new List<string>()
                {
                    "Invalid payload"
                },
                Success = false,
               
            });
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest user)
        {
            if(ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);
                if(existingUser == null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>()
                            {
                                "User is not Registered"
                            },
                        Success = false,

                    });
                }
                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);
                if(!isCorrect)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>()
                        {
                            "login failed"
                        },
                        Success = false,

                    });
                }
                var jwtToken = await GenerateJwtToken(existingUser);
                return Ok(jwtToken);
            }
            return BadRequest(new RegistrationResponse()
            {
                Errors = new List<string>()
                        {
                            "Invalid payload"
                        },
                Success = false,

            });

        }
        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody]TokenRequest tokenRequest)
        {
            if(ModelState.IsValid)
            {
             var result =  await VerifiyAndGenerateToken(tokenRequest);
             if(result== null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors= new List<string>()
                        {
                            "invalid Token"
                        },
                        Success = false,
                    });
                }
             return Ok(result);
            }
            return BadRequest(new RegistrationResponse()
            {
                Errors = new List<string>
                {
                    "invalid"
                },
                Success = false,
            });
        }

        private async Task<AuthResult> VerifiyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler =new JwtSecurityTokenHandler();
            try
            {   //validation 1 - token format
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token,_tokenValidationParams,out var validatedToken);
                
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    //validation 2 - encryption alg
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase);
                    if (result == false)
                    {
                        return null;
                    }

                }
                //validation 3 - expiry 
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
                var expiryDate = unixTimeStampToDateTime(utcExpiryDate);
                if (expiryDate > DateTime.UtcNow)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>
                        {
                            "not expired"
                        }
                    };
                }
                //validation 4 - existance 
                var storedToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x=> x.Token == tokenRequest.RefreshToken);
                if (storedToken == null)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>
                        {
                            "token does not exist"
                        }
                    };
                }
                //validation 5 - usage
                if (storedToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>
                        {
                            "token has been used"
                        }
                    };
                }
                //validation 6 - revoking
                if(storedToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>
                        {
                            "Token has been revoked"
                        }
                    };
                }
                //validation 7 - id
                var jti = tokenInVerification.Claims.FirstOrDefault(x=>x.Type == JwtRegisteredClaimNames.Jti).Value;
                if (storedToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>
                        {
                            "Token does not match"
                        }
                    };
                }
                // update token
                storedToken.IsUsed = true;
                _dbContext.RefreshTokens.Update(storedToken);
                await _dbContext.SaveChangesAsync();

                //generate a new token
                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtToken(dbUser);
            }
            catch (Exception ex)
            {
                return null; 
            }
        }

        private DateTime unixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();
            return dateTimeVal;
        }

        private async Task<AuthResult> GenerateJwtToken(IdentityUser user) 
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtConfig.secret);
            var tokenDiscriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddSeconds(300),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256Signature)
            };
            var token = jwtTokenHandler.CreateToken(tokenDiscriptor);
            var jwtToken= jwtTokenHandler.WriteToken(token);
            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                UserId  = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                Token = RandomString(35) + Guid.NewGuid().ToString(),
            };
            await _dbContext.RefreshTokens.AddAsync(refreshToken);
            await _dbContext.SaveChangesAsync();
            return new AuthResult()
            {
                Token = jwtToken,
                Success = true,
                RefreshToken = refreshToken.Token,
            };
        }

        private string RandomString(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(x => x[random.Next(x.Length)]).ToArray());
        }
    }
}
