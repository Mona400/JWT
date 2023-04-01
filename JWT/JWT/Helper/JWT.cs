using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace JWT.Helper
{
    public class JWTc
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double DurationInDay { get; set; }
    }
}
