using System.Collections.Generic;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace IdentityServer4.Models
{
    /// <summary>
    /// Default JwtPayload.
    /// </summary>
    internal class CustomJwtPayload : JwtPayload
    {
        /// <summary>
        /// Initializes a new instance of the System.IdentityModel.Tokens.Jwt.JwtPayload class with claims added for each parameter specified. Default string comparer System.StringComparer.Ordinal.
        /// </summary>
        /// <param name="issuer">If this value is not null, a { iss, 'issuer' } claim will be added, overwriting any 'iss' claim in 'claims' if present.</param>
        /// <param name="audience">If this value is not null, a { aud, 'audience' } claim will be added, appending to any 'aud' claims in 'claims' if present.</param>
        /// <param name="claims">If this value is not null then for each System.Security.Claims.Claim a { 'Claim.Type', 'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type', List&lt;object&gt; } will be created to contain the duplicate values.</param>
        /// <param name="notBefore">If notbefore.HasValue a { nbf, 'value' } claim is added, overwriting any 'nbf' claim in 'claims' if present.</param>
        /// <param name="expires">If expires.HasValue a { exp, 'value' } claim is added, overwriting any 'exp' claim in 'claims' if present.</param>
        public CustomJwtPayload(string issuer, string audience, IEnumerable<Claim> claims, DateTime? notBefore, DateTime? expires)
            : base(issuer, audience, claims, notBefore, expires)
        {
        }

        /// <summary>
        ///  Serializes this instance to JSON.
        /// </summary>
        /// <returns>This instance as JSON.</returns>
        public override string SerializeToJson()
        {
            return JsonSerializer.Serialize(this);
        }
    }
}
