// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace IdentityServer.IntegrationTests.Clients
{
    public class CustomTokenResponseClients
    {
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;

        public CustomTokenResponseClients()
        {
            var builder = new WebHostBuilder()
                .UseStartup<StartupWithCustomTokenResponses>();
            var server = new TestServer(builder);

            _client = server.CreateClient();
        }

        [Fact]
        public async Task Resource_owner_success_should_return_custom_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                UserName = "bob",
                Password = "bob",
                Scope = "api1"
            });

            // raw fields
            var fields = GetFields(response);
            fields.Should().Contain("string_value", "some_string");
            ((Int64)fields["int_value"]).Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeFalse();
            fields.TryGetValue("error_description", out temp).Should().BeFalse();
            fields.TryGetValue("token_type", out temp).Should().BeTrue();
            fields.TryGetValue("expires_in", out temp).Should().BeTrue();

            var responseObject = fields["dto"] as JsonElement?;
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(false);
            response.ExpiresIn.Should().Be(3600);
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            

            // token content
            var payload = GetPayload(response);
            payload.Count().Should().Be(12);
            payload.Keys.Should().Contain("iss");
            payload["iss"].ValueKind.Should().Be(JsonValueKind.String);
            payload["iss"].GetString().Should().Be("https://idsvr4");
            payload.Keys.Should().Contain("client_id");
            payload["client_id"].ValueKind.Should().Be(JsonValueKind.String);
            payload["client_id"].GetString().Should().Be("roclient");
            payload.Keys.Should().Contain("sub");
            payload["sub"].ValueKind.Should().Be(JsonValueKind.String);
            payload["sub"].GetString().Should().Be("bob");
            payload.Keys.Should().Contain("idp");
            payload["idp"].ValueKind.Should().Be(JsonValueKind.String);
            payload["idp"].GetString().Should().Be("local");

            payload["aud"].GetString().Should().Be("api");

            payload["scope"].ValueKind.Should().Be(JsonValueKind.Array);
            var scopes = payload["scope"].EnumerateArray().Select(s => s.ToString());
            scopes.First().ToString().Should().Be("api1");

            payload["amr"].ValueKind.Should().Be(JsonValueKind.Array);
            var amr = payload["amr"].EnumerateArray().Select(s => s.ToString());
            amr.Count().Should().Be(1);
            amr.First().ToString().Should().Be("password");
        }

        [Fact]
        public async Task Resource_owner_failure_should_return_custom_error_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                UserName = "bob",
                Password = "invalid",
                Scope = "api1"
            });

            // raw fields
            var fields = GetFields(response);
            fields.Should().Contain("string_value", "some_string");
            ((Int64)fields["int_value"]).Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeTrue();
            fields.TryGetValue("error_description", out temp).Should().BeTrue();
            fields.TryGetValue("token_type", out temp).Should().BeFalse();
            fields.TryGetValue("expires_in", out temp).Should().BeFalse();

            var responseObject = fields["dto"] as JsonElement?;
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(true);
            response.Error.Should().Be("invalid_grant");
            response.ErrorDescription.Should().Be("invalid_credential");
            response.ExpiresIn.Should().Be(0);
            response.TokenType.Should().BeNull();
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
        }

        [Fact]
        public async Task Extension_grant_success_should_return_custom_response()
        {
            var response = await _client.RequestTokenAsync(new TokenRequest
            {
                Address = TokenEndpoint,
                GrantType = "custom",

                ClientId = "client.custom",
                ClientSecret = "secret",

                Parameters =
                {
                    { "scope", "api1" },
                    { "outcome", "succeed"}
                }
            });


            // raw fields
            var fields = GetFields(response);
            fields.Should().Contain("string_value", "some_string");
            ((Int64)fields["int_value"]).Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeFalse();
            fields.TryGetValue("error_description", out temp).Should().BeFalse();
            fields.TryGetValue("token_type", out temp).Should().BeTrue();
            fields.TryGetValue("expires_in", out temp).Should().BeTrue();

            var responseObject = fields["dto"] as JsonElement?;
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(false);
            response.ExpiresIn.Should().Be(3600);
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();


            // token content
            var payload = GetPayload(response);
            payload.Count().Should().Be(12);
            payload.Keys.Should().Contain("iss");
            payload["iss"].ValueKind.Should().Be(JsonValueKind.String);
            payload["iss"].GetString().Should().Be("https://idsvr4");
            payload.Keys.Should().Contain("client_id");
            payload["client_id"].ValueKind.Should().Be(JsonValueKind.String);
            payload["client_id"].GetString().Should().Be("client.custom");
            payload.Keys.Should().Contain("sub");
            payload["sub"].ValueKind.Should().Be(JsonValueKind.String);
            payload["sub"].GetString().Should().Be("bob");
            payload.Keys.Should().Contain("idp");
            payload["idp"].ValueKind.Should().Be(JsonValueKind.String);
            payload["idp"].GetString().Should().Be("local");

            payload["aud"].GetString().Should().Be("api");

            payload["scope"].ValueKind.Should().Be(JsonValueKind.Array);
            var scopes = payload["scope"].EnumerateArray().Select(s => s.ToString());
            scopes.First().ToString().Should().Be("api1");

            payload["amr"].ValueKind.Should().Be(JsonValueKind.Array);
            var amr = payload["amr"].EnumerateArray().Select(s => s.ToString());
            amr.Count().Should().Be(1);
            amr.First().ToString().Should().Be("custom");

        }

        [Fact]
        public async Task Extension_grant_failure_should_return_custom_error_response()
        {
            var response = await _client.RequestTokenAsync(new TokenRequest
            {
                Address = TokenEndpoint,
                GrantType = "custom",

                ClientId = "client.custom",
                ClientSecret = "secret",

                Parameters =
                {
                    { "scope", "api1" },
                    { "outcome", "fail"}
                }
            });


            // raw fields
            var fields = GetFields(response);
            fields.Should().Contain("string_value", "some_string");
            ((Int64)fields["int_value"]).Should().Be(42);

            object temp;
            fields.TryGetValue("identity_token", out temp).Should().BeFalse();
            fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
            fields.TryGetValue("error", out temp).Should().BeTrue();
            fields.TryGetValue("error_description", out temp).Should().BeTrue();
            fields.TryGetValue("token_type", out temp).Should().BeFalse();
            fields.TryGetValue("expires_in", out temp).Should().BeFalse();

            var responseObject = fields["dto"] as JsonElement?;
            responseObject.Should().NotBeNull();

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(true);
            response.Error.Should().Be("invalid_grant");
            response.ErrorDescription.Should().Be("invalid_credential");
            response.ExpiresIn.Should().Be(0);
            response.TokenType.Should().BeNull();
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
        }

        private CustomResponseDto GetDto(JsonElement? responseObject)
        {
            if (!responseObject.HasValue)
            {
                return null;
            }
            return responseObject.Value.Deserialize<CustomResponseDto>();
        }

        private Dictionary<string, object> GetFields(TokenResponse response)
        {
            return response.Json?.EnumerateObject().ToDictionary(je => je.Name, je => {
                object value;
                switch (je.Value.ValueKind)
                {
                    case JsonValueKind.Undefined:
                        value= null;
                        break;
                    case JsonValueKind.Object:
                        value = je.Value;
                        break;
                    case JsonValueKind.Array:
                        value = je.Value;
                        break;
                    case JsonValueKind.String:
                        value = je.Value.GetString();
                        break;
                    case JsonValueKind.Number:
                        value = je.Value.GetInt64();
                        break;
                    case JsonValueKind.True:
                    case JsonValueKind.False:
                        value = je.Value.GetBoolean();
						break;
                    case JsonValueKind.Null:
                        value = null;
                        break;
                    default:
                        value = null;
                        break;
                }
                return value;
            });
        }

        private Dictionary<string, JsonElement> GetPayload(TokenResponse response)
        {
            var token = response.AccessToken.Split('.').Skip(1).Take(1).First();
            var dictionary = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                Encoding.UTF8.GetString(Base64Url.Decode(token)));

            return dictionary;
        }
    }
}