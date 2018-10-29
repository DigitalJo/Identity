// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Testing.xunit;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.AspNetCore.ApiAuthorization.IdentityServer
{
    public class ConfigureSigningCredentialsTests
    {
        [ConditionalFact]
        [FrameworkSkipCondition(RuntimeFrameworks.CLR)]
        public void Configure_AddsDevelopmentKeyFromConfiguration()
        {
            var expectedKeyPath = Path.Combine(Directory.GetCurrentDirectory(), "./testkey.json");
            try
            {
                // Arrange
                var configuration = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string>()
                    {
                        ["Type"] = "Development",
                        ["FilePath"] = "testkey.json"
                    }).Build();

                var configureSigningCredentials = new ConfigureSigningCredentials(
                    configuration,
                    new TestLogger<ConfigureSigningCredentials>());

                var options = new ApiAuthorizationOptions();

                // Act
                configureSigningCredentials.Configure(options);

                // Assert
                Assert.NotNull(options);
                Assert.True(File.Exists(expectedKeyPath));
                Assert.NotNull(options.SigningCredential);
                Assert.Equal("Development", options.SigningCredential.Kid);
                Assert.IsType<RsaSecurityKey>(options.SigningCredential.Key);
            }
            finally
            {
                if (File.Exists(expectedKeyPath))
                {
                    File.Delete(expectedKeyPath);
                }
            }
        }

        [Fact]
        public void Configure_LoadsPfxCertificateCredentialFromConfiguration()
        {
            // Arrange
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string>()
                {
                    ["Type"] = "File",
                    ["FilePath"] = "test.pfx",
                    ["Password"] = "aspnetcore"
                }).Build();

            var configureSigningCredentials = new ConfigureSigningCredentials(
                configuration,
                new TestLogger<ConfigureSigningCredentials>());

            var options = new ApiAuthorizationOptions();

            // Act
            configureSigningCredentials.Configure(options);

            // Assert
            Assert.NotNull(options);
            Assert.NotNull(options.SigningCredential);
            var key = Assert.IsType<X509SecurityKey>(options.SigningCredential.Key);
            Assert.NotNull(key.Certificate);
            Assert.Equal("AC8FDF4BD4C10841BD24DC88D983225D10B43BB2", key.Certificate.Thumbprint);
        }

        [Fact]
        public void Configure_LoadsCertificateStoreCertificateCredentialFromConfiguration()
        {
            try
            {
                // Arrange
                var x509Certificate = new X509Certificate2("test.pfx", "aspnetcore", X509KeyStorageFlags.DefaultKeySet);
                SetupTestCertificate(x509Certificate);

                var configuration = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string>()
                    {
                        ["Type"] = "Store",
                        ["StoreLocation"] = "CurrentUser",
                        ["StoreName"] = "My",
                        ["Name"] = "CN=Test"
                    }).Build();

                var configureSigningCredentials = new ConfigureSigningCredentials(
                    configuration,
                    new TestLogger<ConfigureSigningCredentials>());

                var options = new ApiAuthorizationOptions();

                // Act
                configureSigningCredentials.Configure(options);

                // Assert
                Assert.NotNull(options);
                Assert.NotNull(options.SigningCredential);
                var key = Assert.IsType<X509SecurityKey>(options.SigningCredential.Key);
                Assert.NotNull(key.Certificate);
                Assert.Equal("AC8FDF4BD4C10841BD24DC88D983225D10B43BB2", key.Certificate.Thumbprint);
            }
            finally
            {
                CleanupTestCertificate();
            }
        }

        private static void CleanupTestCertificate()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadWrite);
                var certificates = store
                    .Certificates
                    .Find(X509FindType.FindByThumbprint, "1646CFBEE354788D7116DF86EFC35C0075A9C05D", validOnly: false);

                foreach (var certificate in certificates)
                {
                    store.Certificates.Remove(certificate);
                }
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }

                store.Close();
            }
        }

        private static void SetupTestCertificate(X509Certificate2 x509Certificate)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadWrite);
                var certificates = store
                    .Certificates
                    .Find(X509FindType.FindByThumbprint, "AC8FDF4BD4C10841BD24DC88D983225D10B43BB2", validOnly: false);
                if (certificates.Count == 0)
                {
                    store.Add(x509Certificate);
                }
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
                store.Close();
            }
        }
    }
}
