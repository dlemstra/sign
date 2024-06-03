// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using Azure.Core;

namespace Sign.Core.CertificateServices
{
    internal class TrustedSigningServiceProvider : ICodeSigningServiceProvider
    {
        private readonly TokenCredential _credential;
        private readonly Uri _endpoint;
        private readonly string _accountName;
        private readonly string _certificateProfileName;
        private readonly object _lockObject = new();
        private TrustedSigningService? _trustedSigningService;

        public TrustedSigningServiceProvider(
            TokenCredential credential,
            Uri endpoint,
            string accountName,
            string certificateProfileName)
        {
            ArgumentNullException.ThrowIfNull(credential, nameof(credential));
            ArgumentNullException.ThrowIfNull(endpoint, nameof(endpoint));
            ArgumentException.ThrowIfNullOrEmpty(accountName, nameof(accountName));
            ArgumentException.ThrowIfNullOrEmpty(certificateProfileName, nameof(certificateProfileName));

            _credential = credential;
            _endpoint = endpoint;
            _accountName = accountName;
            _certificateProfileName = certificateProfileName;
        }

        public ISignatureAlgorithmProvider GetSignatureAlgorithmProvider(IServiceProvider serviceProvider)
        {
            ArgumentNullException.ThrowIfNull(serviceProvider, nameof(serviceProvider));

            return GetService(serviceProvider);
        }

        public ICertificateProvider GetCertificateProvider(IServiceProvider serviceProvider)
        {
            ArgumentNullException.ThrowIfNull(serviceProvider, nameof(serviceProvider));

            return GetService(serviceProvider);
        }

        private TrustedSigningService GetService(IServiceProvider serviceProvider)
        {
            if (_trustedSigningService is not null)
            {
                return _trustedSigningService;
            }

            lock (_lockObject)
            {
                if (_trustedSigningService is not null)
                {
                    return _trustedSigningService;
                }

                _trustedSigningService = new TrustedSigningService(serviceProvider, _credential, _endpoint, _accountName, _certificateProfileName);
            }

            return _trustedSigningService;
        }
    }
}
