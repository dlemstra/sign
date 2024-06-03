// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.CommandLine;
using System.CommandLine.Invocation;
using Azure.Core;
using Azure.Identity;
using Sign.Core;
using Sign.Core.CertificateServices;

namespace Sign.Cli
{
    internal sealed class TrustedSigningCommand : Command
    {
        private readonly CodeCommandHandler _codeCommandHandler;

        internal Option<Uri> EndpointOption { get; } = new(["-tse", "--trusted-signing-endpoint"], TrustedSigningResources.EndpointOptionDescription);
        internal Option<string> AccountOption { get; } = new(["-tsa", "--trusted-signing-account"], TrustedSigningResources.AccountNameOptionDescription);
        internal Option<string> CertificateProfileOption { get; } = new(["-tsc", "--trusted-signing-certificate-profile"], TrustedSigningResources.CertificateProfileNameOptionDescription);
        internal Option<bool> ManagedIdentityOption { get; } = new(["-tsm", "--trusted-signing-managed-identity"], getDefaultValue: () => false, AzureKeyVaultResources.ManagedIdentityOptionDescription);
        internal Option<string?> TenantIdOption { get; } = new(["-tst", "--trusted-signing-tenant-id"], AzureKeyVaultResources.TenantIdOptionDescription);
        internal Option<string?> ClientIdOption { get; } = new(["-tsi", "--trusted-signing-client-id"], AzureKeyVaultResources.ClientIdOptionDescription);
        internal Option<string?> ClientSecretOption { get; } = new(["-tss", "--trusted-signing-client-secret"], AzureKeyVaultResources.ClientSecretOptionDescription);

        internal TrustedSigningCommand(CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory)
               : base("trusted-signing", TrustedSigningResources.CommandDescription)
        {
            _codeCommandHandler = new CodeCommandHandler(codeCommand, serviceProviderFactory);

            EndpointOption.IsRequired = true;
            AccountOption.IsRequired = true;
            CertificateProfileOption.IsRequired = true;

            AddOption(EndpointOption);
            AddOption(AccountOption);
            AddOption(CertificateProfileOption);
            AddOption(ManagedIdentityOption);
            AddOption(TenantIdOption);
            AddOption(ClientIdOption);
            AddOption(ClientSecretOption);

            AddArgument(codeCommand.FileArgument);

            this.SetHandler(async (InvocationContext context) =>
            {
                bool useManagedIdentity = context.ParseResult.GetValueForOption(ManagedIdentityOption);

                TokenCredential? credential = null;

                if (useManagedIdentity)
                {
                    credential = new DefaultAzureCredential();
                }

                string? tenantId = context.ParseResult.GetValueForOption(TenantIdOption);
                string? clientId = context.ParseResult.GetValueForOption(ClientIdOption);
                string? clientSecret = context.ParseResult.GetValueForOption(ClientSecretOption);

                if (string.IsNullOrEmpty(tenantId) ||
                    string.IsNullOrEmpty(clientId) ||
                    string.IsNullOrEmpty(clientSecret))
                {
                    context.Console.Error.WriteFormattedLine(
                                AzureKeyVaultResources.InvalidClientSecretCredential,
                                TenantIdOption,
                                ClientIdOption,
                                ClientSecretOption);
                    context.ExitCode = ExitCode.NoInputsFound;
                    return;
                }

                credential = new ClientSecretCredential(tenantId, clientId, clientSecret);

                Uri endpoint = context.ParseResult.GetValueForOption(EndpointOption)!;
                string accountName = context.ParseResult.GetValueForOption(AccountOption)!;
                string certificateId = context.ParseResult.GetValueForOption(CertificateProfileOption)!;

                TrustedSigningServiceProvider trustedSigningServiceProvider = new(credential, endpoint, accountName, certificateId);

                await _codeCommandHandler.Handle(context, trustedSigningServiceProvider);
            });
        }
    }
}