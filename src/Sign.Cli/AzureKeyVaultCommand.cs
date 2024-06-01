// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.CommandLine;
using System.CommandLine.Invocation;
using Azure.Core;
using Azure.Identity;
using Sign.Core;

namespace Sign.Cli
{
    internal sealed class AzureKeyVaultCommand : Command
    {
        private readonly CodeCommandHandler _codeCommandHandler;

        internal Option<string> CertificateOption { get; } = new(["-kvc", "--azure-key-vault-certificate"], AzureKeyVaultResources.CertificateOptionDescription);
        internal Option<string?> ClientIdOption { get; } = new(["-kvi", "--azure-key-vault-client-id"], AzureKeyVaultResources.ClientIdOptionDescription);
        internal Option<string?> ClientSecretOption { get; } = new(["-kvs", "--azure-key-vault-client-secret"], AzureKeyVaultResources.ClientSecretOptionDescription);
        internal Option<bool> ManagedIdentityOption { get; } = new(["-kvm", "--azure-key-vault-managed-identity"], getDefaultValue: () => false, AzureKeyVaultResources.ManagedIdentityOptionDescription);
        internal Option<string?> TenantIdOption { get; } = new(["-kvt", "--azure-key-vault-tenant-id"], AzureKeyVaultResources.TenantIdOptionDescription);
        internal Option<Uri> UrlOption { get; } = new(["-kvu", "--azure-key-vault-url"], AzureKeyVaultResources.UrlOptionDescription);

        internal AzureKeyVaultCommand(CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory)
            : base("azure-key-vault", AzureKeyVaultResources.CommandDescription)
        {
            _codeCommandHandler = new CodeCommandHandler(codeCommand, serviceProviderFactory);

            CertificateOption.IsRequired = true;
            UrlOption.IsRequired = true;

            ManagedIdentityOption.SetDefaultValue(false);

            AddOption(UrlOption);
            AddOption(TenantIdOption);
            AddOption(ClientIdOption);
            AddOption(ClientSecretOption);
            AddOption(CertificateOption);
            AddOption(ManagedIdentityOption);

            AddArgument(codeCommand.FileArgument);

            this.SetHandler(async (InvocationContext context) =>
            {
                Uri? url = context.ParseResult.GetValueForOption(UrlOption);
                string? tenantId = context.ParseResult.GetValueForOption(TenantIdOption);
                string? clientId = context.ParseResult.GetValueForOption(ClientIdOption);
                string? secret = context.ParseResult.GetValueForOption(ClientSecretOption);
                string? certificateId = context.ParseResult.GetValueForOption(CertificateOption);
                bool useManagedIdentity = context.ParseResult.GetValueForOption(ManagedIdentityOption);

                TokenCredential? credential = null;

                if (useManagedIdentity)
                {
                    credential = new DefaultAzureCredential();
                }
                else
                {
                    if (string.IsNullOrEmpty(tenantId) ||
                        string.IsNullOrEmpty(clientId) ||
                        string.IsNullOrEmpty(secret))
                    {
                        context.Console.Error.WriteFormattedLine(
                                AzureKeyVaultResources.InvalidClientSecretCredential,
                                TenantIdOption,
                                ClientIdOption,
                                ClientSecretOption);
                        context.ExitCode = ExitCode.NoInputsFound;
                        return;
                    }

                    credential = new ClientSecretCredential(tenantId!, clientId!, secret!);
                }

                KeyVaultServiceProvider keyVaultServiceProvider = new(credential, url!, certificateId!);

                await _codeCommandHandler.Handle(context, keyVaultServiceProvider);
            });
        }
    }
}