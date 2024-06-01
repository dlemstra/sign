// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.IO;
using Sign.Core;

namespace Sign.Cli
{
    internal sealed class CertificateStoreCommand : Command
    {
        private readonly CodeCommandHandler _codeCommandHandler;

        internal Option<string> Sha1ThumbprintOption { get; } = new(["-s", "--sha1"], CertificateStoreResources.Sha1ThumbprintOptionDescription);
        internal Option<string?> CertificateFileOption { get; } = new(["-cf", "--certificate-file"], CertificateStoreResources.CertificateFileOptionDescription);
        internal Option<string?> CertificatePasswordOption { get; } = new(["-p", "--password"], CertificateStoreResources.CertificatePasswordOptionDescription);
        internal Option<string?> CryptoServiceProviderOption { get; } = new(["-csp", "--crypto-service-provider"], CertificateStoreResources.CspOptionDescription);
        internal Option<string?> PrivateKeyContainerOption { get; } = new(["-k", "--key-container"], CertificateStoreResources.KeyContainerOptionDescription);
        internal Option<bool> UseMachineKeyContainerOption { get; } = new(["-km", "--use-machine-key-container"], getDefaultValue: () => false, description: CertificateStoreResources.UseMachineKeyContainerOptionDescription);

        internal CertificateStoreCommand(CodeCommand codeCommand, IServiceProviderFactory serviceProviderFactory)
            : base("certificate-store", Resources.CertificateStoreCommandDescription)
        {
            _codeCommandHandler = new CodeCommandHandler(codeCommand, serviceProviderFactory);

            Sha1ThumbprintOption.IsRequired = true;

            AddOption(Sha1ThumbprintOption);
            AddOption(CertificateFileOption);
            AddOption(CertificatePasswordOption);
            AddOption(CryptoServiceProviderOption);
            AddOption(PrivateKeyContainerOption);
            AddOption(UseMachineKeyContainerOption);

            AddArgument(codeCommand.FileArgument);

            this.SetHandler(async (InvocationContext context) =>
            {
                string? sha1Thumbprint = context.ParseResult.GetValueForOption(Sha1ThumbprintOption);
                string? certificatePath = context.ParseResult.GetValueForOption(CertificateFileOption);
                string? certificatePassword = context.ParseResult.GetValueForOption(CertificatePasswordOption);
                string? cryptoServiceProvider = context.ParseResult.GetValueForOption(CryptoServiceProviderOption);
                string? privateKeyContainer = context.ParseResult.GetValueForOption(PrivateKeyContainerOption);
                bool useMachineKeyContainer = context.ParseResult.GetValueForOption(UseMachineKeyContainerOption);

                // SHA-1 Thumbprint is required in case the provided certificate container contains multiple certificates.
                if (string.IsNullOrEmpty(sha1Thumbprint))
                {
                    context.Console.Error.WriteFormattedLine(
                        Resources.InvalidSha1ThumbprintValue, 
                        Sha1ThumbprintOption);
                    context.ExitCode = ExitCode.NoInputsFound;
                    return;
                }

                // CSP requires a private key container to function.
                if (string.IsNullOrEmpty(cryptoServiceProvider) != string.IsNullOrEmpty(privateKeyContainer))
                {
                    if (string.IsNullOrEmpty(privateKeyContainer))
                    {
                        context.Console.Error.WriteLine(CertificateStoreResources.MissingPrivateKeyContainerError);
                        context.ExitCode = ExitCode.InvalidOptions;
                        return;
                    }
                    else
                    {
                        context.Console.Error.WriteLine(CertificateStoreResources.MissingCspError);
                        context.ExitCode = ExitCode.InvalidOptions;
                        return;
                    }
                }

                CertificateStoreServiceProvider certificateStoreServiceProvider = new(
                    sha1Thumbprint,
                    cryptoServiceProvider,
                    privateKeyContainer,
                    certificatePath,
                    certificatePassword,
                    useMachineKeyContainer);

                await _codeCommandHandler.Handle(context, certificateStoreServiceProvider);
            });
        }
    }
}