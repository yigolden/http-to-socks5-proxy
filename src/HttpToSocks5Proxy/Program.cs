using System;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Globalization;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Pipelines.Sockets.Unofficial;

namespace HttpToSocks5Proxy
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var builder = new CommandLineBuilder();

            SetupRootCommand(builder.Command);

            builder.UseVersionOption();

            builder.UseHelp();
            builder.UseSuggestDirective();
            builder.RegisterWithDotnetSuggest();
            builder.UseParseErrorReporting();
            builder.UseExceptionHandler();

            Parser parser = builder.Build();
            await parser.InvokeAsync(args);
        }

        static void SetupRootCommand(Command command)
        {
            command.Description = "Forward HTTP proxy requests to SOCKS5 proxy.";

            command.AddOption(
                new Option(new string[] { "--inbound", "--in" }, "Inbound HTTP endpoint.")
                {
                    Argument = new Argument<string>() { Arity = ArgumentArity.ExactlyOne }
                });

            command.AddOption(
                new Option(new string[] { "--outbound", "--out" }, "SOCKS5 server endpoint.")
                {
                    Argument = new Argument<string>() { Arity = ArgumentArity.ExactlyOne }
                });

            command.AddOption(
                new Option(new string[] { "--backlog" }, "The maximum length of the pending connections queue.")
                {
                    Argument = new Argument<int>(() => Environment.ProcessorCount * 8) { Arity = ArgumentArity.ExactlyOne, IsHidden = true }
                });

            command.Handler = CommandHandler.Create<string, string, int, CancellationToken>(ForwardAction.Run);
        }
    }
}
