using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace HttpToSocks5Proxy
{
    internal static class ForwardAction
    {
        public static async Task<int> Run(string inbound, string outbound, int backlog, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(inbound))
            {
                Console.WriteLine("Inbound HTTP endpoint is not specified.");
                return 1;
            }
            if (string.IsNullOrEmpty(outbound))
            {
                Console.WriteLine("SOCKS5 server endpoint is not specified");
                return 1;
            }
            if (backlog <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(backlog));
            }
            if (!Uri.TryCreate(inbound, UriKind.Absolute, out Uri? inboundUri))
            {
                Console.WriteLine(inbound + " is not a valid URI.");
                return 1;
            }
            if (!Uri.TryCreate(outbound, UriKind.Absolute, out Uri? outboundUri))
            {
                Console.WriteLine(outbound + " is not a valid URI.");
                return 1;
            }

            if (!inboundUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Inbound endpoint only supports HTTP protocol.");
                return 1;
            }
            if (!inboundUri.PathAndQuery.Equals("/") || !string.IsNullOrEmpty(inboundUri.Fragment))
            {
                Console.WriteLine("Incorrect inbound endpoint is specified.");
                return 1;
            }
            if (!outboundUri.Scheme.Equals("socks5", StringComparison.OrdinalIgnoreCase) && !outboundUri.Scheme.Equals("debug", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Outbound endpoint only supports SOCKS5 protocol.");
                return 1;
            }
            if (!outboundUri.PathAndQuery.Equals("/") || !string.IsNullOrEmpty(outboundUri.Fragment))
            {
                Console.WriteLine("Incorrect outbound endpoint is specified.");
                return 1;
            }

            // Parse endpoints
            IPEndPoint inboundEP;
            if (IPAddress.TryParse(inboundUri.Host, out IPAddress ip))
            {
                inboundEP = new IPEndPoint(ip, inboundUri.Port);
            }
            else if (inboundUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            {
                inboundEP = new IPEndPoint(IPAddress.IPv6Loopback, inboundUri.Port);
            }
            else
            {
                Console.WriteLine("Invalid IP adress is specified in the inbound endpoint.");
                return 1;
            }

            // Create outbound tunnel factory
            ITunnelFactory tunnelFactory;
            if (outboundUri.Scheme.Equals("socks5", StringComparison.OrdinalIgnoreCase))
            {
                if (IPAddress.TryParse(outboundUri.Host, out IPAddress ip2))
                {
                    var outboundEP = new IPEndPoint(ip2, outboundUri.Port);
                    tunnelFactory = new Socks5TunnelFactory(outboundEP);
                }
                else
                {
                    var outboundEP = new DnsEndPoint(outboundUri.Host, outboundUri.Port);
                    tunnelFactory = new Socks5TunnelFactory(outboundEP);
                }
                if (!string.IsNullOrEmpty(outboundUri.UserInfo))
                {
                    ((Socks5TunnelFactory)tunnelFactory).SetCredential(outboundUri.UserInfo);
                }
            }
            else
            {
                if (!outboundUri.Scheme.Equals("debug", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException();
                }
                if (outboundUri.Authority.Equals("direct", StringComparison.OrdinalIgnoreCase))
                {
                    tunnelFactory = new DirectTunnelFactory();
                }
                else
                {
                    Console.WriteLine("Unknown debug type.");
                    return 1;
                }
            }


            // Start accepting inbound connections
            var listener = new HttpProxyListener(inboundEP, backlog, tunnelFactory);
            if (!string.IsNullOrEmpty(inboundUri.UserInfo))
            {
                listener.SetCredential(inboundUri.UserInfo);
            }
            try
            {
                await listener.RunAsync(cancellationToken);
            }
            catch (Exception)
            {
                // Do nothing
            }

            return 0;
        }
    }
}
