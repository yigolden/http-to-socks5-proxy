using System;
using System.IO.Pipelines;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Pipelines.Sockets.Unofficial;

namespace HttpToSocks5Proxy
{
    internal class DirectTunnelFactory : ITunnelFactory
    {
        public async Task<IDuplexPipe?> CreateAsync(EndPoint endPoint, CancellationToken cancellationToken)
        {
            if (endPoint is null)
            {
                throw new ArgumentNullException(nameof(endPoint));
            }

            return await SocketConnection.ConnectAsync(endPoint).ConfigureAwait(false);
        }
    }
}
