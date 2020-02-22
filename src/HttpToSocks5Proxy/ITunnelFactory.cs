using System.IO.Pipelines;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace HttpToSocks5Proxy
{
    internal interface ITunnelFactory
    {
        Task<IDuplexPipe?> CreateAsync(EndPoint endPoint, CancellationToken cancellationToken);
    }
}
