using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HttpToSocks5Proxy
{
    internal class HttpProxyListener
    {
        private readonly IPEndPoint _endPoint;
        private readonly int _backlog;
        private readonly ITunnelFactory _tunnelFactory;

        private string? _authorization;

        public HttpProxyListener(IPEndPoint endPoint, int backlog, ITunnelFactory tunnelFactory)
        {
            _endPoint = endPoint ?? throw new ArgumentNullException(nameof(endPoint));
            _backlog = backlog;
            _tunnelFactory = tunnelFactory ?? throw new ArgumentNullException(nameof(tunnelFactory));
        }

        public void SetCredential(string userInfo)
        {
            if (userInfo is null)
            {
                throw new ArgumentNullException(nameof(userInfo));
            }

            int length = Encoding.ASCII.GetByteCount(userInfo);
            Span<byte> buffer = length <= 64 ? stackalloc byte[64] : new byte[length];
            Encoding.ASCII.GetBytes(userInfo, buffer);
            _authorization = Convert.ToBase64String(buffer.Slice(0, length));
        }

        public void SetCredential(string username, string password)
        {
            if (username is null)
            {
                throw new ArgumentNullException(nameof(username));
            }
            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            int length = Encoding.ASCII.GetByteCount(username) + 1 + Encoding.ASCII.GetByteCount(password);
            Span<byte> buffer = length <= 64 ? stackalloc byte[64] : new byte[length];
            Span<byte> buffer2 = buffer.Slice(Encoding.ASCII.GetBytes(username, buffer));
            buffer2[0] = (byte)':';
            Encoding.ASCII.GetBytes(password, buffer2.Slice(1));
            _authorization = Convert.ToBase64String(buffer.Slice(0, length));
        }

        public async Task RunAsync(CancellationToken cancellationToken = default)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            if (_endPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = true;
            }
            socket.Bind(_endPoint);
            socket.Listen(_backlog);
            using (cancellationToken.UnsafeRegister(s => { ((IDisposable)s!).Dispose(); }, socket))
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    Socket incoming = await socket.AcceptAsync();
                    _ = Task.Run(() => ProcessSocketAsync(incoming, cancellationToken));
                }

            }
        }

        private async Task ProcessSocketAsync(Socket socket, CancellationToken cancellationToken)
        {
            using (var ns = new NetworkStream(socket, ownsSocket: true))
            {
                var processor = new HttpProxyProcessor(_tunnelFactory, ns);
                if (!(_authorization is null))
                {
                    processor.SetCredential(_authorization);
                }
                try
                {
                    await processor.RunAsync(cancellationToken);
                }
                catch (Exception)
                {
                    // Ignore
                }

            }
        }
    }
}
