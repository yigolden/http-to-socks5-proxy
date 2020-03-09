using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HttpToSocks5Proxy
{
    internal class HttpProxyProcessor
    {
        private readonly ITunnelFactory _tunnelFactory;
        private readonly Stream _inboundStream;

        private string? _authorization;

        private static readonly HttpMethod s_connectMethod = new HttpMethod("CONNECT");

        public HttpProxyProcessor(ITunnelFactory tunnelFactory, Stream inboundStream)
        {
            _tunnelFactory = tunnelFactory;
            _inboundStream = inboundStream;
        }

        public void SetCredential(string authorization)
        {
            _authorization = authorization;
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            Stream stream = _inboundStream;
            IDuplexPipe? tunnel = null;
            try
            {
                using (var parser = new HttpParser(stream))
                {
                    // Parse HTTP header
                    if (!(await parser.ParseAsync(cancellationToken).ConfigureAwait(false)))
                    {
                        await WriteBadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
                        return;
                    }

                    // Authenticate
                    if (!Authenticate(parser.ProxyAuthorization))
                    {
                        if (parser.ProxyAuthorization is null)
                        {
                            await WriteProxyAuthenticationAsync(stream, cancellationToken).ConfigureAwait(false);
                            return;
                        }

                        await WriteForbiddenAsync(stream, cancellationToken).ConfigureAwait(false);
                        return;
                    }

                    // Process CONNECT requests
                    if (parser.Method.Equals(s_connectMethod))
                    {
                        if (!TryParseConnectEndpoint(parser.Url, out EndPoint? endPoint))
                        {
                            await WriteBadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
                            return;
                        }

                        try
                        {
                            tunnel = await _tunnelFactory.CreateAsync(endPoint, cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception)
                        {
                            tunnel = null;
                        }
                        if (tunnel is null)
                        {
                            await WriteServerFailureAsync(stream, cancellationToken).ConfigureAwait(false);
                            return;
                        }


                        await WriteOkStatusAsync(stream, cancellationToken).ConfigureAwait(false);
                        await SendInitialRequestForConnectAsync(parser, tunnel.Output, cancellationToken).ConfigureAwait(false);
                    }

                    // Process other requests
                    else
                    {
                        if (!Uri.TryCreate(parser.Url, UriKind.Absolute, out Uri? uri) || !uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
                        {
                            await WriteBadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
                            return;
                        }

                        EndPoint endPoint;
                        if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
                        {
                            if (!IPAddress.TryParse(uri.Host, out IPAddress ip))
                            {
                                await WriteBadRequestAsync(stream, cancellationToken).ConfigureAwait(false);
                                return;
                            }

                            endPoint = new IPEndPoint(ip, uri.Port);
                        }
                        else
                        {
                            endPoint = new DnsEndPoint(uri.DnsSafeHost, uri.Port);
                        }

                        try
                        {
                            tunnel = await _tunnelFactory.CreateAsync(endPoint, cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception)
                        {
                            tunnel = null;
                        }
                        if (tunnel is null)
                        {
                            await WriteServerFailureAsync(stream, cancellationToken).ConfigureAwait(false);
                            return;
                        }

                        await SendInitialRequestForHttpAsync(parser, uri, tunnel.Output, cancellationToken).ConfigureAwait(false);
                    }
                }

                await PumpDataAsync(stream, tunnel, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (!(tunnel is null) && tunnel is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
        }

        private static byte[] s_okResponse = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\n\n");
        private static byte[] s_badRequest = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\nConnection: close\n\n");
        private static byte[] s_forbidden = Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\nConnection: close\n\n");
        private static byte[] s_authenticationRequired = Encoding.ASCII.GetBytes("HTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: Basic realm=\"proxy\"\n\n");
        private static byte[] s_serverFailure = Encoding.ASCII.GetBytes("HTTP/1.1 500 Proxy Failure\nConnection: close\n\n");

        private async Task WriteOkStatusAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] response = s_okResponse;
            await stream.WriteAsync(response, 0, response.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        private async Task WriteBadRequestAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] response = s_badRequest;
            await stream.WriteAsync(response, 0, response.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        private async Task WriteForbiddenAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] response = s_forbidden;
            await stream.WriteAsync(response, 0, response.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        private async Task WriteProxyAuthenticationAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] response = s_authenticationRequired;
            await stream.WriteAsync(response, 0, response.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        private async Task WriteServerFailureAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] response = s_serverFailure;
            await stream.WriteAsync(response, 0, response.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        private bool Authenticate(string? proxyAuthentxation)
        {
            if (_authorization is null)
            {
                return true;
            }
            if (proxyAuthentxation is null)
            {
                return false;
            }
            ReadOnlySpan<char> header = proxyAuthentxation.AsSpan().Trim();
            if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            header = header.Slice(6).Trim();
            return header.SequenceEqual(_authorization);
        }

        private static bool TryParseConnectEndpoint(string url, [NotNullWhen(true)] out EndPoint? endPoint)
        {
            if (string.IsNullOrEmpty(url))
            {
                endPoint = null;
                return false;
            }

            int pos = url.LastIndexOf(':');
            if (pos <= 0)
            {
                endPoint = null;
                return false;
            }

            if (!ushort.TryParse(url.AsSpan(pos + 1), out ushort port))
            {
                endPoint = null;
                return false;
            }

            if (IPAddress.TryParse(url.AsSpan(0, pos), out IPAddress ip))
            {
                endPoint = new IPEndPoint(ip, port);
                return true;
            }

            endPoint = new DnsEndPoint(url.Substring(0, pos), port);
            return true;
        }

        private static async Task SendInitialRequestForHttpAsync(HttpParser parser, Uri uri, PipeWriter pipeWriter, CancellationToken cancellationToken)
        {
            // Send request line
            WriteRequestLine(pipeWriter, parser.Method.ToString(), uri);

            // Send headers
            foreach ((string key, string value) in parser.Headers)
            {
                WriteHeader(pipeWriter, key, value);
            }

            // Send end of header
            pipeWriter.GetMemory(1).Span[0] = (byte)'\n';
            pipeWriter.Advance(1);

            // Send remaining data
            Memory<byte> remainingBytes = parser.RemainingBytes;
            if (!remainingBytes.IsEmpty)
            {
                remainingBytes.CopyTo(pipeWriter.GetMemory(remainingBytes.Length));
                pipeWriter.Advance(remainingBytes.Length);
            }

            await pipeWriter.FlushAsync(cancellationToken).ConfigureAwait(false);

            static void WriteRequestLine(IBufferWriter<byte> writer, string method, Uri uri)
            {
                string pathAndQuery = uri.PathAndQuery;
                int length = Encoding.ASCII.GetByteCount(method) + Encoding.ASCII.GetByteCount(pathAndQuery) + 11;
                Span<byte> span = writer.GetSpan(length);

                int len = Encoding.ASCII.GetBytes(method, span);
                span = span.Slice(len);
                span[0] = (byte)' ';
                len = Encoding.ASCII.GetBytes(pathAndQuery, span.Slice(1));
                span = span.Slice(len + 1);
                span[0] = (byte)' ';
                span[1] = (byte)'H';
                span[2] = (byte)'T';
                span[3] = (byte)'T';
                span[4] = (byte)'P';
                span[5] = (byte)'/';
                span[6] = (byte)'1';
                span[7] = (byte)'.';
                span[8] = (byte)'1';
                span[9] = (byte)'\n';

                writer.Advance(length);
            }

            static void WriteHeader(IBufferWriter<byte> writer, string key, string value)
            {
                int length = Encoding.ASCII.GetByteCount(key) + Encoding.ASCII.GetByteCount(value) + 3;
                Span<byte> span = writer.GetSpan(length);

                int len = Encoding.ASCII.GetBytes(key, span);
                span = span.Slice(len);
                span[0] = (byte)':';
                span[1] = (byte)' ';
                len = Encoding.ASCII.GetBytes(value, span.Slice(2));
                span = span.Slice(len + 2);
                span[0] = (byte)'\n';

                writer.Advance(length);
            }
        }

        private static async Task SendInitialRequestForConnectAsync(HttpParser parser, PipeWriter pipeWriter, CancellationToken cancellationToken)
        {
            Memory<byte> remainingBytes = parser.RemainingBytes;
            if (!remainingBytes.IsEmpty)
            {
                remainingBytes.CopyTo(pipeWriter.GetMemory(remainingBytes.Length));
                pipeWriter.Advance(remainingBytes.Length);
                await pipeWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        private const int BufferSize = 4096;

        private static async Task PumpDataAsync(Stream stream, IDuplexPipe pipe, CancellationToken cancellationToken)
        {
            CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, default);

            var streamToPipeTask = Task.Run(() => PumpDataFromStreamToPipe(stream, pipe, cts.Token));
            var pipeToStreamTask = Task.Run(() => PumpDataFromPipeToStream(pipe, stream, cts.Token));

            Task completedTask = await Task.WhenAny(streamToPipeTask, pipeToStreamTask).ConfigureAwait(false);
            Task otherTask = ReferenceEquals(completedTask, streamToPipeTask) ? pipeToStreamTask : streamToPipeTask;

            await Task.WhenAny(otherTask, Task.Delay(2000)).ConfigureAwait(false);
            cts.Cancel();

            static async Task PumpDataFromStreamToPipe(Stream stream, IDuplexPipe pipe, CancellationToken cancellationToken)
            {
                PipeWriter writer = pipe.Output;
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        Memory<byte> memory = writer.GetMemory(BufferSize);
                        int readSize = await stream.ReadAsync(memory, cancellationToken).ConfigureAwait(false);
                        if (readSize == 0)
                        {
                            await writer.CompleteAsync().ConfigureAwait(false);
                            pipe.Input.CancelPendingRead();
                            return;
                        }
                        writer.Advance(readSize);
                        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                    }
                }
                catch
                {
                    pipe.Input.CancelPendingRead();
                }
            }

            static async Task PumpDataFromPipeToStream(IDuplexPipe pipe, Stream stream, CancellationToken cancellationToken)
            {
                PipeReader reader = pipe.Input;
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                        if (readResult.IsCompleted || readResult.IsCanceled)
                        {
                            pipe.Output.CancelPendingFlush();
                            return;
                        }
                        foreach (ReadOnlyMemory<byte> buffer in readResult.Buffer)
                        {
                            await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                        }
                        reader.AdvanceTo(readResult.Buffer.End);
                    }
                }
                catch
                {
                    pipe.Output.CancelPendingFlush();
                }
            }
        }
    }
}
