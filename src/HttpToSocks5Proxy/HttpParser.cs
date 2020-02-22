using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HttpToSocks5Proxy
{
    internal class HttpParser : IDisposable
    {
        private readonly Stream _stream;

        private HttpMethod? _httpMethod;
        private string? _url;
        private readonly List<KeyValuePair<string, string>> _headers;

        private string? _proxyAuthorization;

        private const int PrimaryBufferSize = 4096;
        private const int SecondaryBufferSize = 16384;
        private const int MaximumHeaderAreaSize = 81920;

        private byte[]? _primaryBuffer;
        private byte[]? _secondaryBuffer;

        public Memory<byte> RemainingBytes { get; set; }

        public HttpMethod Method => _httpMethod ?? throw new InvalidOperationException();

        public string Url => _url ?? throw new InvalidOperationException();

        public IList<KeyValuePair<string, string>> Headers => _headers;

        public string? ProxyAuthorization => _proxyAuthorization;

        private static ReadOnlySpan<byte> s_httpVersionString => new byte[] { (byte)'H', (byte)'T', (byte)'T', (byte)'P', (byte)'/', (byte)'1', (byte)'.', (byte)'1' };

        public HttpParser(Stream stream)
        {
            _stream = stream;
            _headers = new List<KeyValuePair<string, string>>();
            _primaryBuffer = ArrayPool<byte>.Shared.Rent(PrimaryBufferSize);
        }

        private byte[] AllocateSecondaryBuffer()
        {
            if (_secondaryBuffer is null)
            {
                return _secondaryBuffer = ArrayPool<byte>.Shared.Rent(SecondaryBufferSize);
            }
            return _secondaryBuffer;
        }

        public async Task<bool> ParseAsync(CancellationToken cancellationToken)
        {
            byte[]? buffer = _primaryBuffer;
            if (buffer is null)
            {
                throw new ObjectDisposedException(nameof(HttpParser));
            }

            Stream stream = _stream;
            int bytesRead = 0;
            int readSize;

            // Parse request line
            while (true)
            {
                if (bytesRead == buffer.Length)
                {
                    return false;
                }

                // Read from network
                readSize = await stream.ReadAsync(buffer, bytesRead, buffer.Length - bytesRead).ConfigureAwait(false);
                if (readSize == 0)
                {
                    throw new IOException();
                }

                // Parse content
                OperationStatus status;
                int bytesConsumed = 0;
                try
                {
                    status = ParseRequestLine(buffer, 0, bytesRead + readSize, out bytesConsumed);
                }
                catch (Exception)
                {
                    return false;
                }

                // Shift content in the buffer
                bytesRead = bytesRead + readSize - bytesConsumed;
                Array.Copy(buffer, bytesConsumed, buffer, 0, bytesRead);

                if (status == OperationStatus.Done)
                {
                    break;
                }
                else if (status == OperationStatus.InvalidData)
                {
                    return false;
                }
            }

            // Parse headers
            bool firstRead = true;
            bool isSeconaryBufferInUse = false;
            int totalHeaderAreaSize = 0;
            readSize = 0;
            while (true)
            {
                if (bytesRead == buffer.Length)
                {
                    if (isSeconaryBufferInUse)
                    {
                        return false;
                    }
                    byte[] bigBuffer = AllocateSecondaryBuffer();
                    Array.Copy(buffer, bigBuffer, bytesRead);
                    buffer = bigBuffer;
                    isSeconaryBufferInUse = true;
                }

                // Read from network
                if (!firstRead || bytesRead == 0)
                {
                    readSize = await stream.ReadAsync(buffer, bytesRead, buffer.Length - bytesRead).ConfigureAwait(false);
                    if (readSize == 0)
                    {
                        throw new IOException();
                    }
                }
                firstRead = false;

                // Parse content
                OperationStatus status = OperationStatus.DestinationTooSmall;
                int totalBytesConsumed = 0;
                while (status == OperationStatus.DestinationTooSmall)
                {
                    int bytesConsumed = 0;
                    try
                    {
                        status = ParseHeader(buffer, totalBytesConsumed, bytesRead + readSize - totalBytesConsumed, out bytesConsumed);
                    }
                    catch (Exception)
                    {
                        return false;
                    }
                    totalBytesConsumed += bytesConsumed;
                }

                // Shift content in the buffer
                bytesRead = bytesRead + readSize - totalBytesConsumed;
                Array.Copy(buffer, totalBytesConsumed, buffer, 0, bytesRead);

                if (status == OperationStatus.Done)
                {
                    break;
                }
                else if (status == OperationStatus.InvalidData)
                {
                    return false;
                }

                // Restrict maximum header size
                totalHeaderAreaSize += totalBytesConsumed;
                if (totalHeaderAreaSize >= MaximumHeaderAreaSize)
                {
                    return false;
                }
            }

            RemainingBytes = buffer.AsMemory(0, bytesRead);
            return true;
        }

        private OperationStatus ParseRequestLine(byte[] buffer, int offset, int readSize, out int bytesConsumed)
        {
            ReadOnlySpan<byte> requestLine = buffer.AsSpan(offset, readSize);
            bytesConsumed = 0;
            int pos;

            if (_httpMethod is null)
            {
                pos = requestLine.IndexOf((byte)' ');
                if (pos < 0)
                {
                    return OperationStatus.NeedMoreData;
                }

                _httpMethod = new HttpMethod(Encoding.ASCII.GetString(requestLine.Slice(0, pos)));
                bytesConsumed += pos + 1;
                requestLine = requestLine.Slice(pos + 1);
            }

            if (_url is null)
            {
                pos = requestLine.IndexOf((byte)' ');
                if (pos < 0)
                {
                    return OperationStatus.NeedMoreData;
                }

                _url = Encoding.ASCII.GetString(requestLine.Slice(0, pos));
                bytesConsumed += pos + 1;
                requestLine = requestLine.Slice(pos + 1);
            }

            pos = requestLine.IndexOf((byte)'\n');
            if (pos < 0)
            {
                return OperationStatus.NeedMoreData;
            }
            if (pos == 0)
            {
                return OperationStatus.InvalidData;
            }

            requestLine = requestLine.Slice(0, pos);
            if (requestLine[requestLine.Length - 1] == (byte)'\r')
            {
                requestLine = requestLine.Slice(0, requestLine.Length - 1);
            }

            if (!requestLine.SequenceEqual(s_httpVersionString))
            {
                return OperationStatus.InvalidData;
            }

            bytesConsumed += pos + 1;
            return OperationStatus.Done;
        }

        private OperationStatus ParseHeader(byte[] buffer, int offset, int readSize, out int bytesConsumed)
        {
            ReadOnlySpan<byte> content = buffer.AsSpan(offset, readSize);
            bytesConsumed = 0;

            int pos = content.IndexOf((byte)'\n');
            if (pos < 0)
            {
                return OperationStatus.NeedMoreData;
            }

            content = content.Slice(0, pos);
            if (!content.IsEmpty && content[content.Length - 1] == (byte)'\r')
            {
                content = content.Slice(0, content.Length - 1);
            }

            bytesConsumed = pos + 1;
            if (content.IsEmpty)
            {
                return OperationStatus.Done;
            }
            if (content.Contains((byte)'\r'))
            {
                return OperationStatus.InvalidData;
            }

            pos = content.IndexOf((byte)':');
            if (pos <= 0)
            {
                return OperationStatus.InvalidData;
            }

            ReadOnlySpan<byte> key = content.Slice(0, pos).Trim((byte)' ');
            ReadOnlySpan<byte> value = content.Slice(pos + 1).Trim((byte)' ');

            if (key.IsEmpty)
            {
                return OperationStatus.InvalidData;
            }

            // Special case for proxy-related headers
            string keyString = Encoding.ASCII.GetString(key);
            if (keyString.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase))
            {
                if (keyString.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase))
                {
                    _proxyAuthorization = Encoding.ASCII.GetString(value);
                };
            }
            else
            {
                _headers.Add(KeyValuePair.Create(keyString, Encoding.ASCII.GetString(value)));
            }

            return OperationStatus.DestinationTooSmall;
        }

        public void Dispose()
        {
            if (!(_primaryBuffer is null))
            {
                ArrayPool<byte>.Shared.Return(_primaryBuffer);
                _primaryBuffer = null;
            }
            if (!(_secondaryBuffer is null))
            {
                ArrayPool<byte>.Shared.Return(_secondaryBuffer);
                _secondaryBuffer = null;
            }
        }
    }
}
