using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HttpToSocks5Proxy
{
    internal class HttpResponseParser
    {
        private readonly PipeReader _reader;

        private HttpStatusCode _statusCode;
        private string? _message;


        public HttpResponseParser(PipeReader reader)
        {
            _reader = reader;
        }

        public async Task<bool> ParseAsync(CancellationToken cancellationToken)
        {
            await Task.Yield();
            throw new NotImplementedException();
        }

        private async Task<bool> ParseResponseStatusLineAsync(CancellationToken cancellationToken)
        {
            ReadOnlySequence<byte> statusLine;
            while (true)
            {
                ReadResult result = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                statusLine = result.Buffer;

                SequencePosition? eolPosition = statusLine.PositionOf((byte)'\n');

                if (eolPosition is null)
                {
                    if (result.IsCompleted || result.IsCanceled)
                    {
                        return false;
                    }
                    if (statusLine.Length > 4096)
                    {
                        return false;
                    }
                    _reader.AdvanceTo(statusLine.Start, statusLine.End);
                }
                else
                {
                    statusLine = statusLine.Slice(0, eolPosition.GetValueOrDefault());
                    break;
                }
            }

            // statusLine: HTTP/1.1 200 Connection Established\r
            SequencePosition? position = statusLine.PositionOf((byte)' ');
            if (position is null)
            {
                return false;
            }

            // part: HTTP/1.1
            ReadOnlySequence<byte> part = statusLine.Slice(0, position.GetValueOrDefault());
            if (!ParseHttpVersion(ref part))
            {
                return false;
            }

            // statusLine: 200 Connection Established\r
            statusLine = statusLine.Slice(position.GetValueOrDefault()).Slice(1);
            position = statusLine.PositionOf((byte)' ');
            if (position is null)
            {
                return false;
            }

            // part: 200
            part = statusLine.Slice(0, position.GetValueOrDefault());
            if (!ParseStatusCode(ref part))
            {
                return false;
            }

            // statusLine: Connection Established\r
            statusLine = statusLine.Slice(position.GetValueOrDefault()).Slice(1);
            if (!ParseStatusMessage(statusLine))
            {
                return false;
            }

            _reader.AdvanceTo(statusLine.End); // position ??
            return true;
        }

        private bool ParseHttpVersion(ref ReadOnlySequence<byte> sequence)
        {
            if (sequence.Length != 8)
            {
                return false;
            }

            Span<byte> buffer = stackalloc byte[8];
            sequence.CopyTo(buffer);

            const ulong HttpVersion = 'H' | ((ulong)'T' << 8) | ((ulong)'T' << 16) | ((ulong)'P' << 24) | ((ulong)'/' << 32) | ((ulong)'1' << 40) | ((ulong)'.' << 48) | ((ulong)'1' << 56);

            if (BinaryPrimitives.ReadUInt64LittleEndian(buffer) != HttpVersion)
            {
                return false;
            }

            return true;
        }

        private bool ParseStatusCode(ref ReadOnlySequence<byte> sequence)
        {
            if (sequence.Length != 3)
            {
                return false;
            }

            Span<byte> buffer = stackalloc byte[3];
            sequence.CopyTo(buffer);

            if (!Utf8Parser.TryParse(buffer, out int statusCode, out _))
            {
                return false;
            }

            _statusCode = (HttpStatusCode)statusCode;
            return true;
        }

        private bool ParseStatusMessage(ReadOnlySequence<byte> sequence)
        {
            if (sequence.IsEmpty)
            {
                return false;
            }

            if (sequence.Slice(sequence.Length - 1).FirstSpan[0] == (byte)'r')
            {
                sequence = sequence.Slice(0, sequence.Length - 1);
            }

            if (sequence.IsEmpty)
            {
                return false;
            }

            if (_statusCode != HttpStatusCode.OK)
            {
                if (!ParseUtf8(ref sequence, sizeLimit: 512, out string? value))
                {
                    return false;
                }

                _message = value;
            }

            return true;
        }

        static bool ParseUtf8(ref ReadOnlySequence<byte> seq, int sizeLimit, [NotNullWhen(true)] out string? value)
        {
            if (seq.Length > sizeLimit)
            {
                value = null;
                return false;
            }

            int length = (int)seq.Length;

            Span<byte> stackBuffer = stackalloc byte[64];
            byte[]? rentedArray = null;
            if (seq.Length > 64)
            {
                rentedArray = ArrayPool<byte>.Shared.Rent(length);
                stackBuffer = rentedArray;
            }

            try
            {
                seq.CopyTo(stackBuffer);
                value = Encoding.UTF8.GetString(stackBuffer.Slice(0, length));
            }
            catch
            {
                value = null;
                return false;
            }
            finally
            {
                if (!(rentedArray is null))
                {
                    ArrayPool<byte>.Shared.Return(rentedArray);
                }
            }

            return true;
        }
    }
}
