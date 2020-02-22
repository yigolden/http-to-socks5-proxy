using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Pipelines.Sockets.Unofficial;

namespace HttpToSocks5Proxy
{
    internal class Socks5TunnelFactory : ITunnelFactory
    {
        private readonly EndPoint _endPoint;
        private readonly bool _fastMode;

        private byte[]? _authenticationPacket;

        private static readonly IdnMapping s_idnMapping = new IdnMapping();

        public Socks5TunnelFactory(EndPoint endPoint, bool fastMode = true)
        {
            _endPoint = endPoint;
            _fastMode = fastMode;
        }

        public void SetCredential(string userInfo)
        {
            string username, password;
            string[] parts = userInfo.Split(':');
            if (parts.Length == 1)
            {
                username = userInfo;
                password = string.Empty;
            }
            else if (parts.Length == 2)
            {
                username = parts[0];
                password = parts[1];
            }
            else
            {
                throw new ArgumentException();
            }

            int usernameLength = Encoding.ASCII.GetByteCount(username);
            int passwordLength = Encoding.ASCII.GetByteCount(password);

            if (usernameLength > 255 || passwordLength > 255)
            {
                throw new ArgumentException();
            }

            byte[] packet = new byte[3 + usernameLength + passwordLength];
            packet[0] = 1;
            packet[1] = (byte)usernameLength;
            Encoding.ASCII.GetBytes(username, packet.AsSpan(2));
            packet[usernameLength + 2] = (byte)passwordLength;
            Encoding.ASCII.GetBytes(password, packet.AsSpan(3 + usernameLength));

            _authenticationPacket = packet;
        }

        public Task<IDuplexPipe?> CreateAsync(EndPoint endPoint, CancellationToken cancellationToken)
        {
            if (endPoint is null)
            {
                throw new ArgumentNullException(nameof(endPoint));
            }

            return _fastMode ? CreateFastAsync(endPoint, cancellationToken) : CreateSlowAsync(endPoint, cancellationToken);
        }

        public async Task<IDuplexPipe?> CreateSlowAsync(EndPoint endPoint, CancellationToken cancellationToken)
        {
            byte[]? authenticationPacket = _authenticationPacket;

            SocketConnection? socket = await SocketConnection.ConnectAsync(_endPoint);
            try
            {
                (bool result, bool requireAuthentication) = await NegotiateAsync(socket, !(authenticationPacket is null), cancellationToken).ConfigureAwait(false);
                if (!result)
                {
                    return null;
                }
                if (requireAuthentication)
                {
                    if (authenticationPacket is null)
                    {
                        return null;
                    }

                    if (!await AuthenticateAsync(socket, authenticationPacket, cancellationToken).ConfigureAwait(false))
                    {
                        return null;
                    }
                }

                if (!await ConnectAsync(socket, endPoint, cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                return Interlocked.Exchange(ref socket, null);
            }
            finally
            {
                if (!(socket is null))
                {
                    socket.Dispose();
                }
            }
        }

        public async Task<IDuplexPipe?> CreateFastAsync(EndPoint endPoint, CancellationToken cancellationToken)
        {
            byte[]? authenticationPacket = _authenticationPacket;

            SocketConnection? socket = await SocketConnection.ConnectAsync(_endPoint);
            try
            {
                WriteAllRequests(socket.Output, endPoint, authenticationPacket);
                await socket.Output.FlushAsync(cancellationToken).ConfigureAwait(false);

                if (!await ReceiveAllResponsesAsync(socket.Input, authenticationPacket, cancellationToken))
                {
                    return null;
                }

                return Interlocked.Exchange(ref socket, null);
            }
            finally
            {
                if (!(socket is null))
                {
                    socket.Dispose();
                }
            }
        }

        private static void WriteAllRequests(IBufferWriter<byte> writer, EndPoint endPoint, byte[]? authenticationPacket)
        {
            bool credentialAvailable = !(authenticationPacket is null);

            // Send negotiate request
            WriteNegotiateRequest(writer, credentialAvailable);

            if (!(authenticationPacket is null))
            {
                // Send authentication request
                WriteAuthenticationRequest(writer, authenticationPacket);
            }

            // Send connect request
            WriteConnectRequest(writer, endPoint);
        }

        private async Task<bool> ReceiveAllResponsesAsync(PipeReader reader, byte[]? authenticationPacket, CancellationToken cancellationToken)
        {
            bool credentialAvailable = !(authenticationPacket is null);
            bool requireAuthentication = false;
            OperationStatus status;

            // Receive negotiate response
            status = OperationStatus.NeedMoreData;
            while (status == OperationStatus.NeedMoreData)
            {
                ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (readResult.IsCanceled || readResult.IsCompleted)
                {
                    return false;
                }

                (status, requireAuthentication) = ReadNegotiateResponse(readResult.Buffer, credentialAvailable, out SequencePosition examined, out SequencePosition consumed);
                reader.AdvanceTo(consumed, examined);

                if (status == OperationStatus.InvalidData)
                {
                    return false;
                }
            }

            // Receive authentication response
            if (requireAuthentication)
            {
                status = OperationStatus.NeedMoreData;
                while (status == OperationStatus.NeedMoreData)
                {
                    ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                    if (readResult.IsCanceled || readResult.IsCompleted)
                    {
                        return false;
                    }

                    status = ReadAuthenticationResponse(readResult.Buffer, out SequencePosition examined, out SequencePosition consumed);
                    reader.AdvanceTo(consumed, examined);

                    if (status == OperationStatus.InvalidData)
                    {
                        return false;
                    }
                }
            }

            // Receive connect response
            status = OperationStatus.NeedMoreData;
            while (status == OperationStatus.NeedMoreData)
            {
                ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (readResult.IsCanceled || readResult.IsCompleted)
                {
                    return false;
                }

                status = ReadConnectResponse(readResult.Buffer, out SequencePosition examined, out SequencePosition consumed);
                reader.AdvanceTo(consumed, examined);

                if (status == OperationStatus.InvalidData)
                {
                    return false;
                }
            }

            return true;
        }

        private static async Task<(bool Success, bool RequireAuthentication)> NegotiateAsync(IDuplexPipe pipe, bool credentialAvailable, CancellationToken cancellationToken)
        {
            bool requireAuthentication = false;

            // Send negotiate request
            WriteNegotiateRequest(pipe.Output, credentialAvailable);
            await pipe.Output.FlushAsync(cancellationToken);

            // Receive negotiate response
            PipeReader reader = pipe.Input;
            OperationStatus status = OperationStatus.NeedMoreData;
            while (status == OperationStatus.NeedMoreData)
            {
                ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (readResult.IsCanceled || readResult.IsCompleted)
                {
                    return (Success: false, RequireAuthentication: false);
                }

                (status, requireAuthentication) = ReadNegotiateResponse(readResult.Buffer, credentialAvailable, out SequencePosition examined, out SequencePosition consumed);
                reader.AdvanceTo(consumed, examined);

                if (status == OperationStatus.InvalidData)
                {
                    return (Success: false, RequireAuthentication: requireAuthentication);
                }
            }

            return (Success: true, RequireAuthentication: requireAuthentication);
        }

        private static void WriteNegotiateRequest(IBufferWriter<byte> writer, bool credentialAvailable)
        {
            Span<byte> span = writer.GetSpan(3);
            span[0] = 5;
            span[1] = 1;
            span[2] = credentialAvailable ? (byte)2 : (byte)0;
            writer.Advance(3);
        }

        private static (OperationStatus Status, bool RequireAuthentication) ReadNegotiateResponse(ReadOnlySequence<byte> sequence, bool provideCredential, out SequencePosition examined, out SequencePosition consumed)
        {
            if (sequence.Length < 2)
            {
                examined = sequence.End;
                consumed = sequence.Start;
                return (Status: OperationStatus.NeedMoreData, RequireAuthentication: false);
            }

            ReadOnlySequence<byte> resultSequence = sequence.Slice(0, 2);
            Span<byte> buffer = stackalloc byte[2];
            resultSequence.CopyTo(buffer);

            examined = resultSequence.End;

            if (buffer[0] == 5)
            {
                if (buffer[1] == 0)
                {
                    consumed = resultSequence.End;
                    return (Status: OperationStatus.Done, RequireAuthentication: false);
                }
                else if (buffer[1] == 2)
                {
                    consumed = resultSequence.End;
                    return (Status: OperationStatus.Done, RequireAuthentication: true);
                }
            }

            consumed = sequence.Start;
            return (Status: OperationStatus.InvalidData, RequireAuthentication: false);
        }

        private async Task<bool> AuthenticateAsync(IDuplexPipe pipe, byte[] authenticationPacket, CancellationToken cancellationToken)
        {
            // Send authentication request
            WriteAuthenticationRequest(pipe.Output, authenticationPacket);
            await pipe.Output.FlushAsync(cancellationToken);

            // Receive authentication response
            PipeReader reader = pipe.Input;
            OperationStatus status = OperationStatus.NeedMoreData;
            while (status == OperationStatus.NeedMoreData)
            {
                ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (readResult.IsCanceled || readResult.IsCompleted)
                {
                    return false;
                }

                status = ReadAuthenticationResponse(readResult.Buffer, out SequencePosition examined, out SequencePosition consumed);
                reader.AdvanceTo(consumed, examined);

                if (status == OperationStatus.InvalidData)
                {
                    return false;
                }
            }

            return true;
        }

        private static void WriteAuthenticationRequest(IBufferWriter<byte> writer, byte[] authenticationPacket)
        {
            writer.Write(authenticationPacket);
        }

        private static OperationStatus ReadAuthenticationResponse(ReadOnlySequence<byte> sequence, out SequencePosition examined, out SequencePosition consumed)
        {
            if (sequence.Length < 2)
            {
                examined = sequence.End;
                consumed = sequence.Start;
                return OperationStatus.NeedMoreData;
            }

            sequence = sequence.Slice(0, 2);
            Span<byte> buffer = stackalloc byte[2];
            sequence.CopyTo(buffer);

            consumed = examined = sequence.End;

            if (buffer[0] == 1 && buffer[1] == 0)
            {
                return OperationStatus.Done;
            }

            return OperationStatus.InvalidData;
        }

        private static async Task<bool> ConnectAsync(IDuplexPipe pipe, EndPoint endPoint, CancellationToken cancellationToken)
        {
            // Send connect request
            WriteConnectRequest(pipe.Output, endPoint);
            await pipe.Output.FlushAsync(cancellationToken);

            // Receive connect response
            PipeReader reader = pipe.Input;
            OperationStatus status = OperationStatus.NeedMoreData;
            while (status == OperationStatus.NeedMoreData)
            {
                ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (readResult.IsCanceled || readResult.IsCompleted)
                {
                    return false;
                }

                status = ReadConnectResponse(readResult.Buffer, out SequencePosition examined, out SequencePosition consumed);
                reader.AdvanceTo(consumed, examined);

                if (status == OperationStatus.InvalidData)
                {
                    return false;
                }
            }

            return true;
        }

        private static void WriteConnectRequest(IBufferWriter<byte> writer, EndPoint endPoint)
        {
            IPEndPoint? ipEndPoint = endPoint as IPEndPoint;
            DnsEndPoint? dnsEndPoint = endPoint as DnsEndPoint;
            if (ipEndPoint is null && dnsEndPoint is null)
            {
                throw new InvalidOperationException();
            }

            if (ipEndPoint is null)
            {
                Debug.Assert(!(dnsEndPoint is null));
                string host = s_idnMapping.GetAscii(dnsEndPoint.Host);

                int hostLength = Encoding.ASCII.GetByteCount(host);
                if (hostLength > byte.MaxValue)
                {
                    throw new InvalidOperationException();
                }
                int length = 7 + hostLength;
                Span<byte> span = writer.GetSpan(length);
                span[0] = 5;
                span[1] = 1;
                span[2] = 0;
                span[3] = 3;
                span[4] = (byte)Encoding.ASCII.GetBytes(host, span.Slice(5));
                BinaryPrimitives.WriteUInt16BigEndian(span.Slice(5 + hostLength), (ushort)dnsEndPoint.Port);

                writer.Advance(length);
            }
            else if (ipEndPoint.AddressFamily == AddressFamily.InterNetwork)
            {
                const int length = 10;

                Span<byte> span = writer.GetSpan(length);
                span[0] = 5;
                span[1] = 1;
                span[2] = 0;
                span[3] = 1;
                ipEndPoint.Address.TryWriteBytes(span.Slice(4), out _);
                BinaryPrimitives.WriteUInt16BigEndian(span.Slice(8), (ushort)ipEndPoint.Port);

                writer.Advance(length);
            }
            else if (ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                const int length = 22;

                Span<byte> span = writer.GetSpan(length);
                span[0] = 5;
                span[1] = 1;
                span[2] = 0;
                span[3] = 4;
                ipEndPoint.Address.TryWriteBytes(span.Slice(4), out _);
                BinaryPrimitives.WriteUInt16BigEndian(span.Slice(20), (ushort)ipEndPoint.Port);

                writer.Advance(length);
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        private static OperationStatus ReadConnectResponse(ReadOnlySequence<byte> sequence, out SequencePosition examined, out SequencePosition consumed)
        {
            if (sequence.Length < 4)
            {
                examined = sequence.End;
                consumed = sequence.Start;
                return OperationStatus.NeedMoreData;
            }

            var reader = new SequenceReader<byte>(sequence);
            reader.TryRead(out byte b1);
            reader.TryRead(out byte b2);
            reader.TryRead(out byte b3);
            reader.TryRead(out byte b4);
            examined = reader.Position;
            consumed = sequence.Start;
            if (b1 != 5 || b2 != 0 || b3 != 0)
            {
                return OperationStatus.InvalidData;
            }

            if (b4 == 1)
            {
                // IPv4
                if (reader.Remaining < (4 + 2))
                {
                    examined = sequence.End;
                    return OperationStatus.NeedMoreData;
                }
                reader.Advance(4 + 2);
                consumed = examined = reader.Position;
            }
            else if (b4 == 3)
            {
                // Domain name
                if (!reader.TryRead(out byte len))
                {
                    return OperationStatus.NeedMoreData;
                }
                if (reader.Remaining < (len + 2))
                {
                    examined = sequence.End;
                    return OperationStatus.NeedMoreData;
                }
                reader.Advance(len + 2);
                consumed = examined = reader.Position;
            }
            else if (b4 == 4)
            {
                // IPv6
                if (reader.Remaining < (16 + 2))
                {
                    examined = sequence.End;
                    return OperationStatus.NeedMoreData;
                }
                reader.Advance(16 + 2);
                consumed = examined = reader.Position;
            }

            return OperationStatus.Done;
        }

    }
}
