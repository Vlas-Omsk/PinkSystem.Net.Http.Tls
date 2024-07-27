using BotsCommon.Net.Http.Handlers;
using BotsCommon.Net.Http.Sockets;
using CommunityToolkit.HighPerformance;
using Org.BouncyCastle.Tls;
using System;
using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BotsCommon.Net.Http.Tls.Handlers
{
    public sealed class Ja3TlsHttpRequestHandler : IHttpRequestHandler
    {
        private readonly HttpClient _httpClient;
        private readonly Ja3Fingerprint _fingerprint;
        private readonly ISocketsProvider _socketsProvider;
        private readonly TimeSpan _timeout;

        private sealed class TlsProtocolStream : SslStream
        {
            private readonly Stream _networkStream;
            private readonly Ja3TlsClient _tlsClient;
            private readonly TlsClientProtocol _protocol;
            private readonly byte[] _readBuffer = new byte[8192];
            private readonly byte[] _writeBuffer = new byte[8192];
            private bool _isAuthenticated = false;

            public TlsProtocolStream(Stream networkStream, Ja3TlsClient tlsClient) : base(new MemoryStream(0))
            {
                _networkStream = networkStream;
                _tlsClient = tlsClient;
                _protocol = new TlsClientProtocol();
            }

            public override bool CanRead { get; } = true;
            public override bool CanSeek { get; } = false;
            public override bool CanWrite { get; } = true;
            public override long Length => _networkStream.Length;
            public override long Position { get => _networkStream.Position; set => _networkStream.Position = value; }

            public override int ReadTimeout { get => _networkStream.ReadTimeout; set => _networkStream.ReadTimeout = value; }
            public override int WriteTimeout { get => _networkStream.WriteTimeout; set => _networkStream.WriteTimeout = value; }
            public override bool IsAuthenticated => _isAuthenticated;

            public async Task ConnectAsync(CancellationToken cancellationToken)
            {
                _protocol.Connect(_tlsClient);

                while (true)
                {
                    if (_tlsClient.HandshakeCompleted)
                        break;

                    await FlushWriteAsync(cancellationToken);

                    if (_tlsClient.HandshakeCompleted)
                        break;

                    if (await FlushReadAsync(cancellationToken) == 0)
                        throw new Exception("Connection closed");
                }

                _isAuthenticated = true;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
            }

            public override int Read(Span<byte> buffer)
            {
                var length = ReadAsync(_readBuffer, 0, buffer.Length).GetAwaiter().GetResult();

                _readBuffer.AsSpan(0, length).CopyTo(buffer);

                return length;
            }

            public override int ReadByte()
            {
                var length = ReadAsync(_readBuffer, 0, 1).GetAwaiter().GetResult();

                if (length == 0)
                    return -1;

                return _readBuffer[0];
            }

            public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                return await ReadAsync(new Memory<byte>(buffer, offset, count), cancellationToken);
            }

            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (buffer.Length == 0)
                    return 0;

                int length;

                while (true)
                {
                    if (_protocol.GetAvailableInputBytes() > 0)
                    {
                        length = _protocol.ReadInput(_readBuffer, 0, buffer.Length);

                        if (length > 0)
                        {
                            _readBuffer.AsMemory(0, length).CopyTo(buffer);

                            return length;
                        }
                    }

                    length = await FlushReadAsync(cancellationToken);

                    if (length == 0)
                        return 0;
                }
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                WriteAsync(buffer, offset, count);
            }

            public override void WriteByte(byte value)
            {
                Write(new ReadOnlySpan<byte>(in value));
            }

            public override void Write(ReadOnlySpan<byte> buffer)
            {
                _protocol.WriteApplicationData(buffer);

                FlushWriteAsync(CancellationToken.None).GetAwaiter().GetResult();
            }

            public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                await WriteAsync(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken);
            }

            public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                _protocol.WriteApplicationData(buffer.Span);

                await FlushWriteAsync(cancellationToken);
            }

            public override void Flush()
            {
            }

            public override Task FlushAsync(CancellationToken cancellationToken)
            {
                return Task.CompletedTask;
            }

            private async Task<int> FlushReadAsync(CancellationToken cancellationToken)
            {
                var length = await _networkStream.ReadAsync(_readBuffer, cancellationToken);

                _protocol.OfferInput(_readBuffer, 0, length);

                return length;
            }

            private async Task FlushWriteAsync(CancellationToken cancellationToken)
            {
                while (_protocol.GetAvailableOutputBytes() > 0)
                {
                    var length = _protocol.ReadOutput(_writeBuffer, 0, _writeBuffer.Length);

                    await _networkStream.WriteAsync(_writeBuffer.AsMemory(0, length), cancellationToken);
                }

                await _networkStream.FlushAsync(cancellationToken);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _networkStream.Dispose();
                }

                base.Dispose(disposing);
            }
        }

        public Ja3TlsHttpRequestHandler(
            HttpRequestHandlerOptions options,
            ISocketsProvider socketsProvider,
            Ja3Fingerprint fingerprint,
            TimeSpan timeout
        )
        {
            var handler = new SocketsHttpHandler()
            {
                AutomaticDecompression = DecompressionMethods.None,
                AllowAutoRedirect = false
            };

            handler.ConnectCallback = ConnectCallback;

            if (!options.ValidateSsl)
                handler.SslOptions = new()
                {
                    RemoteCertificateValidationCallback = delegate { return true; }
                };

            _httpClient = new HttpClient(handler)
            {
                Timeout = timeout
            };

            _fingerprint = fingerprint;
            _timeout = timeout;
            _socketsProvider = socketsProvider;

            Options = options;
        }

        public HttpRequestHandlerOptions Options { get; }

        public async Task<HttpResponse> SendAsync(HttpRequest request, CancellationToken cancellationToken)
        {
            request.HttpVersion = HttpVersion.Version11;

            using var requestMessage = SystemNetHttpUtils.CreateNetRequestFromRequest(request);

            using var responseMessage = await _httpClient.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);

            return await SystemNetHttpUtils.CreateResponseFromNetResponse(responseMessage, cancellationToken).ConfigureAwait(false);
        }
        public IHttpRequestHandler Clone()
        {
            return new Ja3TlsHttpRequestHandler(Options, _socketsProvider, _fingerprint, _timeout);
        }

        private async ValueTask<Stream> ConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
        {
            var socket = await _socketsProvider.Create(SocketType.Stream, ProtocolType.Tcp, cancellationToken);

            if (!OperatingSystem.IsLinux())
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            try
            {
                Stream networkStream;

                if (Options.Proxy != null)
                {
                    networkStream = await ConnectProxy(socket, context.InitialRequestMessage, cancellationToken);
                }
                else
                {
                    await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);

                    networkStream = socket.GetStream();
                }

                var uri = context.InitialRequestMessage.RequestUri!;

                if (uri.Scheme == Uri.UriSchemeHttps)
                {
                    var tlsClient = new Ja3TlsClient(null, [uri.Host], _fingerprint);
                    var tlsStream = new TlsProtocolStream(networkStream, tlsClient);

                    await tlsStream.ConnectAsync(cancellationToken);

                    return tlsStream;
                }
                else
                {
                    return networkStream;
                }
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        private async Task<Stream> ConnectProxy(ISocket socket, HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await socket.ConnectAsync(
                new DnsEndPoint(Options.Proxy!.Host, Options.Proxy.Port),
                cancellationToken
            ).ConfigureAwait(false);

            var networkStream = socket.GetStream();

            var uri = request.RequestUri!;

            var dataBuilder = new StringBuilder();

            dataBuilder.Append($"CONNECT {uri.Host}:{uri.Port} HTTP/1.1").AppendHttpLine();

            dataBuilder.Append($"User-Agent: {request.Headers.UserAgent.ToString()}").AppendHttpLine();
            dataBuilder.Append($"Host: {uri.Host}443").AppendHttpLine();
            dataBuilder.Append($"Connection: keep-alive").AppendHttpLine();

            if (Options.Proxy.HasCredentials)
            {
                var credentials = Options.Proxy.ToWebProxy().Credentials!.GetCredential(uri, "Basic")!;

                dataBuilder.Append($"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credentials.UserName}:{credentials.Password}"))}").AppendHttpLine();
            }

            dataBuilder.AppendHttpLine();

            var data = dataBuilder.ToString();

            var buffer = ArrayPool<byte>.Shared.Rent(
                Math.Max(Encoding.UTF8.GetByteCount(data), 8192)
            );

            try
            {
                var length = Encoding.UTF8.GetBytes(data, buffer);

                await networkStream.WriteAsync(buffer.AsMemory(0, length), cancellationToken);
                await networkStream.FlushAsync(cancellationToken);

                var lineBuffer = new StringBuilder();
                var completed = false;

                while (!completed)
                {
                    length = await networkStream.ReadAsync(buffer, cancellationToken);

                    if (length == 0)
                        throw new Exception("Connection closed");

                    for (var i = 0; i < length; i++)
                    {
                        if (i < length - 1 &&
                            buffer[i] == '\r' &&
                            buffer[i + 1] == '\n')
                        {
                            var line = lineBuffer.ToString();

                            if (line.StartsWith("HTTP/1.1", StringComparison.OrdinalIgnoreCase))
                            {
                                var parts = line.Split(' ');

                                var statusCode = int.Parse(parts[1]);

                                if (statusCode != 200)
                                    throw new Exception($"Error when connecting to proxy: {statusCode} {string.Join(' ', parts[2..])}");
                            }
                            else if (line.Length == 0)
                            {
                                completed = true;
                                break;
                            }

                            lineBuffer.Clear();

                            i++;
                        }
                        else
                        {
                            lineBuffer.Append((char)buffer[i]);
                        }
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            return networkStream;
        }

        public void Dispose()
        {
            _httpClient.Dispose();
        }
    }
}
