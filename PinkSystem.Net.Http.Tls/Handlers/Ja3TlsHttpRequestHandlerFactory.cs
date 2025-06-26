using Org.BouncyCastle.Tls;
using PinkSystem.Net.Http.Handlers;
using PinkSystem.Net.Sockets;
using System;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Threading.Tasks;
using System.Threading;

namespace PinkSystem.Net.Http.Tls.Handlers
{
    public sealed class Ja3TlsHttpRequestHandlerFactory : IHttpRequestHandlerFactory
    {
        private readonly ISocketsProvider _socketsProvider;

        private sealed class Ja3TlsHttpRequestHandler : IHttpRequestHandler
        {
            private readonly IHttpRequestHandlerOptions? _options;
            private readonly ISocketsProvider _socketsProvider;
            private readonly HttpClient _httpClient;

            private sealed class NullStream : Stream
            {
                public override bool CanRead { get; } = true;
                public override bool CanSeek { get; } = true;
                public override bool CanWrite { get; } = true;
                public override long Length { get; } = 0;
                public override long Position { get; set; } = 0;

                public override void Flush()
                {
                }

                public override int Read(byte[] buffer, int offset, int count)
                {
                    return 0;
                }

                public override long Seek(long offset, SeekOrigin origin)
                {
                    Position = offset;

                    return offset;
                }

                public override void SetLength(long value)
                {
                    throw new NotSupportedException();
                }

                public override void Write(byte[] buffer, int offset, int count)
                {
                }
            }

            private sealed class TlsProtocolStream : SslStream
            {
                private readonly Stream _networkStream;
                private readonly Ja3TlsClient _tlsClient;
                private readonly TlsClientProtocol _protocol;
                private readonly byte[] _readBuffer = new byte[8192];
                private readonly byte[] _writeBuffer = new byte[8192];
                private bool _isAuthenticated = false;

                public TlsProtocolStream(Stream networkStream, Ja3TlsClient tlsClient) : base(new NullStream())
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
                    return Read(buffer.AsSpan(offset, count));
                }

                public override int ReadByte()
                {
                    var length = Read(_readBuffer.AsSpan(0, 1));

                    if (length == 0)
                        return -1;

                    return _readBuffer[0];
                }

                public override int Read(Span<byte> buffer)
                {
                    if (buffer.Length == 0)
                        return 0;

                    int length;

                    while (true)
                    {
                        var position = 0;

                        while (position < buffer.Length && _protocol.GetAvailableInputBytes() > 0)
                        {
                            length = _protocol.ReadInput(_readBuffer, 0, Math.Min(_readBuffer.Length, buffer.Length - position));

                            _readBuffer.AsSpan(0, length).CopyTo(buffer.Slice(position));

                            position += length;
                        }

                        if (position > 0)
                            return position;

                        length = FlushRead();

                        if (length == 0)
                            return 0;
                    }
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
                        var position = 0;

                        while (position < buffer.Length && _protocol.GetAvailableInputBytes() > 0)
                        {
                            length = _protocol.ReadInput(_readBuffer, 0, Math.Min(_readBuffer.Length, buffer.Length - position));

                            _readBuffer.AsMemory(0, length).CopyTo(buffer.Slice(position));

                            position += length;
                        }

                        if (position > 0)
                            return position;

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
                    Write(buffer.AsSpan(offset, count));
                }

                public override void WriteByte(byte value)
                {
                    Write(new ReadOnlySpan<byte>(in value));
                }

                public override void Write(ReadOnlySpan<byte> buffer)
                {
                    _protocol.WriteApplicationData(buffer);

                    FlushWrite();
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

                private int FlushRead()
                {
                    var length = _networkStream.Read(_readBuffer);

                    if (length > 0)
                        _protocol.OfferInput(_readBuffer, 0, length);

                    return length;
                }

                private async Task<int> FlushReadAsync(CancellationToken cancellationToken)
                {
                    var length = await _networkStream.ReadAsync(_readBuffer, cancellationToken);

                    if (length > 0)
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

                private void FlushWrite()
                {
                    while (_protocol.GetAvailableOutputBytes() > 0)
                    {
                        var length = _protocol.ReadOutput(_writeBuffer, 0, _writeBuffer.Length);

                        _networkStream.Write(_writeBuffer.AsSpan(0, length));
                    }

                    _networkStream.Flush();
                }

                public override ValueTask DisposeAsync()
                {
                    Dispose(true);

                    return ValueTask.CompletedTask;
                }

                protected override void Dispose(bool disposing)
                {
                    if (disposing)
                        _networkStream.Dispose();
                }
            }

            public Ja3TlsHttpRequestHandler(
                IHttpRequestHandlerOptions? options,
                ISocketsProvider socketsProvider
            )
            {
                var handler = new SocketsHttpHandler
                {
                    AutomaticDecompression = DecompressionMethods.None,
                    AllowAutoRedirect = false,
                    ConnectCallback = ConnectCallback,
                };

                _httpClient = new HttpClient(handler)
                {
                    Timeout = options?.Timeout ?? HttpTimeout.Default
                };

                _options = options;
                _socketsProvider = socketsProvider;
            }

            public async Task<HttpResponse> SendAsync(HttpRequest request, CancellationToken cancellationToken)
            {
                // We disable support for other http versions, as they use additional fingerprinting methods that not supported.
                request.HttpVersion = HttpVersion.Version11;

                using var requestMessage = SystemNetHttpUtils.CreateNetRequestFromRequest(request);

                using var responseMessage = await _httpClient.SendWithExceptionWrappingAsync(requestMessage, cancellationToken).ConfigureAwait(false);

                return await SystemNetHttpUtils.CreateResponseFromNetResponse(responseMessage, cancellationToken).ConfigureAwait(false);
            }

            private async ValueTask<Stream> ConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
            {
                var socket = await _socketsProvider.Create(SocketType.Stream, ProtocolType.Tcp, cancellationToken);

                if (!OperatingSystem.IsLinux())
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                try
                {
                    Stream networkStream;

                    if (_options?.Proxy != null)
                    {
                        networkStream = await _options.Proxy.EstablishConnection(
                            socket,
                            context.InitialRequestMessage.RequestUri!.Host,
                            context.InitialRequestMessage.RequestUri!.Port,
                            cancellationToken
                        );
                    }
                    else
                    {
                        await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);

                        networkStream = socket.GetStream();
                    }

                    var uri = context.InitialRequestMessage.RequestUri!;

                    if (uri.Scheme == Uri.UriSchemeHttps)
                    {
                        var fingerprint = _options is IFingerprintedHttpRequestHandlerOptions fingerprintedOptions ?
                            fingerprintedOptions.Fingerprint :
                            Ja3Fingerprint.SystemNet;

                        var tlsClient = new Ja3TlsClient(null, [uri.Host], fingerprint);
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

            public void Dispose()
            {
                _httpClient.Dispose();
            }
        }

        public Ja3TlsHttpRequestHandlerFactory(ISocketsProvider socketsProvider)
        {
            _socketsProvider = socketsProvider;
        }

        public IHttpRequestHandler Create(IHttpRequestHandlerOptions? options)
        {
            return new Ja3TlsHttpRequestHandler(options, _socketsProvider);
        }
    }
}
