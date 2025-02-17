using PinkSystem.Net.Http.Handlers;
using PinkSystem.Net.Sockets;
using System;

namespace PinkSystem.Net.Http.Tls.Handlers.Factories
{
    public sealed class Ja3TlsHttpRequestHandlerFactory : IFingerprintedHttpRequestHandlerFactory
    {
        private readonly ISocketsProvider _socketsProvider;
        private readonly TimeSpan _timeout;

        public Ja3TlsHttpRequestHandlerFactory(ISocketsProvider socketsProvider, TimeSpan timeout)
        {
            _socketsProvider = socketsProvider;
            _timeout = timeout;
        }

        public ISocketsProvider SocketsProvider => _socketsProvider;

        public IHttpRequestHandler Create(FingerprintedHttpRequestHandlerOptions options)
        {
            return new Ja3TlsHttpRequestHandler(options, _socketsProvider, options.Fingerprint ?? Ja3Fingerprint.Default, _timeout);
        }

        public IHttpRequestHandler Create(HttpRequestHandlerOptions options)
        {
            return new Ja3TlsHttpRequestHandler(options, _socketsProvider, Ja3Fingerprint.Default, _timeout);
        }
    }
}
