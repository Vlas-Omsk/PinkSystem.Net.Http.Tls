using BotsCommon.Net.Http.Handlers;
using BotsCommon.Net.Http.Sockets;
using System;

namespace BotsCommon.Net.Http.Tls.Handlers.Factories
{
    public sealed class Ja3TlsHttpRequestHandlerFactory : IFingerprintedHttpRequestHandlerFactory
    {
        private readonly SystemNetSocketOptions _socketOptions;
        private readonly TimeSpan _timeout;

        public Ja3TlsHttpRequestHandlerFactory(SystemNetSocketOptions socketOptions, TimeSpan timeout)
        {
            _socketOptions = socketOptions;
            _timeout = timeout;
        }

        public ISocketsProvider SocketsProvider => _socketOptions.Provider;

        public IHttpRequestHandler Create(FingerprintedHttpRequestHandlerOptions options)
        {
            return new Ja3TlsHttpRequestHandler(options, _socketOptions, options.Fingerprint ?? Ja3Fingerprint.Chrome123, _timeout);
        }

        public IHttpRequestHandler Create(HttpRequestHandlerOptions options)
        {
            return new Ja3TlsHttpRequestHandler(options, _socketOptions, Ja3Fingerprint.Chrome123, _timeout);
        }
    }
}
