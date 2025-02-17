using PinkSystem.Net.Http.Handlers;
using PinkSystem.Net.Http.Handlers.Factories;
using PinkSystem.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace PinkSystem.Net.Http.Tls.Handlers.Factories
{
    public sealed class FingerprintedSharedPooledHttpRequestHandlerFactory : IFingerprintedHttpRequestHandlerFactory
    {
        private readonly SharedPooledHttpRequestHandlerFactory _httpRequestHandlerFactory;

        private sealed class Factory : IFingerprintedHttpRequestHandlerFactory
        {
            private readonly IFingerprintedHttpRequestHandlerFactory _httpRequestHandlerFactory;

            public Factory(IFingerprintedHttpRequestHandlerFactory httpRequestHandlerFactory)
            {
                _httpRequestHandlerFactory = httpRequestHandlerFactory;
            }

            public ISocketsProvider SocketsProvider => _httpRequestHandlerFactory.SocketsProvider;

            public IHttpRequestHandler Create(FingerprintedHttpRequestHandlerOptions options)
            {
                return _httpRequestHandlerFactory.Create(options);
            }

            public IHttpRequestHandler Create(HttpRequestHandlerOptions options)
            {
                if (options is FingerprintedHttpRequestHandlerOptions fingerprintedOptions)
                    return Create(fingerprintedOptions);

                return _httpRequestHandlerFactory.Create(options);
            }
        }

        public FingerprintedSharedPooledHttpRequestHandlerFactory(
            IFingerprintedHttpRequestHandlerFactory httpRequestHandlerFactory,
            IHttpRequestHandlerWrapper httpRequestHandlerWrapper,
            ILoggerFactory loggerFactory
        )
        {
            _httpRequestHandlerFactory = new(new Factory(httpRequestHandlerFactory), httpRequestHandlerWrapper, loggerFactory);
        }

        public ISocketsProvider SocketsProvider => _httpRequestHandlerFactory.SocketsProvider;

        public IHttpRequestHandler Create(FingerprintedHttpRequestHandlerOptions options)
        {
            return _httpRequestHandlerFactory.Create(options);
        }

        public IHttpRequestHandler Create(HttpRequestHandlerOptions options)
        {
            return _httpRequestHandlerFactory.Create(options);
        }
    }
}
