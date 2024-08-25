using PinkSystem.Net.Http.Handlers;
using PinkSystem.Net.Http.Handlers.Factories;

namespace PinkSystem.Net.Http.Tls.Handlers.Factories
{
    public interface IFingerprintedHttpRequestHandlerFactory : ISocketsHttpRequestHandlerFactory
    {
        IHttpRequestHandler Create(FingerprintedHttpRequestHandlerOptions options);
    }
}
