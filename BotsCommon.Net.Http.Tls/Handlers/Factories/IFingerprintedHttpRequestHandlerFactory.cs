using BotsCommon.Net.Http.Handlers;
using BotsCommon.Net.Http.Handlers.Factories;

namespace BotsCommon.Net.Http.Tls.Handlers.Factories
{
    public interface IFingerprintedHttpRequestHandlerFactory : IHttpRequestHandlerFactory
    {
        IHttpRequestHandler Create(FingerprintedHttpRequestHandlerOptions options);
    }
}
