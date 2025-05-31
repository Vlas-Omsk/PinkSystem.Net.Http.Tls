using PinkSystem.Net.Http.Handlers;

namespace PinkSystem.Net.Http.Tls.Handlers
{
    public interface IFingerprintedHttpRequestHandlerOptions : IHttpRequestHandlerOptions
    {
        Ja3Fingerprint Fingerprint { get; }
    }
}
