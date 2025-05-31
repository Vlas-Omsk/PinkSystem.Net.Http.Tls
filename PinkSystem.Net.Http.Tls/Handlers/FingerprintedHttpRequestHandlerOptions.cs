using System;
using PinkSystem.Net.Http.Handlers;

namespace PinkSystem.Net.Http.Tls.Handlers
{
    public sealed record FingerprintedHttpRequestHandlerOptions : IFingerprintedHttpRequestHandlerOptions
    {
        public Proxy? Proxy { get; init; }
        public TimeSpan Timeout { get; init; } = HttpTimeout.Default;
        public Ja3Fingerprint Fingerprint { get; init; } = Ja3Fingerprint.Default;

        public bool Equals(IHttpRequestHandlerOptions? other)
        {
            return ((object)this).Equals(other);
        }
    }
}
