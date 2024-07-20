namespace BotsCommon.Net.Http.Tls
{
    public sealed record FingerprintedHttpRequestHandlerOptions : HttpRequestHandlerOptions
    {
        public Ja3Fingerprint? Fingerprint { get; }
    }
}
