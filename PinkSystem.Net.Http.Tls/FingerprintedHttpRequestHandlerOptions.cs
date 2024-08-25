namespace PinkSystem.Net.Http.Tls
{
    public sealed record FingerprintedHttpRequestHandlerOptions : HttpRequestHandlerOptions
    {
        public Ja3Fingerprint? Fingerprint { get; set; }
    }
}
