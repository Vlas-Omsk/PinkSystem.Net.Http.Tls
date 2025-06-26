using Org.BouncyCastle.Tls;
using System;
using System.Linq;

namespace PinkSystem.Net
{
    public sealed record Ja3Fingerprint(
        ProtocolVersion[] SupportedVersions,
        int[] SupportedCiphers,
        int[] SupportedGroups,
        int[] ExtensionsOrder
    )
    {
        public static Ja3Fingerprint SystemNet { get; } = Parse("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0");

        public override string ToString()
        {
            return $"{ProtocolVersion.GetLatestTls(SupportedVersions).FullVersion},{string.Join('-', SupportedCiphers)},{string.Join('-', ExtensionsOrder)},{string.Join('-', SupportedGroups)},0";
        }

        public static Ja3Fingerprint Parse(string fingerprints)
        {
            var parts = fingerprints.Split(',');

            if (parts.Length != 5)
                throw new FormatException("JA3 isn't in correct format");

            var tlsVersion = short.Parse(parts[0]);
            var ciphers = parts[1].Split('-').Select(int.Parse).ToArray();
            var extensions = parts[2].Split('-').Select(int.Parse).ToArray();
            var ellipticCurve = parts[3].Split('-').Select(int.Parse).ToArray();

            var majorTlsVersion = (tlsVersion & 0b1111111100000000) >> 8;
            var minorTlsVersion = tlsVersion & 0b0000000011111111;

            return new Ja3Fingerprint(
                [ProtocolVersion.Get(majorTlsVersion, minorTlsVersion)],
                ciphers,
                ellipticCurve,
                extensions
            );
        }
    }
}
