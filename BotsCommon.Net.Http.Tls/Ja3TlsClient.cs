using MoreLinq;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace BotsCommon.Net.Http.Tls
{
    internal sealed class Ja3TlsClient : AbstractTlsClient
    {
        private static readonly SignatureAndHashAlgorithm[] _signatureAlgorithms =
        {
            CreateSignatureAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pss_rsae_sha256),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha256),
            CreateSignatureAlgorithm(SignatureScheme.ecdsa_secp384r1_sha384),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pss_rsae_sha384),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha384),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pss_rsae_sha512),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha512),
            CreateSignatureAlgorithm(SignatureScheme.rsa_pkcs1_sha1),
        };
        private readonly TlsSession? _tlsSession;
        private readonly ServerName[] _serverNames;
        private readonly Ja3Fingerprint _fingerprint;
        private IDictionary<int, byte[]>? _supportedClientExtensions;

        private sealed class EmptyTlsAuthentication : TlsAuthentication
        {
            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest)
            {
                return null;
            }

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
            }
        }

        public Ja3TlsClient(
            TlsSession? tlsSession,
            string[] serverNames,
            Ja3Fingerprint fingerprint
        ) : base(new BcTlsCrypto(new SecureRandom()))
        {
            _tlsSession = tlsSession;
            _serverNames = serverNames.Select(x => new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(x))).ToArray();
            _fingerprint = fingerprint;
        }

        public bool EnableHttp2 { get; set; } = false;
        public bool HandshakeCompleted { get; private set; } = false;

        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles)
        {
            var supportedGroups = new List<int>();

            TlsUtilities.AddIfSupported(supportedGroups, Crypto, _fingerprint.SupportedGroups);

            return supportedGroups;
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return _fingerprint.SupportedVersions;
        }

        protected override IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms()
        {
            return _signatureAlgorithms;
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return _fingerprint.SupportedCiphers;
        }

        protected override IList<ServerName> GetSniServerNames()
        {
            return _serverNames;
        }

        public override IList<TlsPskExternal>? GetExternalPsks()
        {
            var identity = Strings.ToUtf8ByteArray("client");
            var key = Crypto.CreateSecret(Strings.ToUtf8ByteArray("TLS_TEST_PSK"));
            int prfAlgorithm = PrfAlgorithm.tls13_hkdf_sha256;

            return TlsUtilities.VectorOfOne(new BasicTlsPskExternal(identity, key, prfAlgorithm))
                .Select(o => (TlsPskExternal)o)
                .ToList();
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new EmptyTlsAuthentication();
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            if (_supportedClientExtensions == null)
            {
                var supportedClientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(base.GetClientExtensions());

                TlsExtensionsUtilities.AddMaxFragmentLengthExtension(supportedClientExtensions, MaxFragmentLength.pow2_9);
                TlsExtensionsUtilities.AddPaddingExtension(supportedClientExtensions, m_context.Crypto.SecureRandom.Next(16));
                TlsExtensionsUtilities.AddTruncatedHmacExtension(supportedClientExtensions);
                TlsExtensionsUtilities.AddRecordSizeLimitExtension(supportedClientExtensions, 16385);
                TlsExtensionsUtilities.AddPaddingExtension(supportedClientExtensions, 0);
                TlsExtensionsUtilities.AddCompressCertificateExtension(supportedClientExtensions, [2]);
                TlsExtensionsUtilities.AddSupportedVersionsExtensionClient(supportedClientExtensions, _fingerprint.SupportedVersions);
                TlsExtensionsUtilities.AddStatusRequestExtension(supportedClientExtensions, new CertificateStatusRequest(1, new OcspStatusRequest(new List<ResponderID>(), null)));
                TlsExtensionsUtilities.AddExtendedMasterSecretExtension(supportedClientExtensions);
                TlsExtensionsUtilities.AddPskKeyExchangeModesExtension(supportedClientExtensions, [1, 1]);
                TlsExtensionsUtilities.AddKeyShareClientHello(supportedClientExtensions, [new KeyShareEntry(29, Encoding.ASCII.GetBytes(Guid.NewGuid().ToString()).Take(32).ToArray())]);
                //TlsExtensionsUtilities.AddStatusRequestaddV2Extension(clientExtensions, [new CertificateStatusRequestItemV2(1,new OcspStatusRequest(new List<ResponderID>(),null))]);
                //TlsExtensionsUtilities.AddEmptyExtensionData(clientExtensions, 0);
                //TlsExtensionsUtilities.enc(clientExtensions, [2]);

                var offeringTlsV13Plus = false;
                var supportedVersions = GetProtocolVersions();

                foreach (var supportedVersion in supportedVersions)
                {
                    if (TlsUtilities.IsTlsV13(supportedVersion))
                    {
                        offeringTlsV13Plus = true;
                        break;
                    }
                }

                if (offeringTlsV13Plus)
                {
                    var offeredCipherSuites = GetCipherSuites();
                    var psks = GetPskExternalsClient(this, offeredCipherSuites);

                    if (psks != null)
                    {
                        var identities = new List<PskIdentity>(psks.Length);

                        for (int i = 0; i < psks.Length; ++i)
                        {
                            TlsPsk psk = psks[i];

                            // TODO: [tls13-psk] Handle obfuscated_ticket_age for resumption PSKs
                            identities.Add(new PskIdentity(psk.Identity, 0L));
                        }

                        TlsExtensionsUtilities.AddPreSharedKeyClientHello(supportedClientExtensions, new OfferedPsks(identities));
                    }
                }

                supportedClientExtensions[ExtensionType.renegotiation_info] = TlsUtilities.EncodeOpaque8(TlsUtilities.EmptyBytes);

                //next_protocol_negotiation
                supportedClientExtensions[13172] = [];
                //extension application settings
                supportedClientExtensions[17513] = [0x00, 0x03, 0x02, 0x68, 0x32];
                //http 2
                supportedClientExtensions[16] = [0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31];
                supportedClientExtensions[18] = [];
                //supportedClientExtensions[34] = [];
                supportedClientExtensions[35] = [];
                supportedClientExtensions[65037] =
                [
                    0x00, // Outer Client Hello (0)
                    0x00, 0x01, 0x00, 0x01, // HKDF-SHA256/AES-128-GCM
                    0xea, // Config Id: 234
                    0x00, 0x20, // Enc length: 32
                    0x98, 0x93, 0x0f, 0x55, 0x8c, 0x72, 0x9c, 0xc8, 0xed, 0x7c, 0xbe, 0xba, 0x1e, 0x92, 0x77, 0xa4, 0x68, 0x2c, 0xa8, 0xb0, 0x7a, 0x8c, 0x45, 0x02, 0xb2, 0x03, 0x31, 0xf3, 0xfe, 0x6d, 0xdb, 0x29, // Enc
                    0x00, 0x00 // Payload length: 0
                ];

                _supportedClientExtensions = supportedClientExtensions;
            }

            var clientExtensions = new Dictionary<int, byte[]>();

            foreach (var clientExtensionId in _fingerprint.ExtensionsOrder.Shuffle())
            {
                if (clientExtensionId == 16 && !EnableHttp2)
                    continue;

                if (!_supportedClientExtensions.TryGetValue(clientExtensionId, out var value))
                {
                    Debug.WriteLine($"Client extension {clientExtensionId} not supported");
                    continue;
                }

                clientExtensions[clientExtensionId] = value;
            }

            return clientExtensions;
        }

        private static TlsPskExternal[]? GetPskExternalsClient(TlsClient client, int[] offeredCipherSuites)
        {
            var externalPsks = client.GetExternalPsks();

            if (externalPsks == null || externalPsks.Count < 1)
                return null;

            var prfAlgorithms = GetPrfAlgorithms13(offeredCipherSuites);

            var count = externalPsks.Count;
            var result = new TlsPskExternal[count];

            for (int i = 0; i < count; ++i)
            {
                var pskExternal = externalPsks[i];

                if (null == pskExternal)
                    throw new TlsFatalAlert(AlertDescription.internal_error, "External PSKs element is not a TlsPSKExternal");

                if (!Arrays.Contains(prfAlgorithms, pskExternal.PrfAlgorithm))
                    throw new TlsFatalAlert(AlertDescription.internal_error, "External PSK incompatible with offered cipher suites");

                result[i] = pskExternal;
            }

            return result;
        }

        private static int[] GetPrfAlgorithms13(int[] cipherSuites)
        {
            var result = new int[Math.Min(3, cipherSuites.Length)];

            var count = 0;

            for (var i = 0; i < cipherSuites.Length; ++i)
            {
                var prfAlgorithm = GetPrfAlgorithm13(cipherSuites[i]);

                if (prfAlgorithm >= 0 &&
                    !Arrays.Contains(result, prfAlgorithm))
                    result[count++] = prfAlgorithm;
            }

            return Truncate(result, count);
        }

        private static int GetPrfAlgorithm13(int cipherSuite)
        {
            // NOTE: GetPrfAlgorithms13 relies on the number of distinct return values
            switch (cipherSuite)
            {
                case CipherSuite.TLS_AES_128_CCM_SHA256:
                case CipherSuite.TLS_AES_128_CCM_8_SHA256:
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                    return PrfAlgorithm.tls13_hkdf_sha256;

                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    return PrfAlgorithm.tls13_hkdf_sha384;

                case CipherSuite.TLS_SM4_CCM_SM3:
                case CipherSuite.TLS_SM4_GCM_SM3:
                    return PrfAlgorithm.tls13_hkdf_sm3;

                default:
                    return -1;
            }
        }
        private static int[] Truncate(int[] a, int n)
        {
            if (n >= a.Length)
                return a;

            int[] t = new int[n];
            Array.Copy(a, 0, t, 0, n);
            return t;
        }

        public override TlsSession? GetSessionToResume()
        {
            return _tlsSession;
        }

        public override void NotifyHandshakeComplete()
        {
            HandshakeCompleted = true;
        }

        private static SignatureAndHashAlgorithm CreateSignatureAlgorithm(int signatureScheme)
        {
            var hashAlgorithm = SignatureScheme.GetHashAlgorithm(signatureScheme);
            var signatureAlgorithm = SignatureScheme.GetSignatureAlgorithm(signatureScheme);

            return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
        }
    }
}
