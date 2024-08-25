using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;

namespace PinkSystem.Net.Http.Tls
{
    public static class TlsCipher
    {
        private static readonly string _base16Chars = "0123456789ABCDEF";
        private static readonly int[] _availableCiphers =
        {
            0x1302,
            0x1303,
            0x1301,
            0xc02c,
            0xc030,
            0xc02b,
            0xc02f,
            0xcca9,
            0xcca8,
            0xc0af,
            0xc0ad,
            0xc05d,
            0xc061,
            0xc0ae,
            0xc0ac,
            0xc05c,
            0xc060,
            0xc024,
            0xc028,
            0xc073,
            0xc077,
            0xc023,
            0xc027,
            0xc072,
            0xc076,
            0xc00a,
            0xc014,
            0xc009,
            0xc013,
            0x009d,
            0xc0a1,
            0xc09d,
            0x009c,
            0xc0a0,
            0xc09c,
            0x003d,
            0x003c,
            0x0035,
            0x002f,
            0x00a3,
            0x009f,
            0xc0a3,
            0xc09f,
            0x006b,
            0x006a,
            0x0039,
            0x0038,
            0xc051,
            0xc050,
            0x00c0,
            0x00ba,
            0x0084,
            0x0041,
            0xccaa,
            0xc057,
            0xc053,
            0x00a2,
            0x009e,
            0xc0a2,
            0xc09e,
            0xc056,
            0xc052,
            0x00c4,
            0x00c3,
            0x0067,
            0x0040,
            0x00be,
            0x00bd,
            0x0088,
            0x0087,
            0x0033,
            0x0032,
            0x0045,
            0x0044,
            0x00ff,
        };

        public static int[] FirefoxCiphers { get; set; } =
        {
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
        };

        public static int[] ArkoseLabsCiphers { get; set; } =
        {
            GetRandomCipher(),
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        };

        public static int[] GetRandomCiphers(int count)
        {
            var ciphers = new List<int>();
            
            for (int i = 0; i < count; i++)
            {
                var cipher = _availableCiphers[Random.Shared.Next(0, _availableCiphers.Length)];

                if (ciphers.Contains(cipher))
                {
                    i--;
                    continue;
                }

                ciphers.Add(cipher);
            }

            return ciphers.ToArray();
        }

        private static int GetRandomCipher()
        {
            var @char = _base16Chars[Random.Shared.Next(_base16Chars.Length)];

            return Convert.ToInt32($"0x{@char}A{@char}A", 16);
        }
    }
}
