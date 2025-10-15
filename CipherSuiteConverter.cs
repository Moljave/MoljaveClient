using System;
using System.Collections.Generic;
using System.Net.Security;

namespace Moljave.Http
{
    public static class CipherSuiteConverter
    {
        private static readonly Dictionary<int, TlsCipherSuite> _cipherSuiteMap = new()
        {
            { 4865, TlsCipherSuite.TLS_AES_128_GCM_SHA256 },
            { 4866, TlsCipherSuite.TLS_AES_256_GCM_SHA384 },
            { 4867, TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256 },
            { 49195, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 },
            { 49199, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },
            { 49196, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 },
            { 49200, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
            { 52393, TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 },
            { 52392, TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 },
            { 49171, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA },
            { 49172, TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA },
            { 156, TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 },
            { 157, TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 },
            { 47, TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA },
            { 53, TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA }
        };

        public static bool TryGetCipherSuite(int cipherSuiteId, out TlsCipherSuite cipherSuite)
        {
            if (_cipherSuiteMap.TryGetValue(cipherSuiteId, out cipherSuite))
            {
                return true;
            }

            if (cipherSuiteId >= 0 && cipherSuiteId <= ushort.MaxValue)
            {
                cipherSuite = (TlsCipherSuite)(ushort)cipherSuiteId;
                return true;
            }

            cipherSuite = default;
            return false;
        }

        public static TlsCipherSuite GetCipherSuite(int cipherSuiteId)
        {
            if (TryGetCipherSuite(cipherSuiteId, out var cipherSuite)) return cipherSuite;
            throw new ArgumentException($"Unsupported cipher suite ID: {cipherSuiteId}", nameof(cipherSuiteId));
        }
    }
}
