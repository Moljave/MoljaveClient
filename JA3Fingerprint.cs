using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;

namespace Moljave.Http
{
    public class JA3Fingerprint : IEquatable<JA3Fingerprint>
    {
        public static readonly JA3Fingerprint Default = new(
            769,
            new[] { 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53 },
            new[] { 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21, 41, 28, 19 },
            new[] { 29, 23, 24 },
            new[] { 0 }
        );

        private TlsCipherSuite[] _cachedCipherSuites;
        private string[] _cachedApplicationProtocols;

        public JA3Fingerprint(int sslVersion, int[] cipherSuites, int[] extensions, int[] ellipticCurves, int[] ellipticCurvePointFormats)
        {
            SslVersion = sslVersion;
            CipherSuites = cipherSuites;
            Extensions = extensions;
            EllipticCurves = ellipticCurves;
            EllipticCurvePointFormats = ellipticCurvePointFormats;
        }

        public int SslVersion { get; }
        public int[] CipherSuites { get; }
        public int[] Extensions { get; }
        public int[] EllipticCurves { get; }
        public int[] EllipticCurvePointFormats { get; }

        public SslProtocols GetSslProtocols()
        {
            return SslVersion switch
            {
                771 => SslProtocols.Tls12,
                772 => SslProtocols.Tls13,
                769 => SslProtocols.Tls12,
                768 => SslProtocols.Tls11,
                767 => SslProtocols.Tls,
                _ => SslProtocols.None
            };
        }

        public TlsCipherSuite[] GetCipherSuites()
        {
            if (_cachedCipherSuites != null)
            {
                return _cachedCipherSuites;
            }

            if (CipherSuites == null || CipherSuites.Length == 0)
            {
                _cachedCipherSuites = Array.Empty<TlsCipherSuite>();
                return _cachedCipherSuites;
            }

            var supportedSuites = new List<TlsCipherSuite>(CipherSuites.Length);
            foreach (var cipherSuiteId in CipherSuites)
            {
                if (CipherSuiteConverter.TryGetCipherSuite(cipherSuiteId, out var cipherSuite))
                {
                    supportedSuites.Add(cipherSuite);
                }
            }

            _cachedCipherSuites = supportedSuites.ToArray();
            return _cachedCipherSuites;
        }

        public string[] GetApplicationProtocols()
        {
            if (_cachedApplicationProtocols != null)
            {
                return _cachedApplicationProtocols;
            }

            if (Extensions == null || Extensions.Length == 0)
            {
                _cachedApplicationProtocols = Array.Empty<string>();
                return _cachedApplicationProtocols;
            }

            var count = 0;
            foreach (var extensionType in Extensions)
            {
                if (extensionType == 16)
                {
                    count++;
                }
            }

            if (count == 0)
            {
                _cachedApplicationProtocols = Array.Empty<string>();
                return _cachedApplicationProtocols;
            }

            var protocols = new string[count];
            for (int i = 0; i < count; i++)
            {
                protocols[i] = "http/1.1";
            }

            _cachedApplicationProtocols = protocols;
            return _cachedApplicationProtocols;
        }

        public bool Equals(JA3Fingerprint other)
        {
            if (ReferenceEquals(this, other))
            {
                return true;
            }

            if (other is null)
            {
                return false;
            }

            return SslVersion == other.SslVersion &&
                   SequenceEqual(CipherSuites, other.CipherSuites) &&
                   SequenceEqual(Extensions, other.Extensions) &&
                   SequenceEqual(EllipticCurves, other.EllipticCurves) &&
                   SequenceEqual(EllipticCurvePointFormats, other.EllipticCurvePointFormats);
        }

        public override bool Equals(object obj)
            => Equals(obj as JA3Fingerprint);

        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(SslVersion);
            AddSequenceHash(ref hash, CipherSuites);
            AddSequenceHash(ref hash, Extensions);
            AddSequenceHash(ref hash, EllipticCurves);
            AddSequenceHash(ref hash, EllipticCurvePointFormats);
            return hash.ToHashCode();
        }

        private static bool SequenceEqual(int[] first, int[] second)
        {
            if (ReferenceEquals(first, second))
            {
                return true;
            }

            if (first == null || second == null || first.Length != second.Length)
            {
                return false;
            }

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static void AddSequenceHash(ref HashCode hash, int[] values)
        {
            if (values == null)
            {
                hash.Add(0);
                return;
            }

            hash.Add(values.Length);
            for (int i = 0; i < values.Length; i++)
            {
                hash.Add(values[i]);
            }
        }
    }
}
