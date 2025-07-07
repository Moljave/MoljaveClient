using System;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;

namespace Moljave.Http
{
    public class JA3Fingerprint
    {
        public static readonly JA3Fingerprint Default = new(
            769,
            new[] { 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53 },
            new[] { 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21, 41, 28, 19 },
            new[] { 29, 23, 24 },
            new[] { 0 }
        );

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
                769 => SslProtocols.Tls12,
                768 => SslProtocols.Tls11,
                767 => SslProtocols.Tls,
                _ => SslProtocols.None
            };
        }

        public TlsCipherSuite[] GetCipherSuites()
        {
            return CipherSuites.Select(CipherSuiteConverter.GetCipherSuite).ToArray();
        }

        public string[] GetApplicationProtocols()
        {
            var applicationProtocols = Extensions
                .Where(extensionType => extensionType == 16)
                .Select(extensionType => "http/1.1")
                .ToArray();
            return applicationProtocols;
        }
    }
}
