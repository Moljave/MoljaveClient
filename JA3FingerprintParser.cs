using System;
using System.Linq;

namespace Moljave.Http
{
    public static class JA3FingerprintParser
    {
        public static JA3Fingerprint Parse(string ja3FingerprintString)
        {
            var fields = ja3FingerprintString.Split(',');
            if (fields.Length != 5)
                throw new ArgumentException("Invalid JA3 fingerprint format.", nameof(ja3FingerprintString));

            var sslVersion = int.Parse(fields[0]);
            var cipherSuites = ParseIntArray(fields[1]);
            var extensions = ParseIntArray(fields[2]);
            var ellipticCurves = ParseIntArray(fields[3]);
            var ellipticCurvePointFormats = ParseIntArray(fields[4]);

            return new JA3Fingerprint(sslVersion, cipherSuites, extensions, ellipticCurves, ellipticCurvePointFormats);
        }

        private static int[] ParseIntArray(string field)
        {
            return string.IsNullOrWhiteSpace(field)
                ? Array.Empty<int>()
                : field.Split('-').Select(int.Parse).ToArray();
        }
    }
}
