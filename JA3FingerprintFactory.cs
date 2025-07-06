using System;
using System.Collections.Generic;

namespace Moljave.Http
{
    public enum BrowserJa3Profile
    {
        Chrome,
        Custom
    }

    public static class JA3FingerprintFactory
    {
        private static readonly Dictionary<BrowserJa3Profile, string[]> Ja3Presets = new()
        {
            { BrowserJa3Profile.Chrome, new[] {
                "771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-45-43-51-27-21-41-28-19,29-23-24,0"
            }},
        };

        private static readonly Random _rnd = new();

        public static JA3Fingerprint GetFingerprint(BrowserJa3Profile profile, string custom = null)
        {
            if (profile == BrowserJa3Profile.Custom)
            {
                if (string.IsNullOrWhiteSpace(custom)) throw new ArgumentNullException(nameof(custom));
                return JA3FingerprintParser.Parse(custom);
            }
            if (!Ja3Presets.TryGetValue(profile, out var presets) || presets.Length == 0)
                throw new NotSupportedException($"Profile {profile} not implemented.");
            var ja3 = presets[_rnd.Next(presets.Length)];
            return JA3FingerprintParser.Parse(ja3);
        }
    }
}
