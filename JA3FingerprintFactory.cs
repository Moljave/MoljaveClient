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
            {
                BrowserJa3Profile.Chrome,
                new[]
                {
                    "771,4866-4867-4865-49195-49199-49196-49200-49171-49172-49199-52393-52392-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-41-28-19,29-23-24,0",
                    "771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-49199-49195-49196-52394-49172-49171-156-157-57-47-53,0-10-11-35-13-18-23-45-51-16-65281-27-43-28-29-41-65037-17513,29-23-24,0",
                    "771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49188-49192-49187-49191-49162-49172-156-157-47-53,0-10-11-13-16-18-23-27-28-29-35-43-45-51-17513-0,23-24,0"
                }
            },
            {
                BrowserJa3Profile.Custom,
                Array.Empty<string>()
            }
        };

        private static readonly Lazy<Dictionary<BrowserJa3Profile, JA3Fingerprint[]>> s_cachedFingerprints = new(() =>
        {
            var cache = new Dictionary<BrowserJa3Profile, JA3Fingerprint[]>(Ja3Presets.Count);

            foreach (var (profile, presets) in Ja3Presets)
            {
                if (presets == null || presets.Length == 0)
                {
                    cache[profile] = Array.Empty<JA3Fingerprint>();
                    continue;
                }

                var parsed = new JA3Fingerprint[presets.Length];
                for (int i = 0; i < presets.Length; i++)
                {
                    parsed[i] = JA3FingerprintParser.Parse(presets[i]);
                }

                cache[profile] = parsed;
            }

            return cache;
        });

        private static readonly Random _rnd = new();

        public static JA3Fingerprint GetFingerprint(BrowserJa3Profile profile, string custom = null)
        {
            if (profile == BrowserJa3Profile.Custom)
            {
                if (string.IsNullOrWhiteSpace(custom)) throw new ArgumentNullException(nameof(custom));
                return JA3FingerprintParser.Parse(custom);
            }
            if (!s_cachedFingerprints.Value.TryGetValue(profile, out var cachedFingerprints) || cachedFingerprints.Length == 0)
                throw new NotSupportedException($"Profile {profile} not implemented.");

            return cachedFingerprints[_rnd.Next(cachedFingerprints.Length)];
        }
    }
}
