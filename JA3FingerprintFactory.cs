using System;

namespace Moljave.Http
{
    public enum Ja3Preset
    {
        Disabled,
        Default,
        Chrome
    }

    public static class JA3FingerprintFactory
    {
        private static readonly JA3Fingerprint[] s_defaultPreset =
        {
            JA3Fingerprint.Default
        };

        private static readonly Lazy<JA3Fingerprint[]> s_chromePreset = new(() => new[]
        {
            JA3FingerprintParser.Parse("771,4866-4867-4865-49195-49199-49196-49200-49171-49172-49199-52393-52392-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-41-28-19,29-23-24,0"),
            JA3FingerprintParser.Parse("771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-49199-49195-49196-52394-49172-49171-156-157-57-47-53,0-10-11-35-13-18-23-45-51-16-65281-27-43-28-29-41-65037-17513,29-23-24,0"),
            JA3FingerprintParser.Parse("771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49188-49192-49187-49191-49162-49172-156-157-47-53,0-10-11-13-16-18-23-27-28-29-35-43-45-51-17513-0,23-24,0")
        });

        public static JA3Fingerprint GetFingerprint(Ja3Preset preset)
        {
            return preset switch
            {
                Ja3Preset.Disabled => null,
                Ja3Preset.Default => s_defaultPreset[0],
                Ja3Preset.Chrome =>
                    GetRandomChromeFingerprint(),
                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, "Unknown JA3 preset.")
            };
        }

        private static JA3Fingerprint GetRandomChromeFingerprint()
        {
            var presets = s_chromePreset.Value;
            if (presets.Length == 0)
            {
                throw new NotSupportedException("Chrome JA3 preset is not configured.");
            }

            return presets[Random.Shared.Next(presets.Length)];
        }
    }
}
