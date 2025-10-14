using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;

namespace Moljave.Http
{
    public sealed class MojaveCookieManager
    {
        private readonly object _syncRoot = new();
        private CookieContainer _container;

        public MojaveCookieManager()
            : this(new CookieContainer())
        {
        }

        public MojaveCookieManager(CookieContainer container)
        {
            _container = container ?? new CookieContainer();
        }

        public CookieCollection GetCookies(Uri uri)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            lock (_syncRoot)
            {
                var collection = _container.GetCookies(uri);
                var cloned = new CookieCollection();
                foreach (Cookie cookie in collection)
                {
                    cloned.Add(CloneCookie(cookie));
                }

                return cloned;
            }
        }

        public string GetCookieHeader(Uri uri)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            lock (_syncRoot)
            {
                return _container.GetCookieHeader(uri);
            }
        }

        public void SetCookie(Uri uri, Cookie cookie)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (cookie == null)
            {
                throw new ArgumentNullException(nameof(cookie));
            }

            lock (_syncRoot)
            {
                _container.Add(uri, cookie);
            }
        }

        public void SetCookie(string domain, string name, string value, string path = "/", DateTime? expires = null, bool? secure = null, bool? httpOnly = null)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentNullException(nameof(domain));
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentNullException(nameof(name));
            }

            var cookie = new Cookie(name, value ?? string.Empty, string.IsNullOrEmpty(path) ? "/" : path, domain);

            if (expires.HasValue)
            {
                cookie.Expires = expires.Value;
            }

            if (secure.HasValue)
            {
                cookie.Secure = secure.Value;
            }

            if (httpOnly.HasValue)
            {
                cookie.HttpOnly = httpOnly.Value;
            }

            lock (_syncRoot)
            {
                _container.Add(cookie);
            }
        }

        public void RemoveCookie(string domain, string name, string path = "/")
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentNullException(nameof(domain));
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentNullException(nameof(name));
            }

            var cookie = new Cookie(name, string.Empty, string.IsNullOrEmpty(path) ? "/" : path, domain)
            {
                Expires = DateTime.UtcNow.AddYears(-1)
            };

            lock (_syncRoot)
            {
                _container.Add(cookie);
            }
        }

        public void ClearAll()
        {
            lock (_syncRoot)
            {
                _container = new CookieContainer();
            }
        }

        public void ClearDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentNullException(nameof(domain));
            }

            lock (_syncRoot)
            {
                var updated = new CookieContainer();
                foreach (var cookie in EnumerateCookiesInternal())
                {
                    if (!IsDomainMatch(cookie.Domain, domain))
                    {
                        updated.Add(CloneCookie(cookie));
                    }
                }

                _container = updated;
            }
        }

        public void ClearDomain(Uri uri)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            ClearDomain(uri.Host);
        }

        public void ReplaceWith(CookieContainer container)
        {
            lock (_syncRoot)
            {
                _container = container ?? new CookieContainer();
            }
        }

        internal CookieContainer GetInternalContainer()
        {
            lock (_syncRoot)
            {
                return _container;
            }
        }

        internal void UpdateFromSetCookieHeaders(Uri uri, IEnumerable<string> setCookieHeaders)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (setCookieHeaders == null)
            {
                return;
            }

            lock (_syncRoot)
            {
                foreach (var header in setCookieHeaders.Where(h => !string.IsNullOrWhiteSpace(h)))
                {
                    _container.SetCookies(uri, header);
                }
            }
        }

        private IEnumerable<Cookie> EnumerateCookiesInternal()
        {
            var domainTableField = typeof(CookieContainer).GetField("m_domainTable", BindingFlags.NonPublic | BindingFlags.Instance);
            if (domainTableField == null)
            {
                yield break;
            }

            var domainTable = domainTableField.GetValue(_container) as Hashtable;
            if (domainTable == null)
            {
                yield break;
            }

            foreach (DictionaryEntry entry in domainTable)
            {
                var pathList = entry.Value;
                var pathListType = pathList.GetType();
                var listField = pathListType.GetField("m_list", BindingFlags.NonPublic | BindingFlags.Instance);
                if (listField?.GetValue(pathList) is not SortedList paths)
                {
                    continue;
                }

                foreach (DictionaryEntry pathEntry in paths)
                {
                    if (pathEntry.Value is CookieCollection cookies)
                    {
                        foreach (Cookie cookie in cookies)
                        {
                            yield return cookie;
                        }
                    }
                }
            }
        }

        private static Cookie CloneCookie(Cookie cookie)
        {
            return new Cookie(cookie?.Name ?? string.Empty, cookie?.Value ?? string.Empty, cookie?.Path ?? "/", cookie?.Domain ?? string.Empty)
            {
                Expires = cookie?.Expires ?? DateTime.MinValue,
                HttpOnly = cookie?.HttpOnly ?? false,
                Secure = cookie?.Secure ?? false
            };
        }

        private static bool IsDomainMatch(string cookieDomain, string targetDomain)
        {
            if (string.IsNullOrWhiteSpace(cookieDomain) || string.IsNullOrWhiteSpace(targetDomain))
            {
                return false;
            }

            var normalizedCookie = NormalizeDomain(cookieDomain);
            var normalizedTarget = NormalizeDomain(targetDomain);

            if (string.Equals(normalizedCookie, normalizedTarget, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return normalizedCookie.EndsWith("." + normalizedTarget, StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                return string.Empty;
            }

            return domain.Trim().TrimStart('.').ToLowerInvariant();
        }
    }
}
