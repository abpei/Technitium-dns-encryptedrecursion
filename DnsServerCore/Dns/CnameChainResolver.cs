/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;
using DnsServerCore.Dns.ZoneManagers;

namespace DnsServerCore.Dns
{
    /// <summary>
    /// Interface for DNS resolution, allowing mock implementations in tests.
    /// </summary>
    public interface IDnsResolver
    {
        Task<DnsDatagram> RecursiveResolveAsync(
            DnsQuestionRecord question,
            DnsCache cache,
            NetProxy proxy,
            IPv6Mode ipv6Mode,
            ushort udpPayloadSize,
            bool randomizeName,
            bool qnameMinimization,
            bool skipDnsAppAuthoritativeRequestHandlers,
            CancellationToken cancellationToken);
    }

    /// <summary>
    /// Represents a single entry in a CNAME resolution chain.
    /// </summary>
    public sealed class CnameChainEntry
    {
        public string Domain { get; set; }
        public string Type { get; set; }
        public string Target { get; set; }
        public bool IsBlocked { get; set; }
        public bool IsAllowed { get; set; }
        public string BlockedDomain { get; set; }
        public IReadOnlyList<string> BlockListUrls { get; set; }
    }

    /// <summary>
    /// Resolves CNAME chains for domain lookup, with support for loop detection.
    /// Optionally checks AllowedZoneManager and BlockListZoneManager at each hop.
    /// </summary>
    public sealed class CnameChainResolver
    {
        private readonly IDnsResolver _dnsResolver;
        private readonly int _maxCnameHops;
        private readonly AllowedZoneManager _allowedZoneManager;
        private readonly BlockListZoneManager _blockListZoneManager;

        public CnameChainResolver(IDnsResolver dnsResolver, int maxCnameHops = 16, AllowedZoneManager allowedZoneManager = null, BlockListZoneManager blockListZoneManager = null)
        {
            _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
            _maxCnameHops = maxCnameHops;
            _allowedZoneManager = allowedZoneManager;
            _blockListZoneManager = blockListZoneManager;
        }

        /// <summary>
        /// Checks if a domain is allowed by the AllowedZoneManager or BlockListZoneManager.
        /// Mirrors the DNS pipeline pattern: AllowedZoneManager.IsAllowed(request) || BlockListZoneManager.IsAllowed(request).
        /// </summary>
        private bool IsDomainAllowed(string domain)
        {
            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN) });

            if (_allowedZoneManager is not null && _allowedZoneManager.IsAllowed(request))
                return true;

            if (_blockListZoneManager is not null && _blockListZoneManager.IsAllowed(request))
                return true;

            return false;
        }

        /// <summary>
        /// Resolves a domain via the recursive resolver and extracts the full CNAME chain from the answer section.
        /// Returns null on resolution failure or when no CNAME records are found.
        /// </summary>
        public async Task<List<CnameChainEntry>> ResolveCnameChainAsync(
            string domain,
            NetProxy proxy,
            IPv6Mode ipv6Mode,
            ushort udpPayloadSize,
            bool randomizeName,
            bool qnameMinimization,
            CancellationToken cancellationToken)
        {
            DnsQuestionRecord question = new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN);

            DnsCache dnsCache = new DnsCache();
            dnsCache.MinimumRecordTtl = 0;
            dnsCache.MaximumRecordTtl = 7 * 24 * 60 * 60;

            DnsDatagram dnsResponse;

            try
            {
                dnsResponse = await _dnsResolver.RecursiveResolveAsync(
                    question, dnsCache, proxy, ipv6Mode, udpPayloadSize,
                    randomizeName, qnameMinimization, false, cancellationToken);
            }
            catch
            {
                // Resolution failed (timeout, SERVFAIL, NXDOMAIN, etc.)
                return null;
            }

            if ((dnsResponse is null) || (dnsResponse.Answer is null) || (dnsResponse.Answer.Count == 0))
                return null;

            // Extract the CNAME chain from the Answer section
            List<CnameChainEntry> chain = new List<CnameChainEntry>();
            HashSet<string> seenDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int hops = 0;

            foreach (DnsResourceRecord record in dnsResponse.Answer)
            {
                if (hops >= _maxCnameHops)
                    break;

                if (record.Type == DnsResourceRecordType.CNAME)
                {
                    if (record.RDATA is DnsCNAMERecordData cnameData)
                    {
                        string targetDomain = cnameData.Domain;

                        // Detect CNAME loop
                        if (!seenDomains.Add(targetDomain))
                            break; // loop detected

                        bool isAllowed = IsDomainAllowed(targetDomain);

                        chain.Add(new CnameChainEntry
                        {
                            Domain = record.Name,
                            Type = "CNAME",
                            Target = targetDomain,
                            IsAllowed = isAllowed
                        });

                        hops++;
                    }
                }
                else if (record.Type == DnsResourceRecordType.A || record.Type == DnsResourceRecordType.AAAA)
                {
                    // Final record in the chain
                    bool isAllowed = IsDomainAllowed(record.Name);

                    chain.Add(new CnameChainEntry
                    {
                        Domain = record.Name,
                        Type = record.Type.ToString(),
                        IsAllowed = isAllowed
                    });

                    break; // stop at the first non-CNAME record
                }
            }

            // If no CNAME records were found in the answer, return null so the caller falls back to direct lookup
            // Check if we have any CNAME entries (not just A/AAAA records)
            if (!chain.Any(e => e.Type == "CNAME"))
                return null;

            // If we have CNAME records but the chain ends without a final A/AAAA record,
            // the last CNAME target should also be checked as a terminal entry.
            // Note: seenDomains already contains every CNAME target from chain construction,
            // so a seenDomains guard here would suppress this terminal entry entirely.
            // The terminal entry is appended unconditionally so the final CNAME target
            // always reaches the blocklist/allowlist check.
            if (chain.All(e => e.Type == "CNAME"))
            {
                string lastTarget = chain[chain.Count - 1].Target;
                bool isAllowed = IsDomainAllowed(lastTarget);

                chain.Add(new CnameChainEntry
                {
                    Domain = lastTarget,
                    Type = "A",
                    IsAllowed = isAllowed
                });
            }

            return chain;
        }
    }
}
