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

using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceBlockListApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceBlockListApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region public
            public void GetBlockListStatus(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                BlockListZoneManager manager = _dnsWebService._dnsServer.BlockListZoneManager;

                jsonWriter.WriteNumber("totalBlockedDomains", manager.TotalZonesBlocked);
                jsonWriter.WriteNumber("totalAllowedDomains", manager.TotalZonesAllowed);
                jsonWriter.WriteString("blockListLastUpdatedOn", manager.BlockListLastUpdatedOn);
                jsonWriter.WriteBoolean("blockListUpdateEnabled", manager.BlockListUpdateEnabled);
                jsonWriter.WriteNumber("blockListUpdateIntervalHours", manager.BlockListUpdateIntervalHours);

                if (manager.BlockListUpdateEnabled)
                {
                    DateTime nextUpdate = manager.BlockListLastUpdatedOn.AddHours(manager.BlockListUpdateIntervalHours);
                    jsonWriter.WriteString("blockListNextUpdatedOn", nextUpdate);
                }

                // block lists array
                jsonWriter.WritePropertyName("blockLists");
                jsonWriter.WriteStartArray();

                foreach (BlockListUrlStatus status in manager.BlockListUrlStatuses)
                {
                    if (status.Type == "block")
                    {
                        jsonWriter.WriteStartObject();
                        jsonWriter.WriteString("url", status.Url);
                        jsonWriter.WriteString("type", status.Type);
                        jsonWriter.WriteNumber("domainCount", status.DomainCount);
                        jsonWriter.WriteString("lastUpdatedOn", status.LastUpdatedOn);
                        jsonWriter.WriteString("lastUpdateStatus", status.LastUpdateStatus);

                        if (status.LastErrorMessage is not null)
                            jsonWriter.WriteString("lastErrorMessage", status.LastErrorMessage);

                        jsonWriter.WriteEndObject();
                    }
                }

                jsonWriter.WriteEndArray();

                // allow lists array
                jsonWriter.WritePropertyName("allowLists");
                jsonWriter.WriteStartArray();

                foreach (BlockListUrlStatus status in manager.BlockListUrlStatuses)
                {
                    if (status.Type == "allow")
                    {
                        jsonWriter.WriteStartObject();
                        jsonWriter.WriteString("url", status.Url);
                        jsonWriter.WriteString("type", status.Type);
                        jsonWriter.WriteNumber("domainCount", status.DomainCount);
                        jsonWriter.WriteString("lastUpdatedOn", status.LastUpdatedOn);
                        jsonWriter.WriteString("lastUpdateStatus", status.LastUpdateStatus);

                        if (status.LastErrorMessage is not null)
                            jsonWriter.WriteString("lastErrorMessage", status.LastErrorMessage);

                        jsonWriter.WriteEndObject();
                    }
                }

                jsonWriter.WriteEndArray();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list status was retrieved.");
            }

            /// <summary>
            /// Checks a domain against the blocklist, following CNAME chains via recursive DNS resolution.
            /// Falls back to direct dictionary lookup on resolution failure or IP address input.
            /// </summary>
            public async Task CheckDomain(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                string domain = context.Request.GetQueryOrForm("domain")?.Trim();

                if (string.IsNullOrEmpty(domain))
                    throw new DnsWebServiceException("The 'domain' parameter is required.");

                domain = DnsUtils.NormalizeDomainInput(domain);

                if (DnsClient.IsDomainNameUnicode(domain))
                    domain = DnsClient.ConvertDomainNameToAscii(domain);

                domain = domain.ToLowerInvariant();

                BlockListZoneManager manager = _dnsWebService._dnsServer.BlockListZoneManager;
                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                // Check if the input is an IP address; skip resolution for IPs
                if (IPAddress.TryParse(domain, out _))
                {
                    // Direct lookup only for IP address input
                    // Check allowed-zone first (mirrors DNS pipeline), then blocklist
                    string ipAllowedBy = null;
                    AllowedZoneManager ipAllowedZoneManager = _dnsWebService._dnsServer.AllowedZoneManager;

                    if (ipAllowedZoneManager is not null)
                    {
                        DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN) });

                        if (ipAllowedZoneManager.IsAllowed(request))
                            ipAllowedBy = "allowed-zone";
                    }

                    BlockListDomainCheckResult domainResult = manager.CheckDomain(domain);
                    BlockListAllowCheckResult allowResult = manager.CheckAllowList(domain);

                    // Apply AllowedZone or allowlist overrides to isBlocked
                    bool ipIsBlocked = domainResult.IsBlocked;
                    if (ipAllowedBy == "allowed-zone" || allowResult.IsAllowed)
                        ipIsBlocked = false;

                    jsonWriter.WriteString("domain", domainResult.Domain);
                    jsonWriter.WriteBoolean("isBlocked", ipIsBlocked);

                    if (ipIsBlocked)
                    {
                        jsonWriter.WriteString("matchedBlockedDomain", domainResult.BlockedDomain);
                        jsonWriter.WritePropertyName("blockListUrls");
                        jsonWriter.WriteStartArray();

                        foreach (string url in domainResult.BlockListUrls)
                            jsonWriter.WriteStringValue(url);

                        jsonWriter.WriteEndArray();
                    }

                    bool ipIsAllowed = allowResult.IsAllowed || (ipAllowedBy == "allowed-zone");
                    jsonWriter.WriteBoolean("isAllowed", ipIsAllowed);

                    if (allowResult.IsAllowed)
                    {
                        jsonWriter.WriteString("matchedAllowedDomain", allowResult.AllowedDomain);
                        if (ipAllowedBy is null)
                            ipAllowedBy = "blocklist";
                    }

                    if (ipAllowedBy is not null)
                        jsonWriter.WriteString("allowedBy", ipAllowedBy);

                    // Emit an empty chain for IP address inputs
                    jsonWriter.WritePropertyName("chain");
                    jsonWriter.WriteStartArray();
                    jsonWriter.WriteEndArray();

                    string logDomain = new string(domain.Where(c => !char.IsControl(c)).ToArray());
                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list domain check (IP): " + logDomain);
                    return;
                }

                // Attempt CNAME chain resolution, falling back to direct lookup on failure
                List<CnameChainEntry> chain;
                string resolutionError = null;

                try
                {
                    DnsServer dnsServer = _dnsWebService._dnsServer;
                    NetProxy proxy = dnsServer.Proxy;
                    IPv6Mode ipv6Mode = dnsServer.IPv6Mode;
                    ushort udpPayloadSize = dnsServer.UdpPayloadSize;
                    bool randomizeName = dnsServer.RandomizeName;
                    bool qnameMinimization = dnsServer.QnameMinimization;

                    CnameChainResolver resolver = new CnameChainResolver(
                        new DnsResolverAdapter(dnsServer),
                        DnsServer.MAX_CNAME_HOPS);

                    chain = await resolver.ResolveCnameChainAsync(
                        domain, proxy, ipv6Mode, udpPayloadSize,
                        randomizeName, qnameMinimization,
                        CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list CNAME resolution error for '" + domain + "': " + ex.ToString());
                    chain = null;
                    resolutionError = ex.Message;
                }

                if ((chain is null) || (chain.Count == 0))
                {
                    // Fall back to direct dictionary lookup (current behavior)
                    // Check allowed-zone first (mirrors DNS pipeline), then blocklist
                    string fbAllowedBy = null;
                    AllowedZoneManager fbAllowedZoneManager = _dnsWebService._dnsServer.AllowedZoneManager;

                    if (fbAllowedZoneManager is not null)
                    {
                        DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN) });

                        if (fbAllowedZoneManager.IsAllowed(request))
                            fbAllowedBy = "allowed-zone";
                    }

                    BlockListDomainCheckResult domainResult = manager.CheckDomain(domain);
                    BlockListAllowCheckResult allowResult = manager.CheckAllowList(domain);

                    jsonWriter.WriteString("domain", domainResult.Domain);
                    jsonWriter.WriteBoolean("isBlocked", domainResult.IsBlocked);

                    if (domainResult.IsBlocked)
                    {
                        jsonWriter.WriteString("matchedBlockedDomain", domainResult.BlockedDomain);
                        jsonWriter.WritePropertyName("blockListUrls");
                        jsonWriter.WriteStartArray();

                        foreach (string url in domainResult.BlockListUrls)
                            jsonWriter.WriteStringValue(url);

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteBoolean("isAllowed", allowResult.IsAllowed);

                    if (allowResult.IsAllowed)
                    {
                        jsonWriter.WriteString("matchedAllowedDomain", allowResult.AllowedDomain);
                        if (fbAllowedBy is null)
                            fbAllowedBy = "blocklist";
                    }

                    if (fbAllowedBy is not null)
                        jsonWriter.WriteString("allowedBy", fbAllowedBy);

                    // Emit chain array (empty for fallback)
                    jsonWriter.WritePropertyName("chain");
                    jsonWriter.WriteStartArray();
                    jsonWriter.WriteEndArray();

                    if (resolutionError is not null)
                        jsonWriter.WriteString("resolutionError", resolutionError);

                    string logDomain = new string(domain.Where(c => !char.IsControl(c)).ToArray());
                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list domain check (fallback): " + logDomain);
                    return;
                }

                // Check each domain in the CNAME chain against blocklist and allowlist
                string overallBlockedDomain = null;
                List<string> overallBlockListUrls = new List<string>();
                bool isAllowed = false;
                string matchedAllowedDomain = null;
                string allowedBy = null;
                AllowedZoneManager allowedZoneManager = _dnsWebService._dnsServer.AllowedZoneManager;

                foreach (CnameChainEntry entry in chain)
                {
                    string checkDomain = entry.Target ?? entry.Domain;

                    BlockListDomainCheckResult domainResult = manager.CheckDomain(checkDomain);
                    BlockListAllowCheckResult allowResult = manager.CheckAllowList(checkDomain);

                    entry.IsBlocked = domainResult.IsBlocked;
                    entry.IsAllowed = allowResult.IsAllowed;

                    if (domainResult.IsBlocked)
                    {
                        entry.BlockedDomain = domainResult.BlockedDomain;
                        entry.BlockListUrls = domainResult.BlockListUrls;
                    }

                    // Allowlist overrides blocklist at each level; track the overall result
                    if (allowResult.IsAllowed)
                    {
                        entry.IsBlocked = false;
                        isAllowed = true;
                        matchedAllowedDomain = allowResult.AllowedDomain;
                        if (allowedBy is null)
                            allowedBy = "blocklist";
                    }

                    if (domainResult.IsBlocked && !allowResult.IsAllowed)
                    {
                        if (overallBlockedDomain is null)
                        {
                            overallBlockedDomain = domainResult.BlockedDomain;
                            overallBlockListUrls.AddRange(domainResult.BlockListUrls);
                        }
                    }
                }

                // Determine the final target domain in the chain (last entry's Target or Domain)
                CnameChainEntry lastEntry = chain[chain.Count - 1];
                string finalTargetDomain = lastEntry.Target ?? lastEntry.Domain;

                // Check the final target against AllowedZoneManager
                // Allow/block determination happens at the final target only
                if (allowedZoneManager is not null)
                {
                    DnsDatagram finalRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(finalTargetDomain, DnsResourceRecordType.A, DnsClass.IN) });

                    if (allowedZoneManager.IsAllowed(finalRequest))
                    {
                        allowedBy = "allowed-zone";
                        isAllowed = true;
                        matchedAllowedDomain = finalTargetDomain;
                    }
                }

                bool isBlocked = overallBlockedDomain is not null;

                // Final target allowed overrides block
                if (isAllowed && allowedBy == "allowed-zone")
                    isBlocked = false;

                // Write the JSON response
                jsonWriter.WriteString("domain", domain);
                jsonWriter.WriteBoolean("isBlocked", isBlocked);

                if (isBlocked)
                {
                    jsonWriter.WriteString("matchedBlockedDomain", overallBlockedDomain);
                    jsonWriter.WritePropertyName("blockListUrls");
                    jsonWriter.WriteStartArray();

                    foreach (string url in overallBlockListUrls)
                        jsonWriter.WriteStringValue(url);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteBoolean("isAllowed", isAllowed);

                if (isAllowed)
                    jsonWriter.WriteString("matchedAllowedDomain", matchedAllowedDomain);

                if (allowedBy is not null)
                    jsonWriter.WriteString("allowedBy", allowedBy);

                // Write the CNAME chain
                jsonWriter.WritePropertyName("chain");
                jsonWriter.WriteStartArray();

                foreach (CnameChainEntry entry in chain)
                {
                    jsonWriter.WriteStartObject();
                    jsonWriter.WriteString("domain", entry.Domain);
                    jsonWriter.WriteString("type", entry.Type);

                    if (entry.Target is not null)
                        jsonWriter.WriteString("target", entry.Target);

                    jsonWriter.WriteBoolean("isBlocked", entry.IsBlocked);
                    jsonWriter.WriteBoolean("isAllowed", entry.IsAllowed);

                    if (entry.IsBlocked)
                    {
                        jsonWriter.WriteString("blockedDomain", entry.BlockedDomain);
                        jsonWriter.WritePropertyName("blockListUrls");
                        jsonWriter.WriteStartArray();

                        if (entry.BlockListUrls is not null)
                        {
                            foreach (string url in entry.BlockListUrls)
                                jsonWriter.WriteStringValue(url);
                        }

                        jsonWriter.WriteEndArray();
                    }

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                string safeLogDomain = new string(domain.Where(c => !char.IsControl(c)).ToArray());
                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list domain check: " + safeLogDomain);
            }

            #endregion

            #region private

            /// <summary>
            /// Adapter that wraps DnsServer to implement IDnsResolver for CNAME chain resolution.
            /// </summary>
            sealed class DnsResolverAdapter : IDnsResolver
            {
                private readonly DnsServer _dnsServer;

                public DnsResolverAdapter(DnsServer dnsServer)
                {
                    _dnsServer = dnsServer;
                }

                public async Task<DnsDatagram> RecursiveResolveAsync(
                    DnsQuestionRecord question,
                    DnsCache cache,
                    NetProxy proxy,
                    IPv6Mode ipv6Mode,
                    ushort udpPayloadSize,
                    bool randomizeName,
                    bool qnameMinimization,
                    bool skipDnsAppAuthoritativeRequestHandlers,
                    CancellationToken cancellationToken)
                {
                    return await TechnitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken ct)
                    {
                        return await DnsClient.RecursiveResolveAsync(
                            question, cache, proxy, ipv6Mode, udpPayloadSize,
                            randomizeName, qnameMinimization, false, null, 1, 10000,
                            cancellationToken: ct);
                    }, DnsServer.RECURSIVE_RESOLUTION_TIMEOUT);
                }
            }

            #endregion
        }
    }
}
