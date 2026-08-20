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
using DnsServerCore.Dns.ZoneManagers;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

using TechnitiumLibrary.Net.Dns;

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

            public void CheckDomain(HttpContext context)
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

                BlockListDomainCheckResult domainResult = manager.CheckDomain(domain);
                BlockListAllowCheckResult allowResult = manager.CheckAllowList(domain);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

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
                    jsonWriter.WriteString("matchedAllowedDomain", allowResult.AllowedDomain);

                string logDomain = new string(domain.Where(c => !char.IsControl(c)).ToArray());
                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list domain check: " + logDomain);
            }

            #endregion
        }
    }
}
