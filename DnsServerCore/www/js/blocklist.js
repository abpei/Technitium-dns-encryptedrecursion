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

function refreshBlockLists() {
    var node = $("#optBlockListsClusterNode").val();
    localStorage.setItem("blockListsClusterNode", node);

    var divBlockListsLoader = $("#divBlockListsLoader");
    var divBlockLists = $("#divBlockLists");

    divBlockLists.hide();
    divBlockListsLoader.show();

    HTTPRequest({
        url: "api/blockList/getStatus?node=" + encodeURIComponent(node),
        token: sessionData.token,
        success: function (responseJSON) {
            var blockLists = responseJSON.response.blockLists;
            var allowLists = responseJSON.response.allowLists;

            // summary
            $("#lblBlockListsTotalBlocked").text(responseJSON.response.totalBlockedDomains.toLocaleString());
            $("#lblBlockListsTotalAllowed").text(responseJSON.response.totalAllowedDomains.toLocaleString());

            if (responseJSON.response.blockListLastUpdatedOn)
                $("#lblBlockListsLastUpdated").text(moment(responseJSON.response.blockListLastUpdatedOn).local().format("YYYY-MM-DD HH:mm"));
            else
                $("#lblBlockListsLastUpdated").text("-");

            if (responseJSON.response.blockListNextUpdatedOn)
                $("#lblBlockListsNextUpdated").text(moment(responseJSON.response.blockListNextUpdatedOn).local().format("YYYY-MM-DD HH:mm"));
            else
                $("#lblBlockListsNextUpdated").text("-");

            // block lists table
            var blockListHtmlRows = "";
            for (var i = 0; i < blockLists.length; i++) {
                blockListHtmlRows += "<tr><td>" + htmlEncode(blockLists[i].url) + "</td><td>" +
                    htmlEncode(blockLists[i].type) + "</td><td>" +
                    blockLists[i].domainCount.toLocaleString() + "</td><td>" +
                    (blockLists[i].lastUpdatedOn ? moment(blockLists[i].lastUpdatedOn).local().format("YYYY-MM-DD HH:mm") : "-") + "</td><td>" +
                    formatBlockListStatus(blockLists[i].lastUpdateStatus) + "</td><td>" +
                    (blockLists[i].lastErrorMessage ? htmlEncode(blockLists[i].lastErrorMessage) : "-") + "</td></tr>";
            }

            $("#tableBlockListsBody").html(blockListHtmlRows);

            if (blockLists.length > 0)
                $("#tableBlockListsFooter").html("<tr><td colspan=\"6\"><b>Total Block Lists: " + blockLists.length + "</b></td></tr>");
            else
                $("#tableBlockListsFooter").html("<tr><td colspan=\"6\" align=\"center\">No Block Lists Found</td></tr>");

            // allow lists table
            var allowListHtmlRows = "";
            for (var i = 0; i < allowLists.length; i++) {
                allowListHtmlRows += "<tr><td>" + htmlEncode(allowLists[i].url) + "</td><td>" +
                    htmlEncode(allowLists[i].type) + "</td><td>" +
                    allowLists[i].domainCount.toLocaleString() + "</td><td>" +
                    (allowLists[i].lastUpdatedOn ? moment(allowLists[i].lastUpdatedOn).local().format("YYYY-MM-DD HH:mm") : "-") + "</td><td>" +
                    formatBlockListStatus(allowLists[i].lastUpdateStatus) + "</td><td>" +
                    (allowLists[i].lastErrorMessage ? htmlEncode(allowLists[i].lastErrorMessage) : "-") + "</td></tr>";
            }

            $("#tableAllowListsBody").html(allowListHtmlRows);

            if (allowLists.length > 0)
                $("#tableAllowListsFooter").html("<tr><td colspan=\"6\"><b>Total Allow Lists: " + allowLists.length + "</b></td></tr>");
            else
                $("#tableAllowListsFooter").html("<tr><td colspan=\"6\" align=\"center\">No Allow Lists Found</td></tr>");

            divBlockListsLoader.hide();
            divBlockLists.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divBlockListsLoader
    });
}

// Format the allowedBy field into a human-readable label
function formatAllowedBySource(allowedBy) {
    switch (allowedBy) {
        case "allowed-zone":
            return "Allowed Zone";
        case "blocklist":
            return "Blocklist Allowlist";
        default:
            return "";
    }
}

function formatBlockListStatus(status) {
    switch (status) {
        case "success":
            return "<span class=\"label label-success\">Success</span>";
        case "notModified":
            return "<span class=\"label label-default\">Not Modified</span>";
        case "failed":
            return "<span class=\"label label-danger\">Failed</span>";
        default:
            return "<span class=\"label label-default\">" + htmlEncode(status || "Unknown") + "</span>";
    }
}

function checkBlockListDomain() {
    var domain = $("#txtBlockListDomainChecker").val().trim().toLowerCase();

    if (domain === "") {
        showAlert("warning", "Warning!", "Please enter a domain to check.");
        return;
    }

    var node = $("#optBlockListsClusterNode").val();
    var btn = $("#btnBlockListCheckDomain");
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='img/loader-small.gif'/>");

    var divResult = $("#divBlockListCheckResult");

    HTTPRequest({
        url: "api/blockList/checkDomain?domain=" + encodeURIComponent(domain) + "&node=" + encodeURIComponent(node),
        token: sessionData.token,
        success: function (responseJSON) {
            var resultHtml = "";
            var resp = responseJSON.response;

            // Overall result banner
            if (resp.isBlocked && resp.isAllowed) {
                var allowedSource = formatAllowedBySource(resp.allowedBy);
                resultHtml += "<div class=\"alert alert-success\" style=\"margin-bottom: 5px;\"><b>ALLOWED</b> — matched domain: " + htmlEncode(resp.matchedAllowedDomain);
                if (allowedSource)
                    resultHtml += " (source: " + htmlEncode(allowedSource) + ")";
                resultHtml += "<br/>Note: domain is in a block list (" + htmlEncode(resp.matchedBlockedDomain) + ") but the allow rule takes precedence.<br/>Block list sources:";
                if (resp.blockListUrls) {
                    resultHtml += "<ul>";
                    for (var i = 0; i < resp.blockListUrls.length; i++)
                        resultHtml += "<li>" + htmlEncode(resp.blockListUrls[i]) + "</li>";
                    resultHtml += "</ul>";
                }
                resultHtml += "</div>";
            } else if (resp.isBlocked) {
                resultHtml += "<div class=\"alert alert-danger\" style=\"margin-bottom: 5px;\"><b>BLOCKED</b> — matched domain: " + htmlEncode(resp.matchedBlockedDomain) + "<br/>Block list sources:<ul>";
                if (resp.blockListUrls) {
                    for (var i = 0; i < resp.blockListUrls.length; i++)
                        resultHtml += "<li>" + htmlEncode(resp.blockListUrls[i]) + "</li>";
                }
                resultHtml += "</ul></div>";
            } else {
                resultHtml += "<div class=\"alert alert-success\" style=\"margin-bottom: 5px;\"><b>NOT BLOCKED</b> — the domain is not in any block list.</div>";
            }

            if (resp.isAllowed && !resp.isBlocked) {
                var allowedSource = formatAllowedBySource(resp.allowedBy);
                resultHtml += "<div class=\"alert alert-info\"><b>ALLOWED</b> — matched domain: " + htmlEncode(resp.matchedAllowedDomain);
                if (allowedSource)
                    resultHtml += " (source: " + htmlEncode(allowedSource) + ")";
                resultHtml += "</div>";
            }

            // Resolution error warning
            if (resp.resolutionError) {
                resultHtml += "<div class=\"alert alert-warning\" style=\"margin-bottom: 5px;\"><b>Resolution Error:</b> " + htmlEncode(resp.resolutionError) + " — falling back to direct lookup.</div>";
            }

            // CNAME chain display (backward compatible: only if chain exists and is non-empty)
            var chain = resp.chain;
            if (chain && chain.length > 0) {
                resultHtml += "<div style=\"margin-top: 8px;\"><b>CNAME Resolution Chain:</b></div>";
                resultHtml += "<table class=\"table table-bordered table-condensed\" style=\"margin-bottom: 5px; font-size: 12px;\">";
                resultHtml += "<thead><tr><th>Domain</th><th>Type</th><th>Target</th><th>Status</th><th>Blocked By</th><th>Block Lists</th><th>Allowed By</th></tr></thead>";
                resultHtml += "<tbody>";

                for (var i = 0; i < chain.length; i++) {
                    var entry = chain[i];

                    // Determine row highlighting: highlight the entry where the block/allow match occurred
                    var rowClass = "";
                    if (entry.isBlocked && !entry.isAllowed) {
                        rowClass = " class=\"danger\"";
                    } else if (entry.isAllowed) {
                        rowClass = " class=\"success\"";
                    }

                    resultHtml += "<tr" + rowClass + ">";

                    // Domain name
                    resultHtml += "<td>" + htmlEncode(entry.domain) + "</td>";

                    // Record type
                    resultHtml += "<td>" + htmlEncode(entry.type) + "</td>";

                    // Target (for CNAME entries)
                    resultHtml += "<td>" + (entry.target ? htmlEncode(entry.target) : "-") + "</td>";

                    // Status indicator
                    if (entry.isBlocked && !entry.isAllowed) {
                        resultHtml += "<td><span class=\"label label-danger\">BLOCKED</span></td>";
                    } else if (entry.isAllowed) {
                        resultHtml += "<td><span class=\"label label-info\">ALLOWED</span></td>";
                    } else {
                        resultHtml += "<td><span class=\"label label-default\">OK</span></td>";
                    }

                    // Blocked by domain
                    if (entry.isBlocked) {
                        resultHtml += "<td>" + htmlEncode(entry.blockedDomain || "-") + "</td>";
                    } else {
                        resultHtml += "<td>-</td>";
                    }

                    // Block list URLs
                    if (entry.isBlocked && entry.blockListUrls && entry.blockListUrls.length > 0) {
                        resultHtml += "<td>";
                        for (var j = 0; j < entry.blockListUrls.length; j++) {
                            if (j > 0) resultHtml += "<br/>";
                            resultHtml += htmlEncode(entry.blockListUrls[j]);
                        }
                        resultHtml += "</td>";
                    } else {
                        resultHtml += "<td>-</td>";
                    }

                    // Allowed by source
                    if (entry.isAllowed && entry.allowedBy) {
                        var allowedSource = formatAllowedBySource(entry.allowedBy);
                        resultHtml += "<td><span class=\"label label-info\">" + htmlEncode(allowedSource) + "</span></td>";
                    } else {
                        resultHtml += "<td>-</td>";
                    }

                    resultHtml += "</tr>";
                }

                resultHtml += "</tbody></table>";
            }

            divResult.html(resultHtml);

            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        }
    });
}
