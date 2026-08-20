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
            $("#lblBlockListsTotalBlocked").text(responseJSON.response.totalBlockedDomains);
            $("#lblBlockListsTotalAllowed").text(responseJSON.response.totalAllowedDomains);

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
                    blockLists[i].domainCount + "</td><td>" +
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
                    allowLists[i].domainCount + "</td><td>" +
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

            if (responseJSON.response.isBlocked) {
                resultHtml += "<div class=\"alert alert-danger\" style=\"margin-bottom: 5px;\"><b>BLOCKED</b> — matched domain: " + htmlEncode(responseJSON.response.matchedBlockedDomain) + "<br/>Block list sources:<ul>";
                if (responseJSON.response.blockListUrls) {
                    for (var i = 0; i < responseJSON.response.blockListUrls.length; i++)
                        resultHtml += "<li>" + htmlEncode(responseJSON.response.blockListUrls[i]) + "</li>";
                }
                resultHtml += "</ul></div>";
            } else {
                resultHtml += "<div class=\"alert alert-success\" style=\"margin-bottom: 5px;\"><b>NOT BLOCKED</b> — the domain is not in any block list.</div>";
            }

            if (responseJSON.response.isAllowed)
                resultHtml += "<div class=\"alert alert-info\"><b>ALLOWED</b> — matched domain: " + htmlEncode(responseJSON.response.matchedAllowedDomain) + "</div>";

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
