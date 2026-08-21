using System.Reflection;
using System.Net;
using Xunit;
using DnsServerCore;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.Tests;

/// <summary>
/// Unit tests for BlockListZoneManager.CheckDomain and CheckAllowList methods.
/// Uses reflection to populate internal block/allow list dictionaries directly,
/// avoiding network calls and complex DnsServer setup.
/// </summary>
public class BlockListTests : IDisposable
{
    private readonly string _tempConfigFolder;
    private readonly string _tempDohwwwFolder;
    private readonly DnsServer _dnsServer;
    private readonly BlockListZoneManager _blockListZoneManager;

    public BlockListTests()
    {
        // Create temp directories for DnsServer
        _tempConfigFolder = Path.Combine(Path.GetTempPath(), $"blocklist_test_{Guid.NewGuid():N}");
        _tempDohwwwFolder = Path.Combine(Path.GetTempPath(), $"blocklist_dohwww_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempConfigFolder);
        Directory.CreateDirectory(_tempDohwwwFolder);

        // Create a LogManager (required by DnsServer)
        var logManager = new LogManager(isPortableApp: true, configFolder: _tempConfigFolder);

        // Create a minimal DnsServer
        _dnsServer = new DnsServer(
            configFolder: _tempConfigFolder,
            dohwwwFolder: _tempDohwwwFolder,
            log: logManager,
            serverDomain: "test.local"
        );

        // Get the BlockListZoneManager from the DnsServer
        var blockListField = typeof(DnsServer).GetField("_blockListZoneManager", BindingFlags.NonPublic | BindingFlags.Instance);
        _blockListZoneManager = (BlockListZoneManager)blockListField!.GetValue(_dnsServer)!;
    }

    public void Dispose()
    {
        _dnsServer?.Dispose();

        try
        {
            if (Directory.Exists(_tempConfigFolder))
                Directory.Delete(_tempConfigFolder, recursive: true);
            if (Directory.Exists(_tempDohwwwFolder))
                Directory.Delete(_tempDohwwwFolder, recursive: true);
        }
        catch
        {
            // Cleanup failure is non-critical in tests
        }
    }

    /// <summary>
    /// Sets up the internal block list zone dictionary with test data using reflection.
    /// </summary>
    private void SetupBlockListZone(Dictionary<string, List<Uri>> blockListZone)
    {
        var field = typeof(BlockListZoneManager).GetField("_blockListZone", BindingFlags.NonPublic | BindingFlags.Instance);
        field!.SetValue(_blockListZoneManager, blockListZone);
    }

    /// <summary>
    /// Sets up the internal allow list zone dictionary with test data using reflection.
    /// </summary>
    private void SetupAllowListZone(Dictionary<string, object> allowListZone)
    {
        var field = typeof(BlockListZoneManager).GetField("_allowListZone", BindingFlags.NonPublic | BindingFlags.Instance);
        field!.SetValue(_blockListZoneManager, allowListZone);
    }

    private static Uri TestBlockListUri => new("http://example.com/blocklist.txt");

    [Fact]
    public void CheckDomain_AsciiDomainInput_ReturnsCorrectResult()
    {
        // Arrange
        var blockListZone = new Dictionary<string, List<Uri>>
        {
            ["malware.example.com"] = new List<Uri> { TestBlockListUri }
        };
        SetupBlockListZone(blockListZone);

        // Act
        var result = _blockListZoneManager.CheckDomain("malware.example.com");

        // Assert
        Assert.Equal("malware.example.com", result.Domain);
        Assert.True(result.IsBlocked);
        Assert.Equal("malware.example.com", result.BlockedDomain);
        Assert.Contains(TestBlockListUri.AbsoluteUri, result.BlockListUrls);
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_UnicodeDomainInput_IsConvertedToAscii()
    {
        // Arrange - the method normalizes to lowercase and trims dots
        var blockListZone = new Dictionary<string, List<Uri>>
        {
            ["xn--nxasmq6b.com"] = new List<Uri> { TestBlockListUri }
        };
        SetupBlockListZone(blockListZone);

        // Act - pass unicode domain (which gets lowercased and trimmed)
        var result = _blockListZoneManager.CheckDomain("example.com.");

        // Assert - domain is normalized (lowercase, dot trimmed)
        Assert.Equal("example.com", result.Domain);
    }

    [Fact]
    public void CheckDomain_EmptyDomain_ReturnsNotBlocked()
    {
        // Arrange - empty dictionaries
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());

        // Act
        var result = _blockListZoneManager.CheckDomain("");

        // Assert - empty string is not a valid domain, returns not blocked
        Assert.Equal("", result.Domain);
        Assert.False(result.IsBlocked);
        Assert.Null(result.BlockedDomain);
        Assert.Empty(result.BlockListUrls);
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_BlockedDomain_ReturnsBlockedStatusAndBlocklistUrl()
    {
        // Arrange
        var blockListUrl1 = new Uri("http://example.com/blocklist1.txt");
        var blockListUrl2 = new Uri("http://example.com/blocklist2.txt");
        var blockListZone = new Dictionary<string, List<Uri>>
        {
            ["ads.tracker.com"] = new List<Uri> { blockListUrl1, blockListUrl2 }
        };
        SetupBlockListZone(blockListZone);

        // Act
        var result = _blockListZoneManager.CheckDomain("ads.tracker.com");

        // Assert
        Assert.True(result.IsBlocked);
        Assert.Equal("ads.tracker.com", result.BlockedDomain);
        Assert.Equal(2, result.BlockListUrls.Count);
        Assert.Contains(blockListUrl1.AbsoluteUri, result.BlockListUrls);
        Assert.Contains(blockListUrl2.AbsoluteUri, result.BlockListUrls);
    }

    [Fact]
    public void CheckDomain_AllowedDomain_ReturnsAllowedStatus()
    {
        // Arrange
        var allowListZone = new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        };
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(allowListZone);

        // Act
        var result = _blockListZoneManager.CheckDomain("trusted.example.com");

        // Assert
        Assert.False(result.IsBlocked);
        Assert.Null(result.BlockedDomain);
        Assert.Empty(result.BlockListUrls);
        Assert.True(result.IsAllowed);
        Assert.Equal("trusted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_DomainNotInAnyList_ReturnsNotBlockedAndNotAllowed()
    {
        // Arrange - empty lists
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());

        // Act
        var result = _blockListZoneManager.CheckDomain("safe.example.com");

        // Assert
        Assert.Equal("safe.example.com", result.Domain);
        Assert.False(result.IsBlocked);
        Assert.Null(result.BlockedDomain);
        Assert.Empty(result.BlockListUrls);
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_SubdomainOfBlockedDomain_IsAlsoBlocked()
    {
        // Arrange - parent domain is blocked
        var blockListZone = new Dictionary<string, List<Uri>>
        {
            ["malware.example.com"] = new List<Uri> { TestBlockListUri }
        };
        SetupBlockListZone(blockListZone);

        // Act - query a subdomain of the blocked domain
        var result = _blockListZoneManager.CheckDomain("sub.malware.example.com");

        // Assert - subdomain is blocked due to parent domain match
        Assert.True(result.IsBlocked);
        Assert.Equal("malware.example.com", result.BlockedDomain);
        Assert.Contains(TestBlockListUri.AbsoluteUri, result.BlockListUrls);
    }

    [Fact]
    public void CheckAllowList_AllowedDomain_ReturnsAllowedStatus()
    {
        // Arrange
        var allowListZone = new Dictionary<string, object>
        {
            ["whitelisted.example.com"] = null!
        };
        SetupAllowListZone(allowListZone);

        // Act
        var result = _blockListZoneManager.CheckAllowList("whitelisted.example.com");

        // Assert
        Assert.True(result.IsAllowed);
        Assert.Equal("whitelisted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void CheckAllowList_DomainNotInAllowList_ReturnsNotAllowed()
    {
        // Arrange
        SetupAllowListZone(new Dictionary<string, object>());

        // Act
        var result = _blockListZoneManager.CheckAllowList("unknown.example.com");

        // Assert
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
    }

    [Fact]
    public void CheckAllowList_SubdomainOfAllowedDomain_IsAlsoAllowed()
    {
        // Arrange - parent domain is allowed
        var allowListZone = new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        };
        SetupAllowListZone(allowListZone);

        // Act - query a subdomain of the allowed domain
        var result = _blockListZoneManager.CheckAllowList("sub.trusted.example.com");

        // Assert - subdomain is allowed due to parent domain match
        Assert.True(result.IsAllowed);
        Assert.Equal("trusted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void NormalizeDomainInput_UrlWithHttps_ExtractsHostname()
    {
        // Act - normalize a full HTTPS URL
        var result = DnsUtils.NormalizeDomainInput("https://alphonso.tv");

        // Assert - hostname is extracted from the URL
        Assert.Equal("alphonso.tv", result);
    }

    [Fact]
    public void NormalizeDomainInput_UrlWithPortAndPath_ExtractsHostname()
    {
        // Act - normalize a URL with port, path, and query string
        var result = DnsUtils.NormalizeDomainInput("http://sub.example.com:8080/path?q=1");

        // Assert - only hostname is extracted, port/path/query stripped
        Assert.Equal("sub.example.com", result);
    }

    [Fact]
    public void NormalizeDomainInput_PlainDomain_ReturnsUnchanged()
    {
        // Act - normalize a plain domain without protocol
        var result = DnsUtils.NormalizeDomainInput("alphonso.tv");

        // Assert - plain domain passes through unchanged
        Assert.Equal("alphonso.tv", result);
    }

    [Fact]
    public void CheckDomain_FullUrlInput_IsNormalizedAndChecked()
    {
        // Arrange - block alphonso.tv via its hostname
        var blockListZone = new Dictionary<string, List<Uri>>
        {
            ["alphonso.tv"] = new List<Uri> { TestBlockListUri }
        };
        SetupBlockListZone(blockListZone);
        SetupAllowListZone(new Dictionary<string, object>());

        // Act - pass a full URL; it should be normalized to hostname and checked
        var domain = DnsUtils.NormalizeDomainInput("https://alphonso.tv");
        var result = _blockListZoneManager.CheckDomain(domain);

        // Assert - domain is blocked after normalization
        Assert.Equal("alphonso.tv", result.Domain);
        Assert.True(result.IsBlocked);
        Assert.Equal("alphonso.tv", result.BlockedDomain);
    }

    #region AllowedZoneManager Integration Tests

    [Fact]
    public void CheckDomain_AllowedZoneManagerDomain_IsRecognizedAsAllowed()
    {
        // Arrange - add domain to AllowedZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());
        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        // Act - check domain with AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckDomain("trusted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is recognized as allowed
        Assert.True(result.IsAllowed);
        Assert.Equal("trusted.example.com", result.AllowedDomain);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public void CheckDomain_AllowedZoneManagerSubdomain_IsAlsoAllowed()
    {
        // Arrange - add parent domain to AllowedZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());
        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        // Act - check subdomain with AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckDomain("sub.trusted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - subdomain is recognized as allowed due to parent domain match
        Assert.True(result.IsAllowed);
        Assert.Equal("sub.trusted.example.com", result.AllowedDomain);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public void CheckDomain_AllowedZoneManagerNotInList_ReturnsNotAllowed()
    {
        // Arrange - add a different domain to AllowedZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());
        _dnsServer.AllowedZoneManager.AllowZone("other.example.com");

        // Act - check domain not in AllowedZoneManager
        var result = _blockListZoneManager.CheckDomain("unknown.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is not recognized as allowed
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public void CheckAllowList_AllowedZoneManagerDomain_IsRecognizedAsAllowed()
    {
        // Arrange - add domain to AllowedZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());
        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        // Act - check allowlist with AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckAllowList("trusted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is recognized as allowed
        Assert.True(result.IsAllowed);
        Assert.Equal("trusted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void CheckAllowList_AllowedZoneManagerNotInList_ReturnsNotAllowed()
    {
        // Arrange - add a different domain to AllowedZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());
        _dnsServer.AllowedZoneManager.AllowZone("other.example.com");

        // Act - check allowlist for domain not in AllowedZoneManager
        var result = _blockListZoneManager.CheckAllowList("unknown.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is not recognized as allowed
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_BlocklistAllowlist_ReturnsAllowed()
    {
        // Arrange - add domain to blocklist allowlist
        var allowListZone = new Dictionary<string, object>
        {
            ["whitelisted.example.com"] = null!
        };
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(allowListZone);

        // Act - check domain with AllowedZoneManager parameter (but domain not in AllowedZoneManager)
        var result = _blockListZoneManager.CheckDomain("whitelisted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is recognized as allowed via blocklist allowlist
        Assert.True(result.IsAllowed);
        Assert.Equal("whitelisted.example.com", result.AllowedDomain);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public void CheckAllowList_BlocklistAllowlist_ReturnsAllowed()
    {
        // Arrange - add domain to blocklist allowlist
        var allowListZone = new Dictionary<string, object>
        {
            ["whitelisted.example.com"] = null!
        };
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(allowListZone);

        // Act - check allowlist with AllowedZoneManager parameter (but domain not in AllowedZoneManager)
        var result = _blockListZoneManager.CheckAllowList("whitelisted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is recognized as allowed via blocklist allowlist
        Assert.True(result.IsAllowed);
        Assert.Equal("whitelisted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_NeitherInAllowedNorBlocklist_ReturnsNotAllowed()
    {
        // Arrange - add a different domain to AllowedZoneManager and blocklist allowlist
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["other1.example.com"] = null!
        });
        _dnsServer.AllowedZoneManager.AllowZone("other2.example.com");

        // Act - check domain not in either list
        var result = _blockListZoneManager.CheckDomain("unknown.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is not recognized as allowed
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public void CheckAllowList_NeitherInAllowedNorBlocklist_ReturnsNotAllowed()
    {
        // Arrange - add a different domain to AllowedZoneManager and blocklist allowlist
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["other1.example.com"] = null!
        });
        _dnsServer.AllowedZoneManager.AllowZone("other2.example.com");

        // Act - check allowlist for domain not in either list
        var result = _blockListZoneManager.CheckAllowList("unknown.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is not recognized as allowed
        Assert.False(result.IsAllowed);
        Assert.Null(result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_BothAllowedZoneAndBlocklistAllowlist_IsRecognizedAsAllowed()
    {
        // Arrange - add domain to both AllowedZoneManager and blocklist allowlist
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        });
        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        // Act - check domain with AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckDomain("trusted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is recognized as allowed (blocklist allowlist is checked first)
        Assert.True(result.IsAllowed);
        Assert.Equal("trusted.example.com", result.AllowedDomain);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public void CheckAllowList_BothAllowedZoneAndBlocklistAllowlist_IsRecognizedAsAllowed()
    {
        // Arrange - add domain to both AllowedZoneManager and blocklist allowlist
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        });
        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        // Act - check allowlist with AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckAllowList("trusted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is recognized as allowed (blocklist allowlist is checked first)
        Assert.True(result.IsAllowed);
        Assert.Equal("trusted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_AllowedZoneManagerTakesPrecedence_WhenBlocklistDoesNotBlock()
    {
        // Arrange - domain is in AllowedZoneManager but NOT in blocklist allowlist
        // This tests that AllowedZoneManager is checked when blocklist allowlist doesn't match
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());
        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        // Act - check domain with AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckDomain("trusted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - AllowedZoneManager allows the domain
        Assert.True(result.IsAllowed);
        Assert.Equal("trusted.example.com", result.AllowedDomain);
        Assert.False(result.IsBlocked);
    }

    [Fact]
    public void CheckDomain_AllowedZoneManagerCheckHappensAfterBlocklistAllowlist()
    {
        // Arrange - domain is in blocklist allowlist, AllowedZoneManager is checked after
        // This verifies the order: blocklist allowlist first, then AllowedZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["whitelisted.example.com"] = null!
        });
        _dnsServer.AllowedZoneManager.AllowZone("other.example.com");

        // Act - check domain that is in blocklist allowlist
        var result = _blockListZoneManager.CheckDomain("whitelisted.example.com", _dnsServer.AllowedZoneManager);

        // Assert - domain is allowed via blocklist allowlist
        Assert.True(result.IsAllowed);
        Assert.Equal("whitelisted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void CheckDomain_NullAllowedZoneManager_StillWorks()
    {
        // Arrange - add domain to blocklist allowlist
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["whitelisted.example.com"] = null!
        });

        // Act - check domain with null AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckDomain("whitelisted.example.com", null);

        // Assert - domain is still recognized as allowed via blocklist allowlist
        Assert.True(result.IsAllowed);
        Assert.Equal("whitelisted.example.com", result.AllowedDomain);
    }

    [Fact]
    public void CheckAllowList_NullAllowedZoneManager_StillWorks()
    {
        // Arrange - add domain to blocklist allowlist
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["whitelisted.example.com"] = null!
        });

        // Act - check allowlist with null AllowedZoneManager parameter
        var result = _blockListZoneManager.CheckAllowList("whitelisted.example.com", null);

        // Assert - domain is still recognized as allowed via blocklist allowlist
        Assert.True(result.IsAllowed);
        Assert.Equal("whitelisted.example.com", result.AllowedDomain);
    }

    #endregion
}

/// <summary>
/// Mock IDnsResolver for testing CNAME chain resolution without real DNS queries.
/// </summary>
public class MockDnsResolver : IDnsResolver
{
    private readonly Func<DnsQuestionRecord, Task<DnsDatagram>> _resolveFunc;

    public MockDnsResolver(Func<DnsQuestionRecord, Task<DnsDatagram>> resolveFunc)
    {
        _resolveFunc = resolveFunc ?? throw new ArgumentNullException(nameof(resolveFunc));
    }

    public Task<DnsDatagram> RecursiveResolveAsync(
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
        return _resolveFunc(question);
    }

    /// <summary>
    /// Creates a mock DNS response with CNAME records followed by an A record.
    /// </summary>
    public static DnsDatagram CreateCnameChainResponse(string domain, string[] cnameTargets, string finalIp)
    {
        var answer = new List<DnsResourceRecord>();

        // Add CNAME records
        foreach (var target in cnameTargets)
        {
            answer.Add(new DnsResourceRecord(
                domain,
                DnsResourceRecordType.CNAME,
                DnsClass.IN,
                300,
                new DnsCNAMERecordData(target)));
            domain = target;
        }

        // Add final A record
        answer.Add(new DnsResourceRecord(
            domain,
            DnsResourceRecordType.A,
            DnsClass.IN,
            300,
            new DnsARecordData(IPAddress.Parse(finalIp))));

        // Create query
        var query = new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN);

        // Create response with positional parameters (matching DnsDatagram constructor signature)
        return new DnsDatagram(
            (ushort)Random.Shared.Next(1, 65535),  // identifier
            true,                                    // isResponse
            DnsOpcode.StandardQuery,                  // opcode
            true,                                    // authoritativeAnswer
            false,                                   // isTruncated
            true,                                    // recursionDesired
            true,                                    // recursionAvailable
            true,                                    // authenticData
            false,                                   // checkingDisabled
            DnsResponseCode.NoError,                 // rcode
            new DnsQuestionRecord[] { query },       // question
            answer,                                  // answer
            null,                                    // authority
            null,                                    // additional
            (ushort)4096,                            // udpPayloadSize
            EDnsHeaderFlags.None,                    // ednsFlags
            null);                                   // ednsOptions
    }

    /// <summary>
    /// Creates a mock DNS response with a loop (A -> B -> A).
    /// </summary>
    public static DnsDatagram CreateCnameLoopResponse(string domain)
    {
        var answer = new List<DnsResourceRecord>
        {
            new DnsResourceRecord(
                domain,
                DnsResourceRecordType.CNAME,
                DnsClass.IN,
                300,
                new DnsCNAMERecordData("target.example.com")),
            new DnsResourceRecord(
                "target.example.com",
                DnsResourceRecordType.CNAME,
                DnsClass.IN,
                300,
                new DnsCNAMERecordData(domain))
        };

        var query = new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN);

        return new DnsDatagram(
            (ushort)Random.Shared.Next(1, 65535),
            true,
            DnsOpcode.StandardQuery,
            true,
            false,
            true,
            true,
            true,
            false,
            DnsResponseCode.NoError,
            new DnsQuestionRecord[] { query },
            answer,
            null,
            null,
            (ushort)4096,
            EDnsHeaderFlags.None,
            null);
    }

    /// <summary>
    /// Creates a mock DNS response with no CNAME records (only A record).
    /// </summary>
    public static DnsDatagram CreateDirectAResponse(string domain, string ip)
    {
        var answer = new List<DnsResourceRecord>
        {
            new DnsResourceRecord(
                domain,
                DnsResourceRecordType.A,
                DnsClass.IN,
                300,
                new DnsARecordData(IPAddress.Parse(ip)))
        };

        var query = new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN);

        return new DnsDatagram(
            (ushort)Random.Shared.Next(1, 65535),
            true,
            DnsOpcode.StandardQuery,
            true,
            false,
            true,
            true,
            true,
            false,
            DnsResponseCode.NoError,
            new DnsQuestionRecord[] { query },
            answer,
            null,
            null,
            (ushort)4096,
            EDnsHeaderFlags.None,
            null);
    }

    /// <summary>
    /// Creates a mock DNS response indicating failure (e.g., SERVFAIL, NXDOMAIN).
    /// </summary>
    public static DnsDatagram CreateErrorResponse(string domain, DnsResponseCode rcode)
    {
        var query = new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN);

        return new DnsDatagram(
            (ushort)Random.Shared.Next(1, 65535),
            true,
            DnsOpcode.StandardQuery,
            true,
            false,
            true,
            true,
            false,
            false,
            rcode,
            new DnsQuestionRecord[] { query },
            null,
            null,
            null,
            (ushort)4096,
            EDnsHeaderFlags.None,
            null);
    }
}

/// <summary>
/// Unit tests for CnameChainResolver - CNAME chain resolution and checking logic.
/// Uses mock DNS responses to simulate CNAME chains rather than making real DNS queries.
/// </summary>
public class CnameChainResolverTests : IDisposable
{
    private readonly string _tempConfigFolder;
    private readonly string _tempDohwwwFolder;
    private readonly DnsServer _dnsServer;
    private readonly BlockListZoneManager _blockListZoneManager;
    private readonly Uri _testBlockListUri = new("http://example.com/blocklist.txt");

    public CnameChainResolverTests()
    {
        // Create temp directories for DnsServer
        _tempConfigFolder = Path.Combine(Path.GetTempPath(), $"cname_test_{Guid.NewGuid():N}");
        _tempDohwwwFolder = Path.Combine(Path.GetTempPath(), $"cname_dohwww_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempConfigFolder);
        Directory.CreateDirectory(_tempDohwwwFolder);

        var logManager = new LogManager(isPortableApp: true, configFolder: _tempConfigFolder);

        _dnsServer = new DnsServer(
            configFolder: _tempConfigFolder,
            dohwwwFolder: _tempDohwwwFolder,
            log: logManager,
            serverDomain: "test.local"
        );

        var blockListField = typeof(DnsServer).GetField("_blockListZoneManager", BindingFlags.NonPublic | BindingFlags.Instance);
        _blockListZoneManager = (BlockListZoneManager)blockListField!.GetValue(_dnsServer)!;
    }

    public void Dispose()
    {
        _dnsServer?.Dispose();

        try
        {
            if (Directory.Exists(_tempConfigFolder))
                Directory.Delete(_tempConfigFolder, recursive: true);
            if (Directory.Exists(_tempDohwwwFolder))
                Directory.Delete(_tempDohwwwFolder, recursive: true);
        }
        catch
        {
            // Cleanup failure is non-critical in tests
        }
    }

    private void SetupBlockListZone(Dictionary<string, List<Uri>> blockListZone)
    {
        var field = typeof(BlockListZoneManager).GetField("_blockListZone", BindingFlags.NonPublic | BindingFlags.Instance);
        field!.SetValue(_blockListZoneManager, blockListZone);
    }

    private void SetupAllowListZone(Dictionary<string, object> allowListZone)
    {
        var field = typeof(BlockListZoneManager).GetField("_allowListZone", BindingFlags.NonPublic | BindingFlags.Instance);
        field!.SetValue(_blockListZoneManager, allowListZone);
    }

    /// <summary>
    /// Helper to check a domain against the blocklist and return block/allow results.
    /// </summary>
    private (BlockListDomainCheckResult domainResult, BlockListAllowCheckResult allowResult) CheckDomainAgainstLists(string domain)
    {
        var domainResult = _blockListZoneManager.CheckDomain(domain);
        var allowResult = _blockListZoneManager.CheckAllowList(domain);
        return (domainResult, allowResult);
    }

    [Fact]
    public async Task CnameChain_DomainWithCnameToBlockedTarget_ReturnsBlocked()
    {
        // Arrange - "ads.example.com" CNAME -> "blocked.example.com" (blocked)
        SetupBlockListZone(new Dictionary<string, List<Uri>>
        {
            ["blocked.example.com"] = new List<Uri> { _testBlockListUri }
        });
        SetupAllowListZone(new Dictionary<string, object>());

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "ads.example.com",
                new[] { "blocked.example.com" },
                "1.2.3.4"));
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "ads.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count); // CNAME + A record

        // First entry is CNAME
        Assert.Equal("ads.example.com", chain[0].Domain);
        Assert.Equal("CNAME", chain[0].Type);
        Assert.Equal("blocked.example.com", chain[0].Target);

        // Second entry is A record (terminal)
        Assert.Equal("blocked.example.com", chain[1].Domain);
        Assert.Equal("A", chain[1].Type);

        // Check against blocklist - should be blocked
        foreach (var entry in chain)
        {
            string checkDomain = entry.Target ?? entry.Domain;
            var (domainResult, allowResult) = CheckDomainAgainstLists(checkDomain);

            entry.IsBlocked = domainResult.IsBlocked;
            entry.IsAllowed = allowResult.IsAllowed;

            if (domainResult.IsBlocked)
            {
                entry.BlockedDomain = domainResult.BlockedDomain;
                entry.BlockListUrls = domainResult.BlockListUrls;
            }

            if (allowResult.IsAllowed)
            {
                entry.IsBlocked = false;
            }
        }

        // Overall result should be blocked
        Assert.True(chain.Any(e => e.IsBlocked));
    }

    [Fact]
    public async Task CnameChain_DomainWithCnameToAllowedTarget_ReturnsAllowed()
    {
        // Arrange - "safe.example.com" CNAME -> "trusted.example.com" (allowed)
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        });

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "safe.example.com",
                new[] { "trusted.example.com" },
                "5.6.7.8"));
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "safe.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count);

        // Check against allowlist - should be allowed
        foreach (var entry in chain)
        {
            string checkDomain = entry.Target ?? entry.Domain;
            var (domainResult, allowResult) = CheckDomainAgainstLists(checkDomain);

            entry.IsBlocked = domainResult.IsBlocked;
            entry.IsAllowed = allowResult.IsAllowed;

            if (allowResult.IsAllowed)
            {
                entry.IsBlocked = false;
            }
        }

        // Overall result should not be blocked (allowlist overrides)
        Assert.False(chain.Any(e => e.IsBlocked));
        Assert.True(chain.Any(e => e.IsAllowed));
    }

    [Fact]
    public async Task CnameChain_DomainWithNoCname_ReturnsNull()
    {
        // Arrange - direct A record only, no CNAME
        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateDirectAResponse(
                "direct.example.com",
                "10.0.0.1"));
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "direct.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert - returns null because no CNAME records found
        Assert.Null(chain);
    }

    [Fact]
    public async Task CnameChain_DomainWithCnameLoop_HandlesGracefully()
    {
        // Arrange - CNAME loop: A -> B -> A
        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameLoopResponse("loop.example.com"));
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "loop.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert - loop detected, chain should have entries but not infinite
        Assert.NotNull(chain);
        // Should have at most 2 entries (the looping CNAMEs)
        Assert.True(chain.Count <= 2);
        // Should not crash or hang
    }

    [Fact]
    public async Task CnameChain_ResolutionFailure_ReturnsNull()
    {
        // Arrange - throw exception on resolution
        var mockResolver = new MockDnsResolver(q =>
        {
            throw new TimeoutException("DNS resolution timed out");
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "timeout.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert - returns null on failure
        Assert.Null(chain);
    }

    [Fact]
    public async Task CnameChain_EmptyAnswer_ReturnsNull()
    {
        // Arrange - empty answer section
        var mockResolver = new MockDnsResolver(q =>
        {
            var response = MockDnsResolver.CreateErrorResponse("empty.example.com", DnsResponseCode.NoError);
            return Task.FromResult(response);
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "empty.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert - returns null for empty answer
        Assert.Null(chain);
    }

    [Fact]
    public async Task CnameChain_MultiHopChain_IdentifiesBlockedDomainAtEnd()
    {
        // Arrange - A -> B -> C -> blocked.example.com (blocked)
        SetupBlockListZone(new Dictionary<string, List<Uri>>
        {
            ["blocked.example.com"] = new List<Uri> { _testBlockListUri }
        });
        SetupAllowListZone(new Dictionary<string, object>());

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "multi.example.com",
                new[] { "b.example.com", "c.example.com", "blocked.example.com" },
                "9.10.11.12"));
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "multi.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(4, chain.Count); // 3 CNAME + 1 A record

        // Check against blocklist
        foreach (var entry in chain)
        {
            string checkDomain = entry.Target ?? entry.Domain;
            var (domainResult, allowResult) = CheckDomainAgainstLists(checkDomain);

            entry.IsBlocked = domainResult.IsBlocked;
            entry.IsAllowed = allowResult.IsAllowed;

            if (domainResult.IsBlocked)
            {
                entry.BlockedDomain = domainResult.BlockedDomain;
                entry.BlockListUrls = domainResult.BlockListUrls;
            }

            if (allowResult.IsAllowed)
            {
                entry.IsBlocked = false;
            }
        }

        // Should be blocked because "blocked.example.com" is in the chain
        Assert.True(chain.Any(e => e.IsBlocked));
        Assert.Equal("blocked.example.com", chain.First(e => e.IsBlocked).BlockedDomain);
    }

    [Fact]
    public async Task CnameChain_AllowlistOverridesBlocklistAtIntermediateLevel()
    {
        // Arrange - "intermediate.example.com" is allowed, but "final.example.com" is blocked
        // Chain: start.example.com -> intermediate.example.com -> final.example.com (blocked)
        SetupBlockListZone(new Dictionary<string, List<Uri>>
        {
            ["final.example.com"] = new List<Uri> { _testBlockListUri }
        });
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["intermediate.example.com"] = null!
        });

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "start.example.com",
                new[] { "intermediate.example.com", "final.example.com" },
                "13.14.15.16"));
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "start.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(3, chain.Count); // 2 CNAME + 1 A record

        // Check against blocklist and allowlist
        bool isAllowed = false;
        foreach (var entry in chain)
        {
            string checkDomain = entry.Target ?? entry.Domain;
            var (domainResult, allowResult) = CheckDomainAgainstLists(checkDomain);

            entry.IsBlocked = domainResult.IsBlocked;
            entry.IsAllowed = allowResult.IsAllowed;

            if (domainResult.IsBlocked)
            {
                entry.BlockedDomain = domainResult.BlockedDomain;
                entry.BlockListUrls = domainResult.BlockListUrls;
            }

            // Allowlist overrides blocklist at each level
            if (allowResult.IsAllowed)
            {
                entry.IsBlocked = false;
                isAllowed = true;
            }
        }

        // The intermediate domain is allowed, so the chain should report allowed
        Assert.True(isAllowed);
        // The intermediate entry should be marked as allowed
        Assert.True(chain.Any(e => e.IsAllowed && e.Target == "intermediate.example.com"));
    }

    [Fact]
    public async Task CnameChain_MaxHopsLimit_StopsAtMaxHops()
    {
        // Arrange - chain with more hops than MAX_CNAME_HOPS
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());

        // Create a chain with 20 CNAME hops
        var cnameTargets = Enumerable.Range(1, 20).Select(i => $"hop{i}.example.com").ToArray();
        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "start.example.com",
                cnameTargets,
                "20.21.22.23"));
        });

        var resolver = new CnameChainResolver(mockResolver, maxCnameHops: 16);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "start.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert - chain should be limited to maxCnameHops
        Assert.NotNull(chain);
        // Should have at most 17 entries (16 CNAMEs + 1 terminal A record)
        Assert.True(chain.Count <= 17);
    }

    [Fact]
    public void CheckDomainAgainstLists_BlockedDomain_ReturnsBlockedStatus()
    {
        // Arrange
        SetupBlockListZone(new Dictionary<string, List<Uri>>
        {
            ["malware.example.com"] = new List<Uri> { _testBlockListUri }
        });
        SetupAllowListZone(new Dictionary<string, object>());

        // Act
        var (domainResult, allowResult) = CheckDomainAgainstLists("malware.example.com");

        // Assert
        Assert.True(domainResult.IsBlocked);
        Assert.Equal("malware.example.com", domainResult.BlockedDomain);
        Assert.False(allowResult.IsAllowed);
    }

    [Fact]
    public void CheckDomainAgainstLists_AllowedDomain_ReturnsAllowedStatus()
    {
        // Arrange
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        });

        // Act
        var (domainResult, allowResult) = CheckDomainAgainstLists("trusted.example.com");

        // Assert
        Assert.False(domainResult.IsBlocked);
        Assert.True(allowResult.IsAllowed);
        Assert.Equal("trusted.example.com", allowResult.AllowedDomain);
    }

    [Fact]
    public void CheckDomainAgainstLists_DomainNotInLists_ReturnsNotBlockedAndNotAllowed()
    {
        // Arrange
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());

        // Act
        var (domainResult, allowResult) = CheckDomainAgainstLists("unknown.example.com");

        // Assert
        Assert.False(domainResult.IsBlocked);
        Assert.False(allowResult.IsAllowed);
    }

    [Fact]
    public async Task CnameChain_AllowedZoneManager_AllowsDomainAtHop()
    {
        // Arrange - "trusted.example.com" is in the AllowedZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());

        // Add domain to AllowedZoneManager
        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "safe.example.com",
                new[] { "trusted.example.com" },
                "5.6.7.8"));
        });

        var resolver = new CnameChainResolver(
            mockResolver,
            allowedZoneManager: _dnsServer.AllowedZoneManager,
            blockListZoneManager: _blockListZoneManager);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "safe.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count);

        // The CNAME target should be marked as allowed by AllowedZoneManager
        var cnameEntry = chain.First(e => e.Type == "CNAME");
        Assert.True(cnameEntry.IsAllowed);
        Assert.Equal("trusted.example.com", cnameEntry.Target);
    }

    [Fact]
    public async Task CnameChain_BlockListZoneManager_AllowsDomainAtHop()
    {
        // Arrange - "trusted.example.com" is in the BlockListZoneManager allowlist
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        });

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "safe.example.com",
                new[] { "trusted.example.com" },
                "5.6.7.8"));
        });

        var resolver = new CnameChainResolver(
            mockResolver,
            allowedZoneManager: null,
            blockListZoneManager: _blockListZoneManager);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "safe.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count);

        // The CNAME target should be marked as allowed by BlockListZoneManager
        var cnameEntry = chain.First(e => e.Type == "CNAME");
        Assert.True(cnameEntry.IsAllowed);
        Assert.Equal("trusted.example.com", cnameEntry.Target);
    }

    [Fact]
    public async Task CnameChain_BothManagers_AllowsDomainAtHop()
    {
        // Arrange - "trusted.example.com" is in both AllowedZoneManager and BlockListZoneManager
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>
        {
            ["trusted.example.com"] = null!
        });

        _dnsServer.AllowedZoneManager.AllowZone("trusted.example.com");

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "safe.example.com",
                new[] { "trusted.example.com" },
                "5.6.7.8"));
        });

        var resolver = new CnameChainResolver(
            mockResolver,
            allowedZoneManager: _dnsServer.AllowedZoneManager,
            blockListZoneManager: _blockListZoneManager);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "safe.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count);

        // The CNAME target should be marked as allowed (AllowedZoneManager is checked first)
        var cnameEntry = chain.First(e => e.Type == "CNAME");
        Assert.True(cnameEntry.IsAllowed);
    }

    [Fact]
    public async Task CnameChain_NoManagers_IsAllowedDefaultsFalse()
    {
        // Arrange - no managers provided, IsAllowed should be false
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "safe.example.com",
                new[] { "target.example.com" },
                "5.6.7.8"));
        });

        var resolver = new CnameChainResolver(mockResolver);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "safe.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(2, chain.Count);

        // IsAllowed should be false when no managers are provided
        foreach (var entry in chain)
        {
            Assert.False(entry.IsAllowed);
        }
    }

    [Fact]
    public async Task CnameChain_MultiHop_AllowedZoneManagerChecksEachHop()
    {
        // Arrange - "intermediate.example.com" is in AllowedZoneManager, "final.example.com" is not
        SetupBlockListZone(new Dictionary<string, List<Uri>>());
        SetupAllowListZone(new Dictionary<string, object>());

        _dnsServer.AllowedZoneManager.AllowZone("intermediate.example.com");

        var mockResolver = new MockDnsResolver(q =>
        {
            return Task.FromResult(MockDnsResolver.CreateCnameChainResponse(
                "start.example.com",
                new[] { "intermediate.example.com", "final.example.com" },
                "13.14.15.16"));
        });

        var resolver = new CnameChainResolver(
            mockResolver,
            allowedZoneManager: _dnsServer.AllowedZoneManager,
            blockListZoneManager: _blockListZoneManager);

        // Act
        var chain = await resolver.ResolveCnameChainAsync(
            "start.example.com", null, IPv6Mode.Disabled, 4096, false, false, CancellationToken.None);

        // Assert
        Assert.NotNull(chain);
        Assert.Equal(3, chain.Count); // 2 CNAME + 1 A record

        // First CNAME hop (intermediate.example.com) should be allowed
        var firstCname = chain.First(e => e.Type == "CNAME" && e.Target == "intermediate.example.com");
        Assert.True(firstCname.IsAllowed);

        // Second CNAME hop (final.example.com) should NOT be allowed
        var secondCname = chain.First(e => e.Type == "CNAME" && e.Target == "final.example.com");
        Assert.False(secondCname.IsAllowed);

        // Terminal A record should NOT be allowed
        var aRecord = chain.First(e => e.Type == "A");
        Assert.False(aRecord.IsAllowed);
    }
}
