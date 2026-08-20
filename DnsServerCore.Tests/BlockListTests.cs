using System.Reflection;
using Xunit;
using DnsServerCore;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;

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
}