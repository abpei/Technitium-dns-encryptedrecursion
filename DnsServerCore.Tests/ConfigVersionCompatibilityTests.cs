using System.Reflection;
using System.Text;
using DnsServerCore.Dns;
using Xunit;

namespace DnsServerCore.Tests;

/// <summary>
/// Tests the DNS server config reader and writer against the ambiguous config version 6 collision (upstream v15.5
/// dropped the cache prefetch sampling options while this fork kept them and appended the DoH custom landing page
/// html), the ambiguous config version 7 collision (upstream v15.6 added an explicit cache prefetch bool while
/// this fork based on upstream v15.5 kept only the landing page html), and a fresh version 8 write/read round-trip.
/// </summary>
public class ConfigVersionCompatibilityTests : IDisposable
{
    /// <summary>Config version written by the current build (upstream v15.6 v7 layout plus fork landing page html).</summary>
    const byte ForkConfigVersion = 8;

    /// <summary>Config version written by both upstream v15.5 and older fork builds with different layouts.</summary>
    const byte AmbiguousConfigVersionV6 = 6;

    /// <summary>Config version written by both upstream v15.6 and this fork with different layouts.</summary>
    const byte AmbiguousConfigVersionV7 = 7;

    /// <summary>Legacy cache prefetch sampling options that only exist in the version 1 to 5 and fork version 6 layouts.</summary>
    static readonly byte[] LegacyCachePrefetchSamplingOptions = [.. BitConverter.GetBytes(60), .. BitConverter.GetBytes(1000)];

    /// <summary>Distinctive landing page html used to locate the fork field in the serialized config.</summary>
    const string LandingPageMarker = "<html>FORK-DOH-LANDING-PAGE-MARKER</html>";

    //distinctive values used as sentinels so that any field misalignment shows up as an assertion failure
    const int PrefetchEligibilitySentinel = 0x11111111;
    const int PrefetchTriggerSentinel = 0x00222222;
    const int MaxStatFileDaysSentinel = 0x00001234;
    const int DnsOverHttpsPortSentinel = 8443;

    static readonly MethodInfo WriteConfigToMethod = typeof(DnsServer).GetMethod("WriteConfigTo", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("DnsServer.WriteConfigTo() was not found.");

    static readonly MethodInfo ReadConfigFromMethod = typeof(DnsServer).GetMethod("ReadConfigFrom", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("DnsServer.ReadConfigFrom() was not found.");

    readonly string _tempFolder;

    public ConfigVersionCompatibilityTests()
    {
        _tempFolder = Path.Combine(Path.GetTempPath(), "dns_config_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempFolder);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempFolder, true);
        }
        catch
        {
            //server timers and log writers may still hold files in the temp folder; the OS cleans it up eventually
        }
    }

    /// <summary>
    /// Verifies that the config written by this build uses version 8 so that it cannot be confused with either the
    /// upstream v15.6 version 7 layout or the fork version 7 layout that lacks the explicit cache prefetch bool.
    /// </summary>
    [Fact]
    public void WriteConfig_ShouldUseVersion8()
    {
        // Arrange
        DnsServer server = CreateServer("writer");

        // Act
        byte[] config = WriteConfig(server);

        // Assert
        Assert.Equal("DC", Encoding.ASCII.GetString(config, 0, 2));
        Assert.Equal(ForkConfigVersion, config[2]);
    }

    /// <summary>
    /// Verifies that every sentinel setting survives a fresh write and read round-trip of the current version 8
    /// layout, including the explicit cache prefetch option and the fork landing page html.
    /// </summary>
    [Fact]
    public void WriteThenRead_ShouldPreserveSettings()
    {
        // Arrange
        DnsServer writer = CreateServer("round_trip_writer");
        DnsServer reader = PrepareServer("round_trip_reader");

        // Act
        long leftover = ReadConfigLeftover(reader, WriteConfig(writer));

        // Assert
        Assert.Equal(0, leftover);
        AssertSentinelSettings(reader, expectLandingPageHtml: true, expectEnableCachePrefetch: false);
    }

    /// <summary>
    /// Verifies that a written version 8 config is byte-layout stable: reading it back and writing it again with
    /// the same settings must reproduce the exact same bytes, which proves the version 8 field order is correct
    /// and the round-trip is lossless.
    /// </summary>
    [Fact]
    public void WriteThenReadThenWrite_ShouldBeByteIdentical()
    {
        // Arrange
        DnsServer writer = CreateServer("stable_writer");
        DnsServer reader = PrepareServer("stable_reader");

        // Act
        byte[] firstWrite = WriteConfig(writer);
        ReadConfig(reader, firstWrite, isConfigTransfer: false);
        byte[] secondWrite = WriteConfig(reader);

        // Assert
        Assert.Equal(firstWrite, secondWrite);
    }

    /// <summary>
    /// Verifies that a config in the fork version 7 layout (landing page html, no explicit cache prefetch bool)
    /// loads with all settings intact, which keeps existing fork nodes upgradeable. The prefetch option is absent
    /// from this layout so it must fall back to its default value.
    /// </summary>
    [Fact]
    public void ForkVersion7Config_ShouldLoadWithAllSettings()
    {
        // Arrange
        byte[] fixture = ToLegacyLayout(
            WriteSentinelConfig("fork_v7_writer"),
            AmbiguousConfigVersionV7,
            hasLandingPageHtml: true,
            hasEnableCachePrefetchOption: false,
            hasLegacyCachePrefetchSamplingOptions: false);

        DnsServer reader = PrepareServer("fork_v7_reader");

        // Act
        long leftover = ReadConfigLeftover(reader, fixture);

        // Assert
        Assert.Equal(0, leftover);
        AssertSentinelSettings(reader, expectLandingPageHtml: true, expectEnableCachePrefetch: true);
    }

    /// <summary>
    /// Verifies that a config in the upstream v15.6 version 7 layout (explicit cache prefetch bool, no landing page
    /// html) loads with all settings intact and with the fork landing page reset to its default.
    /// </summary>
    [Fact]
    public void UpstreamVersion7Config_ShouldLoadWithAllSettings()
    {
        // Arrange
        byte[] fixture = ToLegacyLayout(
            WriteSentinelConfig("upstream_v7_writer"),
            AmbiguousConfigVersionV7,
            hasLandingPageHtml: false,
            hasEnableCachePrefetchOption: true,
            hasLegacyCachePrefetchSamplingOptions: false);

        DnsServer reader = PrepareServer("upstream_v7_reader");

        // Act
        long leftover = ReadConfigLeftover(reader, fixture);

        // Assert
        Assert.Equal(0, leftover);
        AssertSentinelSettings(reader, expectLandingPageHtml: false, expectEnableCachePrefetch: false);
    }

    /// <summary>
    /// Verifies that a config in the pre-merge fork version 6 layout (landing page html plus the legacy cache
    /// prefetch sampling options) loads with all settings intact, which keeps existing fork nodes upgradeable.
    /// </summary>
    [Fact]
    public void ForkVersion6Config_ShouldLoadWithAllSettings()
    {
        // Arrange
        byte[] fixture = ToLegacyLayout(
            WriteSentinelConfig("fork_v6_writer"),
            AmbiguousConfigVersionV6,
            hasLandingPageHtml: true,
            hasEnableCachePrefetchOption: false,
            hasLegacyCachePrefetchSamplingOptions: true);

        DnsServer reader = PrepareServer("fork_v6_reader");

        // Act
        long leftover = ReadConfigLeftover(reader, fixture);

        // Assert
        Assert.Equal(0, leftover);
        AssertSentinelSettings(reader, expectLandingPageHtml: true, expectEnableCachePrefetch: true);
    }

    /// <summary>
    /// Verifies that a config in the upstream v15.5 version 6 layout (no landing page html and no cache prefetch
    /// sampling options) loads with all settings intact and with the fork landing page reset to its default.
    /// </summary>
    [Fact]
    public void UpstreamVersion6Config_ShouldLoadWithAllSettings()
    {
        // Arrange
        byte[] fixture = ToLegacyLayout(
            WriteSentinelConfig("upstream_v6_writer"),
            AmbiguousConfigVersionV6,
            hasLandingPageHtml: false,
            hasEnableCachePrefetchOption: false,
            hasLegacyCachePrefetchSamplingOptions: false);

        DnsServer reader = PrepareServer("upstream_v6_reader");

        // Act
        long leftover = ReadConfigLeftover(reader, fixture);

        // Assert
        Assert.Equal(0, leftover);
        AssertSentinelSettings(reader, expectLandingPageHtml: false, expectEnableCachePrefetch: true);
    }

    /// <summary>
    /// Verifies that a legacy version 5 config (no landing page html, no prefetch bool, with the cache prefetch
    /// sampling options) still loads with all settings intact, since version 5 files are unchanged by either
    /// version collision.
    /// </summary>
    [Fact]
    public void LegacyVersion5Config_ShouldLoadWithAllSettings()
    {
        // Arrange
        byte[] fixture = ToLegacyLayout(
            WriteSentinelConfig("legacy_v5_writer"),
            5,
            hasLandingPageHtml: false,
            hasEnableCachePrefetchOption: false,
            hasLegacyCachePrefetchSamplingOptions: true);

        DnsServer reader = PrepareServer("legacy_v5_reader");

        // Act
        long leftover = ReadConfigLeftover(reader, fixture);

        // Assert
        Assert.Equal(0, leftover);
        AssertSentinelSettings(reader, expectLandingPageHtml: false, expectEnableCachePrefetch: true);
    }

    /// <summary>
    /// Verifies that every legacy layout, including both ambiguous versions, is also readable in config transfer
    /// mode, which is used when a cluster node syncs a config from another node and must not be rejected by the
    /// layout probes.
    /// </summary>
    [Theory]
    [InlineData(AmbiguousConfigVersionV7, true, false, false)]
    [InlineData(AmbiguousConfigVersionV7, false, true, false)]
    [InlineData(AmbiguousConfigVersionV6, true, false, true)]
    [InlineData(AmbiguousConfigVersionV6, false, false, false)]
    [InlineData(5, false, false, true)]
    public void TransferConfig_ShouldReadEveryLegacyLayout(byte version, bool hasLandingPageHtml, bool hasEnableCachePrefetchOption, bool hasLegacyCachePrefetchSamplingOptions)
    {
        // Arrange
        byte[] fixture = ToLegacyLayout(
            WriteSentinelConfig("transfer_writer"),
            version,
            hasLandingPageHtml,
            hasEnableCachePrefetchOption,
            hasLegacyCachePrefetchSamplingOptions);

        DnsServer reader = CreateServer("transfer_reader");

        // Act
        ReadConfig(reader, fixture, isConfigTransfer: true);

        // Assert
        Assert.Equal(hasLandingPageHtml ? LandingPageMarker : null, reader.DohCustomLandingPageHtml);
    }

    /// <summary>
    /// Verifies that a config version that does not exist is rejected instead of being parsed as one of the
    /// known layouts.
    /// </summary>
    [Fact]
    public void UnsupportedConfigVersion_ShouldBeRejected()
    {
        // Arrange
        byte[] config = WriteSentinelConfig("unsupported_version_writer");
        config[2] = ForkConfigVersion + 1;

        // Act
        Exception? failure = ReadConfigFailure(PrepareServer("unsupported_version_reader"), config);

        // Assert
        Assert.IsType<InvalidDataException>(failure);
    }

    /// <summary>
    /// Verifies that a truncated version 6 config is rejected with an invalid data error since neither known
    /// version 6 layout can read it completely.
    /// </summary>
    [Fact]
    public void TruncatedVersion6Config_ShouldBeRejected()
    {
        // Arrange
        byte[] config = ToLegacyLayout(
            WriteSentinelConfig("truncated_v6_writer"),
            AmbiguousConfigVersionV6,
            hasLandingPageHtml: true,
            hasEnableCachePrefetchOption: false,
            hasLegacyCachePrefetchSamplingOptions: true);

        byte[] truncated = config[..^3];

        // Act
        Exception? failure = ReadConfigFailure(PrepareServer("truncated_v6_reader"), truncated);

        // Assert
        Assert.IsType<InvalidDataException>(failure);
    }

    /// <summary>
    /// Verifies that a truncated version 7 config is rejected with an invalid data error since neither known
    /// version 7 layout can read it completely.
    /// </summary>
    [Fact]
    public void TruncatedVersion7Config_ShouldBeRejected()
    {
        // Arrange
        byte[] config = ToLegacyLayout(
            WriteSentinelConfig("truncated_v7_writer"),
            AmbiguousConfigVersionV7,
            hasLandingPageHtml: true,
            hasEnableCachePrefetchOption: false,
            hasLegacyCachePrefetchSamplingOptions: false);

        byte[] truncated = config[..^3];

        // Act
        Exception? failure = ReadConfigFailure(PrepareServer("truncated_v7_reader"), truncated);

        // Assert
        Assert.IsType<InvalidDataException>(failure);
    }

    /// <summary>
    /// Creates a DNS server that stores all of its data inside the test temp folder.
    /// </summary>
    private DnsServer PrepareServer(string name)
    {
        string folder = Path.Combine(_tempFolder, name);
        Directory.CreateDirectory(folder);

        return new DnsServer(folder, folder, new LogManager(true, folder), "test-server.local");
    }

    /// <summary>
    /// Creates a DNS server with sentinel settings applied so that its config can be used as a test fixture.
    /// </summary>
    private DnsServer CreateServer(string name)
    {
        DnsServer server = PrepareServer(name);
        ApplySentinelSettings(server);

        return server;
    }

    /// <summary>
    /// Applies distinctive values to a few settings that are spread across the config file.
    /// </summary>
    private static void ApplySentinelSettings(DnsServer server)
    {
        server.DohCustomLandingPageHtml = LandingPageMarker;
        server.EnableDnsOverHttpHelpRedirect = false;
        server.DnsOverHttpsPort = DnsOverHttpsPortSentinel;
        server.Recursion = DnsServerRecursion.Deny;
        server.ServeStale = true;
        server.CachePrefetchEligibility = PrefetchEligibilitySentinel;
        server.CachePrefetchTrigger = PrefetchTriggerSentinel;
        server.EnableCachePrefetch = false;
        server.StatsManager.EnableInMemoryStats = true;
        server.StatsManager.MaxStatFileDays = MaxStatFileDaysSentinel;
    }

    /// <summary>
    /// Asserts that all sentinel settings are present on the given server, that the landing page html was either
    /// restored or reset as the layout requires, and that the cache prefetch option matches the layout.
    /// </summary>
    private static void AssertSentinelSettings(DnsServer server, bool expectLandingPageHtml, bool expectEnableCachePrefetch)
    {
        Assert.Equal(expectLandingPageHtml ? LandingPageMarker : null, server.DohCustomLandingPageHtml);
        Assert.False(server.EnableDnsOverHttpHelpRedirect);
        Assert.Equal(DnsOverHttpsPortSentinel, server.DnsOverHttpsPort);
        Assert.Equal(DnsServerRecursion.Deny, server.Recursion);
        Assert.True(server.ServeStale);
        Assert.Equal(PrefetchEligibilitySentinel, server.CachePrefetchEligibility);
        Assert.Equal(PrefetchTriggerSentinel, server.CachePrefetchTrigger);
        Assert.Equal(expectEnableCachePrefetch, server.EnableCachePrefetch);
        Assert.True(server.StatsManager.EnableInMemoryStats);
        Assert.Equal(MaxStatFileDaysSentinel, server.StatsManager.MaxStatFileDays);
    }

    /// <summary>
    /// Writes a config with sentinel settings so that it can be transformed into a legacy layout fixture.
    /// </summary>
    private byte[] WriteSentinelConfig(string name)
    {
        return WriteConfig(CreateServer(name));
    }

    /// <summary>
    /// Serializes the current settings of the given server by calling the private config writer.
    /// </summary>
    private static byte[] WriteConfig(DnsServer server)
    {
        using MemoryStream stream = new MemoryStream();
        WriteConfigToMethod.Invoke(server, [stream]);

        return stream.ToArray();
    }

    /// <summary>
    /// Applies the given config bytes to the given server by calling the private config reader.
    /// </summary>
    private static void ReadConfig(DnsServer server, byte[] config, bool isConfigTransfer)
    {
        using MemoryStream stream = new MemoryStream(config);
        ReadConfigFromMethod.Invoke(server, [stream, isConfigTransfer]);
    }

    /// <summary>
    /// Applies the given config bytes to the given server and returns the number of config bytes that the
    /// reader did not consume, which must be zero for a correctly identified layout.
    /// </summary>
    private static long ReadConfigLeftover(DnsServer server, byte[] config)
    {
        using MemoryStream stream = new MemoryStream(config);
        ReadConfigFromMethod.Invoke(server, [stream, false]);

        return stream.Length - stream.Position;
    }

    /// <summary>
    /// Reads a config that is expected to fail and returns the exception thrown by the reader.
    /// </summary>
    private static Exception? ReadConfigFailure(DnsServer server, byte[] config)
    {
        try
        {
            ReadConfig(server, config, isConfigTransfer: false);
        }
        catch (TargetInvocationException ex)
        {
            return ex.InnerException;
        }
        catch (Exception ex)
        {
            return ex;
        }

        return null;
    }

    /// <summary>
    /// Rewrites a config written by this build (the version 8 layout) into one of the older layouts: the given
    /// version byte is set, the landing page html field is dropped when the layout does not have it, the explicit
    /// cache prefetch bool is dropped when the layout does not have it and the two legacy cache prefetch sampling
    /// options are inserted when the layout has them. The pre-merge fork and upstream layouts are byte identical
    /// to the current layout except for the version byte and these fields, so the fixtures are built from the real
    /// writer output instead of being copied by hand.
    /// </summary>
    private static byte[] ToLegacyLayout(byte[] config, byte version, bool hasLandingPageHtml, bool hasEnableCachePrefetchOption, bool hasLegacyCachePrefetchSamplingOptions)
    {
        List<byte> buffer = [.. config];

        if (!hasLandingPageHtml)
        {
            Assert.True(LandingPageMarker.Length < 128, "BinaryWriter uses a single byte for 7 bit encoded string lengths below 128.");

            byte[] landingPageField = [(byte)LandingPageMarker.Length, .. Encoding.UTF8.GetBytes(LandingPageMarker)];
            int landingPageIndex = FindSingleIndex(buffer, landingPageField);
            buffer.RemoveRange(landingPageIndex, landingPageField.Length);
        }

        if (!hasEnableCachePrefetchOption)
        {
            //the explicit cache prefetch bool is written immediately before the cache prefetch eligibility option
            int eligibilityIndex = FindSingleIndex(buffer, BitConverter.GetBytes(PrefetchEligibilitySentinel));
            byte prefetchOption = buffer[eligibilityIndex - 1];

            Assert.True((prefetchOption == 0) || (prefetchOption == 1), "Test fixture expected the explicit cache prefetch option to be a single serialized bool.");

            buffer.RemoveRange(eligibilityIndex - 1, 1);
        }

        if (hasLegacyCachePrefetchSamplingOptions)
        {
            int eligibilityIndex = FindSingleIndex(buffer, BitConverter.GetBytes(PrefetchEligibilitySentinel));
            int triggerIndex = FindSingleIndex(buffer, BitConverter.GetBytes(PrefetchTriggerSentinel));

            if (triggerIndex != (eligibilityIndex + sizeof(int)))
                throw new InvalidOperationException("Test fixture expected the cache prefetch eligibility and trigger options to be adjacent in the serialized config.");

            buffer.InsertRange(triggerIndex + sizeof(int), LegacyCachePrefetchSamplingOptions);
        }

        buffer[2] = version;

        return [.. buffer];
    }

    /// <summary>
    /// Finds the only occurrence of the given byte pattern, failing the test when the pattern is absent or
    /// ambiguous so that a fixture cannot be built from the wrong offset.
    /// </summary>
    private static int FindSingleIndex(List<byte> buffer, byte[] pattern)
    {
        int foundIndex = -1;

        for (int i = 0; i <= (buffer.Count - pattern.Length); i++)
        {
            bool isMatch = true;

            for (int j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    isMatch = false;
                    break;
                }
            }

            if (!isMatch)
                continue;

            if (foundIndex >= 0)
                throw new InvalidOperationException("Test fixture pattern was found more than once in the serialized config.");

            foundIndex = i;
        }

        if (foundIndex < 0)
            throw new InvalidOperationException("Test fixture pattern was not found in the serialized config.");

        return foundIndex;
    }
}
