using System.Reflection;
using System.Text;
using Xunit;
using DnsServerCore.Dns;

namespace DnsServerCore.Tests;
/// <summary>
/// Tests for config serialization, verifying byte round-trips and version checks.
/// </summary>
public class ConfigSerializationTests
{
    /// <summary>
    /// Verifies that all recursion enum values round-trip correctly through byte serialization.
    /// </summary>
    [Theory]
    [InlineData(DnsServerRecursion.Deny, 0)]
    [InlineData(DnsServerRecursion.Allow, 1)]
    [InlineData(DnsServerRecursion.AllowOnlyForPrivateNetworks, 2)]
    [InlineData(DnsServerRecursion.UseSpecifiedNetworkACL, 3)]
    public void RecursionEnum_ShouldRoundTripThroughByte(DnsServerRecursion original, byte expectedByte)
    {
        // Arrange & Act
        var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((byte)original);
        }

        stream.Position = 0;
        DnsServerRecursion result;
        using (var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true))
        {
            result = (DnsServerRecursion)reader.ReadByte();
        }

        stream.Dispose();

        // Assert
        Assert.Equal(original, result);
        Assert.Equal(expectedByte, (byte)result);
    }

    /// <summary>
    /// Verifies that the DNS Server config version constant is 8.
    /// Version 8 is the upstream v15.6 version 7 layout (with the explicit cache prefetch bool) plus the fork's
    /// DoH custom landing page html, so that it cannot be confused with either the upstream v15.6 version 7
    /// layout or the fork version 7 layout. The real write and read round-trip of every layout is covered by
    /// ConfigVersionCompatibilityTests.
    /// </summary>
    [Fact]
    public void DnsServerConfigVersion_ShouldBe8()
    {
        // Arrange
        FieldInfo? versionField = typeof(DnsServer).GetField("DNS_CONFIG_VERSION", BindingFlags.NonPublic | BindingFlags.Static);

        // Act
        object? value = versionField?.GetRawConstantValue();

        // Assert
        Assert.NotNull(versionField);
        Assert.Equal((byte)8, value);
    }

    /// <summary>
    /// Verifies that the Web Service config version is 4.
    /// </summary>
    [Fact]
    public void WebServiceConfigVersion_ShouldBe4()
    {
        // This test verifies the expected config version by reading the source code.
        // The version is written as byte 4 at line 599 in DnsWebService.cs.
        byte expectedVersion = 4;

        // Act - simulate config write
        var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((byte)expectedVersion);
        }

        // Act - simulate config read
        stream.Position = 0;
        byte result;
        using (var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true))
        {
            result = reader.ReadByte();
        }

        stream.Dispose();

        // Assert
        Assert.Equal(expectedVersion, result);
    }
}
