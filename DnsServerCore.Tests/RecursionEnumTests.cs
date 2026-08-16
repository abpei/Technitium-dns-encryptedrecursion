using Xunit;
using DnsServerCore.Dns;

namespace DnsServerCore.Tests;

/// <summary>
/// Tests for the DnsServerRecursion enum, specifically the AllowOnlyForOptionalProtocols value.
/// </summary>
public class RecursionEnumTests
{
    /// <summary>
    /// Verifies that AllowOnlyForOptionalProtocols enum value exists and equals 4.
    /// This value was added for the per-protocol recursion control feature.
    /// </summary>
    [Fact]
    public void AllowOnlyForOptionalProtocols_ShouldExistAndEqual4()
    {
        // Arrange & Act
        DnsServerRecursion value = DnsServerRecursion.AllowOnlyForOptionalProtocols;

        // Assert
        Assert.Equal((byte)4, (byte)value);
        Assert.Equal(4, (int)value);
    }

    /// <summary>
    /// Verifies that all expected enum values exist in the DnsServerRecursion enum.
    /// </summary>
    [Theory]
    [InlineData(DnsServerRecursion.Deny, 0)]
    [InlineData(DnsServerRecursion.Allow, 1)]
    [InlineData(DnsServerRecursion.AllowOnlyForPrivateNetworks, 2)]
    [InlineData(DnsServerRecursion.UseSpecifiedNetworkACL, 3)]
    [InlineData(DnsServerRecursion.AllowOnlyForOptionalProtocols, 4)]
    public void DnsServerRecursion_ShouldHaveExpectedValues(DnsServerRecursion expected, int expectedValue)
    {
        // Assert
        Assert.Equal(expectedValue, (int)expected);
    }

    /// <summary>
    /// Verifies that the enum can be parsed from string (used in Settings API).
    /// </summary>
    [Fact]
    public void AllowOnlyForOptionalProtocols_ShouldBeParseableFromString()
    {
        // Arrange
        string enumString = "AllowOnlyForOptionalProtocols";

        // Act
        bool parsed = Enum.TryParse(enumString, true, out DnsServerRecursion result);

        // Assert
        Assert.True(parsed);
        Assert.Equal(DnsServerRecursion.AllowOnlyForOptionalProtocols, result);
    }

    /// <summary>
    /// Verifies that the enum can be cast from byte (used in config serialization).
    /// </summary>
    [Fact]
    public void AllowOnlyForOptionalProtocols_ShouldBeCastableFromByte()
    {
        // Arrange
        byte value = 4;

        // Act
        DnsServerRecursion result = (DnsServerRecursion)value;

        // Assert
        Assert.Equal(DnsServerRecursion.AllowOnlyForOptionalProtocols, result);
    }

    /// <summary>
    /// Verifies that the enum can be cast to byte (used in config serialization).
    /// </summary>
    [Fact]
    public void AllowOnlyForOptionalProtocols_ShouldBeCastableToByte()
    {
        // Arrange
        DnsServerRecursion value = DnsServerRecursion.AllowOnlyForOptionalProtocols;

        // Act
        byte result = (byte)value;

        // Assert
        Assert.Equal((byte)4, result);
    }
}
