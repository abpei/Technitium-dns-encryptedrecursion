using Xunit;
using DnsServerCore.Dns;

namespace DnsServerCore.Tests;
/// <summary>
/// Tests for the DnsServerRecursion enum values.
/// </summary>
public class RecursionEnumTests
{
    /// <summary>
    /// Verifies that all expected enum values exist in the DnsServerRecursion enum.
    /// </summary>
    [Theory]
    [InlineData(DnsServerRecursion.Deny, 0)]
    [InlineData(DnsServerRecursion.Allow, 1)]
    [InlineData(DnsServerRecursion.AllowOnlyForPrivateNetworks, 2)]
    [InlineData(DnsServerRecursion.UseSpecifiedNetworkACL, 3)]
    public void DnsServerRecursion_ShouldHaveExpectedValues(DnsServerRecursion expected, int expectedValue)
    {
        // Assert
        Assert.Equal(expectedValue, (int)expected);
    }
}
