using System.Net;
using Xunit;

namespace DnsServerCore.Tests;

/// <summary>
/// Tests for IPAddress.IsLoopback detection used in the recursion exemption feature.
/// </summary>
public class LoopbackDetectionTests
{
    /// <summary>
    /// Verifies that IPAddress.IsLoopback returns true for the IPv4 loopback address (127.0.0.1).
    /// This confirms the loopback detection used in IsRecursionAllowed works correctly.
    /// </summary>
    [Fact]
    public void IsLoopback_IPv4Loopback_ShouldReturnTrue()
    {
        // Arrange
        IPAddress loopback = IPAddress.Loopback; // 127.0.0.1

        // Act
        bool result = IPAddress.IsLoopback(loopback);

        // Assert
        Assert.True(result);
        Assert.Equal("127.0.0.1", loopback.ToString());
    }

    /// <summary>
    /// Verifies that IPAddress.IsLoopback returns true for the IPv6 loopback address (::1).
    /// The recursion exemption supports both IPv4 and IPv6 loopback addresses.
    /// </summary>
    [Fact]
    public void IsLoopback_IPv6Loopback_ShouldReturnTrue()
    {
        // Arrange
        IPAddress loopback = IPAddress.IPv6Loopback; // ::1

        // Act
        bool result = IPAddress.IsLoopback(loopback);

        // Assert
        Assert.True(result);
        Assert.Equal("::1", loopback.ToString());
    }

    /// <summary>
    /// Verifies that IPAddress.IsLoopback returns false for a regular non-loopback IP address.
    /// </summary>
    [Fact]
    public void IsLoopback_NonLoopbackAddress_ShouldReturnFalse()
    {
        // Arrange
        IPAddress regularIP = IPAddress.Parse("192.168.1.1");

        // Act
        bool result = IPAddress.IsLoopback(regularIP);

        // Assert
        Assert.False(result);
    }

    /// <summary>
    /// Verifies that IPAddress.IsLoopback returns false for the broadcast address.
    /// </summary>
    [Fact]
    public void IsLoopback_BroadcastAddress_ShouldReturnFalse()
    {
        // Arrange
        IPAddress broadcast = IPAddress.Broadcast; // 255.255.255.255

        // Act
        bool result = IPAddress.IsLoopback(broadcast);

        // Assert
        Assert.False(result);
    }

    /// <summary>
    /// Verifies that IPAddress.IsLoopback returns false for the "any" address (0.0.0.0).
    /// </summary>
    [Fact]
    public void IsLoopback_AnyAddress_ShouldReturnFalse()
    {
        // Arrange
        IPAddress any = IPAddress.Any; // 0.0.0.0

        // Act
        bool result = IPAddress.IsLoopback(any);

        // Assert
        Assert.False(result);
    }
}
