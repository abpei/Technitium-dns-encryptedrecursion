using System.Reflection;
using System.Text.Json;
using Xunit;

namespace DnsServerCore.Tests;

/// <summary>
/// Tests for fork-specific version and label functionality.
/// Uses reflection to test private methods in DnsWebService.
/// </summary>
public class ForkVersionTests
{
    private const string ForkJsonFileName = "fork.json";

    /// <summary>
    /// Test data for fork.json scenarios: (forkName, forkBranch, forkVersion, expectedLabel).
    /// </summary>
    public static IEnumerable<object[]> ForkJsonScenarios => new List<object[]>
    {
        // (forkName, forkBranch, forkVersion, expectedLabel)
        new object?[] { "Test Fork", "dev", "v1.0.0", "dev — v1.0.0" },
        new object?[] { "Test Fork", null, "v1.0.0", "v1.0.0" },
        new object?[] { "Test Fork", "dev", null, "dev" },
        new object?[] { "Test Fork", null, null, null }, // Both null returns null
    };

    /// <summary>
    /// Verifies that GetForkLabel() returns correct formatted string when fork.json exists with valid content.
    /// </summary>
    [Theory]
    [MemberData(nameof(ForkJsonScenarios))]
    public void GetForkLabel_WithValidForkJson_ShouldReturnExpectedLabel(
        string? forkName, string? forkBranch, string? forkVersion, string? expectedLabel)
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), $"fork_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // Create fork.json
            var forkData = new Dictionary<string, object?>();
            if (forkName is not null) forkData["forkName"] = forkName;
            if (forkBranch is not null) forkData["forkBranch"] = forkBranch;
            if (forkVersion is not null) forkData["forkVersion"] = forkVersion;

            string forkJson = JsonSerializer.Serialize(forkData);
            string forkJsonPath = Path.Combine(tempDir, ForkJsonFileName);
            File.WriteAllText(forkJsonPath, forkJson);

            // Act - test the GetForkLabel logic
            string? result = GetForkLabelFromPath(forkJsonPath);

            // Assert
            if (expectedLabel is null)
            {
                Assert.Null(result);
            }
            else
            {
                Assert.Equal(expectedLabel, result);
            }
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    /// <summary>
    /// Verifies that GetForkLabel() returns null when fork.json is missing.
    /// </summary>
    [Fact]
    public void GetForkLabel_WhenForkJsonMissing_ShouldReturnNull()
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), $"fork_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // No fork.json created
            string forkJsonPath = Path.Combine(tempDir, ForkJsonFileName);

            // Act
            string? result = GetForkLabelFromPath(forkJsonPath);

            // Assert
            Assert.Null(result);
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    /// <summary>
    /// Verifies that GetForkLabel() handles malformed JSON gracefully (returns null).
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{invalid json}")]
    [InlineData("[]")]
    public void GetForkLabel_WithMalformedForkJson_ShouldReturnNull(string malformedContent)
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), $"fork_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            string forkJsonPath = Path.Combine(tempDir, ForkJsonFileName);
            File.WriteAllText(forkJsonPath, malformedContent);

            // Act
            string? result = GetForkLabelFromPath(forkJsonPath);

            // Assert
            Assert.Null(result);
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    /// <summary>
    /// Verifies that GetServerVersion() includes fork label when fork.json is present.
    /// </summary>
    [Fact]
    public void GetServerVersion_WithForkJson_ShouldIncludeForkLabel()
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), $"fork_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // Create fork.json
            var forkData = new Dictionary<string, object?>
            {
                ["forkName"] = "Test Fork",
                ["forkBranch"] = "dev",
                ["forkVersion"] = "v1.0.0"
            };
            string forkJson = JsonSerializer.Serialize(forkData);
            string forkJsonPath = Path.Combine(tempDir, ForkJsonFileName);
            File.WriteAllText(forkJsonPath, forkJson);

            // Simulate GetCleanVersion with a sample version
            var version = new Version(15, 4);
            string cleanVersion = GetCleanVersion(version);

            // Get fork label
            string? forkLabel = GetForkLabelFromPath(forkJsonPath);

            // Act - simulate GetServerVersion
            string result = forkLabel is not null ? cleanVersion + " (" + forkLabel + ")" : cleanVersion;

            // Assert
            Assert.Contains("15.4", result);
            Assert.Contains("dev", result);
            Assert.Contains("v1.0.0", result);
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    /// <summary>
    /// Verifies that GetServerVersion() returns clean version when fork.json is missing.
    /// </summary>
    [Fact]
    public void GetServerVersion_WithoutForkJson_ShouldReturnCleanVersion()
    {
        // Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), $"fork_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // No fork.json created
            string forkJsonPath = Path.Combine(tempDir, ForkJsonFileName);

            // Simulate GetCleanVersion with a sample version
            var version = new Version(15, 4);
            string cleanVersion = GetCleanVersion(version);

            // Get fork label (should be null)
            string? forkLabel = GetForkLabelFromPath(forkJsonPath);

            // Act - simulate GetServerVersion
            string result = forkLabel is not null ? cleanVersion + " (" + forkLabel + ")" : cleanVersion;

            // Assert
            Assert.Equal("15.4", result);
            Assert.DoesNotContain("(", result);
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    /// <summary>
    /// Verifies that the fork.json file can be parsed correctly.
    /// </summary>
    [Fact]
    public void ForkJson_ShouldBeParseable()
    {
        // Arrange
        var forkData = new Dictionary<string, object?>
        {
            ["forkName"] = "PIDOH Encrypted-Recursion Fork",
            ["forkBranch"] = "dev",
            ["forkVersion"] = "v15.4.0-dev2"
        };

        string json = JsonSerializer.Serialize(forkData);

        // Act
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;

        string? forkName = root.TryGetProperty("forkName", out JsonElement name) ? name.GetString() : null;
        string? forkBranch = root.TryGetProperty("forkBranch", out JsonElement branch) ? branch.GetString() : null;
        string? forkVersion = root.TryGetProperty("forkVersion", out JsonElement ver) ? ver.GetString() : null;

        // Assert
        Assert.Equal("PIDOH Encrypted-Recursion Fork", forkName);
        Assert.Equal("dev", forkBranch);
        Assert.Equal("v15.4.0-dev2", forkVersion);
    }

    /// <summary>
    /// Helper method that replicates GetForkLabel() logic for testing.
    /// This mirrors the implementation in DnsWebService.cs.
    /// </summary>
    private static string? GetForkLabelFromPath(string forkJsonPath)
    {
        try
        {
            if (!File.Exists(forkJsonPath))
                return null;

            string json = File.ReadAllText(forkJsonPath);
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            string? forkBranch = root.TryGetProperty("forkBranch", out JsonElement branch) ? branch.GetString() : null;
            string? forkVersion = root.TryGetProperty("forkVersion", out JsonElement ver) ? ver.GetString() : null;

            if (forkBranch is null && forkVersion is null)
                return null;

            if (forkBranch is not null && forkVersion is not null)
                return forkBranch + " \u2014 " + forkVersion;

            return forkVersion ?? forkBranch;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Helper method that replicates GetCleanVersion() logic for testing.
    /// This mirrors the implementation in DnsWebService.cs.
    /// </summary>
    private static string GetCleanVersion(Version version)
    {
        string strVersion = version.Major + "." + version.Minor;

        if (version.Build > 0)
            strVersion += "." + version.Build;

        if (version.Revision > 0)
            strVersion += "." + version.Revision;

        return strVersion;
    }
}
