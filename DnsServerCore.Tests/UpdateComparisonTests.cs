using Xunit;

namespace DnsServerCore.Tests;

/// <summary>
/// Regression tests for the fork update comparison (DnsWebService.IsUpdateAvailable).
/// Covers the release-line and fork-increment semantics plus the fail-safe parse behaviour that stops the update check from ever throwing.
/// </summary>
public class UpdateComparisonTests
{
    /// <summary>
    /// Invokes the production comparison and collects every warning it emits, so tests can distinguish a parsed decision from the fail-safe path.
    /// </summary>
    private static (bool UpdateAvailable, List<string> Warnings) Check(
        string? updateVersion,
        string? installedForkVersion,
        string? installedUpstreamVersion,
        string? installedLine)
    {
        var warnings = new List<string>();

        bool updateAvailable = DnsServerCore.DnsWebService.IsUpdateAvailable(
            updateVersion!,
            installedForkVersion!,
            installedUpstreamVersion!,
            installedLine!,
            warnings.Add);

        return (updateAvailable, warnings);
    }

    /// <summary>
    /// Case 1: an update on an older upstream base than the installed one must never be reported, and must not throw.
    /// The installed dev suffix wins over the contradicting "master" line value passed alongside it.
    /// </summary>
    [Fact]
    public void IsUpdateAvailable_WithOlderUpstreamBase_ReturnsFalse()
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            "15.4.0-pidoh.7",
            "15.5.0-pidoh-dev.1",
            "15.5.0",
            "master");

        // Assert
        Assert.False(updateAvailable);
        Assert.Empty(warnings);
    }

    /// <summary>
    /// Case 2: an update on a newer upstream base must always be reported, regardless of the fork line or increment.
    /// </summary>
    [Fact]
    public void IsUpdateAvailable_WithNewerUpstreamBase_ReturnsTrue()
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            "15.6.0-pidoh.1",
            "15.5.0-pidoh-dev.3",
            "15.5.0",
            "master");

        // Assert
        Assert.True(updateAvailable);
        Assert.Empty(warnings);
    }

    /// <summary>
    /// Case 3 test data: same upstream base and same release line, varying the fork increment (updateVersion, installedForkVersion, expected).
    /// </summary>
    public static IEnumerable<object[]> SameBaseSameLineScenarios => new List<object[]>
    {
        // (updateVersion, installedForkVersion, expectedUpdateAvailable)
        new object[] { "15.5.0-pidoh-dev.2", "15.5.0-pidoh-dev.1", true },  // higher increment on the dev line is an update
        new object[] { "15.5.0-pidoh-dev.1", "15.5.0-pidoh-dev.1", false }, // equal increment is not an update
        new object[] { "15.5.0-pidoh-dev.1", "15.5.0-pidoh-dev.2", false }, // lower increment is not an update
        new object[] { "15.5.0-pidoh.2", "15.5.0-pidoh.1", true },          // same rule holds on the stable line
        new object[] { "15.5.0-pidoh.1", "15.5.0-pidoh.1", false },         // stable equal increment is not an update
    };

    /// <summary>
    /// Case 3: with an identical upstream base and release line, only a strictly higher fork increment is an update.
    /// </summary>
    [Theory]
    [MemberData(nameof(SameBaseSameLineScenarios))]
    public void IsUpdateAvailable_WithSameBaseAndLine_ComparesForkIncrement(
        string updateVersion, string installedForkVersion, bool expectedUpdateAvailable)
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            updateVersion,
            installedForkVersion,
            "15.5.0",
            "dev");

        // Assert
        Assert.Equal(expectedUpdateAvailable, updateAvailable);
        Assert.Empty(warnings);
    }

    /// <summary>
    /// Case 4 test data: identical upstream base but opposite release lines (updateVersion, installedForkVersion).
    /// </summary>
    public static IEnumerable<object[]> CrossLineScenarios => new List<object[]>
    {
        // (updateVersion, installedForkVersion)
        new object[] { "15.5.0-pidoh.9", "15.5.0-pidoh-dev.1" },     // stable update vs installed dev
        new object[] { "15.5.0-pidoh-dev.9", "15.5.0-pidoh.1" },     // dev update vs installed stable
    };

    /// <summary>
    /// Case 4: a same-base update on the other release line is never reported, even when its fork increment is much higher.
    /// </summary>
    [Theory]
    [MemberData(nameof(CrossLineScenarios))]
    public void IsUpdateAvailable_WithSameBaseAcrossLines_ReturnsFalse(
        string updateVersion, string installedForkVersion)
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            updateVersion,
            installedForkVersion,
            "15.5.0",
            "dev");

        // Assert
        Assert.False(updateAvailable);
        Assert.Empty(warnings);
    }

    /// <summary>
    /// Case 5: a legacy plain numeric version parses successfully (no warning) and is simply not newer than the installed one.
    /// </summary>
    [Fact]
    public void IsUpdateAvailable_WithLegacyNumericVersionNotNewer_ReturnsFalseWithoutWarning()
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            "15.4.0",
            "15.5.0-pidoh-dev.1",
            "15.5.0",
            "dev");

        // Assert
        Assert.False(updateAvailable);
        Assert.Empty(warnings); // an empty warning list proves the legacy numeric value was parsed, not rejected
    }

    /// <summary>
    /// Case 5 test data: legacy plain numeric versions on both sides, compared by base and by the installed line (update, installedFork, installedUpstream, installedLine, expected).
    /// </summary>
    public static IEnumerable<object[]> LegacyNumericScenarios => new List<object[]>
    {
        // (updateVersion, installedForkVersion, installedUpstreamVersion, installedLine, expectedUpdateAvailable)
        new object[] { "15.4.0", "15.4.0", "15.4.0", "stable", false },     // equal legacy versions are not an update
        new object[] { "15.5.0", "15.4.0", "15.4.0", "stable", true },      // newer legacy base is an update
        new object[] { "15.4.0", "15.3.0", "15.3.0", "stable", true },      // newer legacy base vs older install is an update
        new object[] { "15.4.0", "15.4.0", "15.4.0", "master", false },     // branch name "master" maps to the stable line
    };

    /// <summary>
    /// Case 5: legacy numeric installs fall back to the installed line value, accepting both line names and fork branch names.
    /// </summary>
    [Theory]
    [MemberData(nameof(LegacyNumericScenarios))]
    public void IsUpdateAvailable_WithLegacyNumericVersions_ComparesBaseAndLine(
        string updateVersion, string installedForkVersion, string installedUpstreamVersion, string installedLine, bool expectedUpdateAvailable)
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            updateVersion,
            installedForkVersion,
            installedUpstreamVersion,
            installedLine);

        // Assert
        Assert.Equal(expectedUpdateAvailable, updateAvailable);
        Assert.Empty(warnings);
    }

    /// <summary>
    /// Case 6 test data: malformed update version strings and the fragment each warning message must name.
    /// </summary>
    public static IEnumerable<object[]> MalformedUpdateVersionScenarios => new List<object[]>
    {
        // (updateVersion, expectedWarningFragment)
        new object[] { "abc", "'abc'" },
        new object[] { "", "(empty)" },
        new object[] { "   ", "(empty)" },
        new object[] { "15.5", "'15.5'" },
        new object[] { "15.5.0-pidoh-dev", "'15.5.0-pidoh-dev'" },
        new object[] { "15.5.0-pidoh-x.1", "'15.5.0-pidoh-x.1'" },
        new object[] { "v15.5.0-pidoh-dev.1.2", "'v15.5.0-pidoh-dev.1.2'" },
    };

    /// <summary>
    /// Case 6: garbage and empty update versions return false, never throw, and emit exactly one warning naming the offending value.
    /// </summary>
    [Theory]
    [MemberData(nameof(MalformedUpdateVersionScenarios))]
    public void IsUpdateAvailable_WithMalformedUpdateVersion_ReturnsFalseWithSingleWarning(
        string updateVersion, string expectedWarningFragment)
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            updateVersion,
            "15.5.0-pidoh-dev.1",
            "15.5.0",
            "dev");

        // Assert
        Assert.False(updateAvailable);
        string warning = Assert.Single(warnings);
        Assert.Contains(expectedWarningFragment, warning);
        Assert.Contains("No update will be reported.", warning);
    }

    /// <summary>
    /// Case 7 test data: the leading "v" prefix is optional on the update side and on the installed side (updateVersion, installedForkVersion, expected).
    /// </summary>
    public static IEnumerable<object[]> PrefixScenarios => new List<object[]>
    {
        // (updateVersion, installedForkVersion, expectedUpdateAvailable)
        new object[] { "v15.6.0-pidoh.1", "15.5.0-pidoh-dev.1", true },   // "v" on update, none on installed
        new object[] { "15.6.0-pidoh.1", "v15.5.0-pidoh-dev.1", true },   // none on update, "v" on installed
        new object[] { "v15.6.0-pidoh.1", "v15.5.0-pidoh-dev.1", true },  // "v" on both
        new object[] { "v15.4.0-pidoh.7", "v15.5.0-pidoh-dev.1", false }, // both parse, so this is a real decision, not the fail-safe path
        new object[] { "v15.5.0-pidoh-dev.2", "v15.5.0-pidoh-dev.1", true },
    };

    /// <summary>
    /// Case 7: the leading "v" may be present or absent on either version and both forms parse identically.
    /// </summary>
    [Theory]
    [MemberData(nameof(PrefixScenarios))]
    public void IsUpdateAvailable_WithOptionalVPrefix_ParsesBothForms(
        string updateVersion, string installedForkVersion, bool expectedUpdateAvailable)
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            updateVersion,
            installedForkVersion,
            "15.5.0",
            "dev");

        // Assert
        Assert.Equal(expectedUpdateAvailable, updateAvailable);
        Assert.Empty(warnings);
    }

    /// <summary>
    /// Fail-safe coverage: a malformed installed fork version returns false with one warning naming the installed fork value.
    /// </summary>
    [Fact]
    public void IsUpdateAvailable_WithMalformedInstalledForkVersion_ReturnsFalseWithSingleWarning()
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            "15.6.0-pidoh.1",
            "not-a-fork-version",
            "15.5.0",
            "dev");

        // Assert
        Assert.False(updateAvailable);
        string warning = Assert.Single(warnings);
        Assert.Contains("installed fork", warning);
        Assert.Contains("'not-a-fork-version'", warning);
    }

    /// <summary>
    /// Fail-safe coverage: a malformed installed upstream version returns false with one warning naming the installed upstream value.
    /// </summary>
    [Fact]
    public void IsUpdateAvailable_WithMalformedInstalledUpstreamVersion_ReturnsFalseWithSingleWarning()
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            "15.6.0-pidoh.1",
            "15.5.0-pidoh-dev.1",
            "not-a-version",
            "dev");

        // Assert
        Assert.False(updateAvailable);
        string warning = Assert.Single(warnings);
        Assert.Contains("installed upstream", warning);
        Assert.Contains("'not-a-version'", warning);
    }

    /// <summary>
    /// Fail-safe coverage: null, empty and whitespace installed values never throw and always fall back to no update.
    /// </summary>
    [Theory]
    [InlineData(null, "15.5.0-pidoh-dev.1", "15.5.0")]
    [InlineData("15.6.0-pidoh.1", null, "15.5.0")]
    [InlineData("15.6.0-pidoh.1", "", "15.5.0")]
    [InlineData("15.6.0-pidoh.1", "15.5.0-pidoh-dev.1", null)]
    [InlineData("15.6.0-pidoh.1", "15.5.0-pidoh-dev.1", "")]
    public void IsUpdateAvailable_WithMissingInstalledValues_ReturnsFalseWithoutThrowing(
        string? updateVersion, string? installedForkVersion, string? installedUpstreamVersion)
    {
        // Act
        (bool updateAvailable, List<string> warnings) = Check(
            updateVersion,
            installedForkVersion,
            installedUpstreamVersion,
            "dev");

        // Assert
        Assert.False(updateAvailable);
        Assert.Single(warnings);
    }

    /// <summary>
    /// Fail-safe coverage: the comparison never throws for hostile input, even when the optional warning callback is omitted.
    /// </summary>
    [Fact]
    public void IsUpdateAvailable_WithNullWarningCallback_NeverThrows()
    {
        // Arrange
        string[] malformedVersions = { null!, "", "   ", "abc", "15.5", "15.5.0-pidoh-dev", "v", "-pidoh.1" };

        // Act and assert
        foreach (string malformed in malformedVersions)
        {
            Exception? exception = Record.Exception(() => DnsServerCore.DnsWebService.IsUpdateAvailable(malformed, "15.5.0-pidoh-dev.1", "15.5.0", "dev"));
            Assert.Null(exception);

            exception = Record.Exception(() => DnsServerCore.DnsWebService.IsUpdateAvailable("15.6.0-pidoh.1", malformed, "15.5.0", "dev"));
            Assert.Null(exception);

            exception = Record.Exception(() => DnsServerCore.DnsWebService.IsUpdateAvailable("15.6.0-pidoh.1", "15.5.0-pidoh-dev.1", malformed, "dev"));
            Assert.Null(exception);

            Assert.False(DnsServerCore.DnsWebService.IsUpdateAvailable(malformed, malformed, malformed, malformed));
        }
    }

    /// <summary>
    /// Determinism coverage: the comparison is a pure function, so repeating every scenario must return the same verdict and no warnings.
    /// </summary>
    [Fact]
    public void IsUpdateAvailable_IsDeterministicAcrossRepeatedCalls()
    {
        // Act and assert
        for (int i = 0; i < 5; i++)
        {
            (bool updateAvailable, List<string> warnings) = Check("15.6.0-pidoh.1", "15.5.0-pidoh-dev.3", "15.5.0", "dev");
            Assert.True(updateAvailable);
            Assert.Empty(warnings);

            (updateAvailable, warnings) = Check("15.5.0-pidoh-dev.2", "15.5.0-pidoh-dev.1", "15.5.0", "dev");
            Assert.True(updateAvailable);
            Assert.Empty(warnings);

            (updateAvailable, warnings) = Check("15.4.0-pidoh.7", "15.5.0-pidoh-dev.1", "15.5.0", "dev");
            Assert.False(updateAvailable);
            Assert.Empty(warnings);
        }
    }
}
