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

using System;

namespace DnsServerCore
{
    /// <summary>
    /// Shared utility methods for DNS server operations.
    /// </summary>
    public static class DnsUtils
    {
        /// <summary>
        /// Normalizes domain input: extracts hostname from full URLs (stripping protocol, auth, port, path, query, fragment),
        /// or returns the input unchanged if it is a plain domain or IP address.
        /// </summary>
        public static string NormalizeDomainInput(string input)
        {
            if (Uri.TryCreate(input, UriKind.Absolute, out Uri uri) && !string.IsNullOrEmpty(uri.Host))
                return uri.Host;

            return input;
        }
    }
}
