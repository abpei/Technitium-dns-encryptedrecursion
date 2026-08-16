# syntax=docker.io/docker/dockerfile:1

# Stage 1: Build the fork from source
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Install git for cloning dependencies
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Clone TechnitiumLibrary dependency
RUN git clone --depth 1 https://github.com/TechnitiumSoftware/TechnitiumLibrary.git TechnitiumLibrary

# Copy the fork source (build context should be the fork repo root)
COPY DnsServerApp/ DnsServer/DnsServerApp/
COPY DnsServerCore/ DnsServer/DnsServerCore/
COPY DnsServerCore.ApplicationCommon/ DnsServer/DnsServerCore.ApplicationCommon/
COPY DnsServerCore.HttpApi/ DnsServer/DnsServerCore.HttpApi/
COPY DnsServer.sln DnsServer/
COPY .git/ DnsServer/.git/

# Build TechnitiumLibrary dependencies
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release && \
    dotnet build TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release && \
    dotnet build TechnitiumLibrary/TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj -c Release

# Build and publish the DNS server
RUN dotnet publish DnsServer/DnsServerApp/DnsServerApp.csproj -c Release -o /app/publish

# Stage 2: Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:10.0

# Add the MS repo to install `libmsquic` to support DNS-over-QUIC:
ADD --link https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb /
RUN <<HEREDOC
  dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb
  apt-get update && apt-get install -y libmsquic dnsutils iputils-ping
  apt-get clean -y && rm -rf /var/lib/apt/lists/*
  mkdir /etc/dns
HEREDOC

# Copy the published application
WORKDIR /opt/technitium/dns
COPY --from=build /app/publish /opt/technitium/dns

ENTRYPOINT ["/usr/bin/dotnet", "/opt/technitium/dns/DnsServerApp.dll"]
CMD ["/etc/dns"]
