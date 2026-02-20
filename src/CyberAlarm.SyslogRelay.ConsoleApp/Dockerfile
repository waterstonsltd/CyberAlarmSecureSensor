# This stage is used when running from VS in debug mode
FROM mcr.microsoft.com/dotnet/runtime:10.0-noble-chiseled AS base
ARG BUILD_NUMBER=unknown
ARG DATA_PATH=/var/lib/syslog-relay
ARG DROP_PATH=$DATA_PATH/drop
ARG STATUS_ENDPOINT=unknown

ENV BuildVersion=$BUILD_NUMBER
ENV FileWatcherDropPath=$DROP_PATH
ENV StatusEndpoint=$STATUS_ENDPOINT

USER $APP_UID
WORKDIR $DATA_PATH
WORKDIR /app

# This stage is used to publish the console app to be copied to the final stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS publish
ARG BUILD_CONFIGURATION=Release

WORKDIR /src
COPY ["CyberAlarm.SyslogRelay.ConsoleApp/CyberAlarm.SyslogRelay.ConsoleApp.csproj", "CyberAlarm.SyslogRelay.ConsoleApp/"]
COPY ["CyberAlarm.SyslogRelay.Domain/CyberAlarm.SyslogRelay.Domain.csproj", "CyberAlarm.SyslogRelay.Domain/"]
COPY ["CyberAlarm.EventBundler/CyberAlarm.EventBundler.csproj", "CyberAlarm.EventBundler/"]
COPY ["CyberAlarm.SyslogRelay.Common/CyberAlarm.SyslogRelay.Common.csproj", "CyberAlarm.SyslogRelay.Common/"]
RUN dotnet restore "./CyberAlarm.SyslogRelay.ConsoleApp/CyberAlarm.SyslogRelay.ConsoleApp.csproj"
COPY . .

WORKDIR /src/CyberAlarm.SyslogRelay.ConsoleApp
RUN dotnet publish "./CyberAlarm.SyslogRelay.ConsoleApp.csproj" \
    --no-restore -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in release mode
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "CyberAlarm.SyslogRelay.ConsoleApp.dll"]