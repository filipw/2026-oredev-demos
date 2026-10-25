FROM mcr.microsoft.com/dotnet/sdk:10.0-resolute AS build
WORKDIR /src
COPY TlsHybridPqc.csproj Program.cs ./
RUN dotnet publish -c Release -o /app

# Ubuntu 26.04 LTS ships OpenSSL 3.5, whose default groups already put X25519MLKEM768 first - no extra configuration
FROM mcr.microsoft.com/dotnet/aspnet:10.0-resolute-chiseled
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=
EXPOSE 8443

ENTRYPOINT ["dotnet", "TlsHybridPqc.dll"]
