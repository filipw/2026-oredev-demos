FROM mcr.microsoft.com/dotnet/sdk:10.0-resolute AS build
WORKDIR /src
COPY TlsPurePqc.csproj Program.cs ./
RUN dotnet publish -c Release -o /app && mkdir /certs

# Ubuntu 26.04 LTS ships OpenSSL 3.5 - chiseled means no shell, no package manager and no OpenSSL CLI
FROM mcr.microsoft.com/dotnet/aspnet:10.0-resolute-chiseled
WORKDIR /app
COPY --from=build /app .
COPY --from=build --chown=$APP_UID /certs /certs
COPY openssl-pqc.cnf /etc/ssl/openssl-pqc.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-pqc.cnf
ENV ASPNETCORE_HTTP_PORTS=
EXPOSE 8443

ENTRYPOINT ["dotnet", "TlsPurePqc.dll"]
