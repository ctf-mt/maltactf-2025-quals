FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY src/TemplateService.csproj .
RUN dotnet restore ./TemplateService.csproj

COPY src .
WORKDIR /src

RUN dotnet build TemplateService.csproj -c Release -o /app/build

FROM build AS publish
RUN dotnet publish TemplateService.csproj -c Release -o /app/publish

FROM ubuntu:24.04 AS readflag

RUN apt update && apt install -y build-essential
COPY readflag/readflag.c .
RUN gcc readflag.c -static -o /readflag
RUN chmod u+s /readflag
RUN rm readflag.c

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

COPY --from=readflag /readflag /readflag
COPY flag.txt /flag.txt
RUN chmod 400 /flag.txt

COPY --from=publish /app/publish .

USER app

ENTRYPOINT ["dotnet", "TemplateService.dll"]
