# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=docker
WORKDIR /src
COPY go.mod ./
COPY . .
RUN GOARM="${TARGETVARIANT#v}" CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/golangtakserver ./cmd/golangtakserver \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/golangtakserver /usr/local/bin/golangtakserver
COPY --from=build --chown=65532:65532 /out/data /data
ENV GOLANGTAKSERVER_DATA=/data
VOLUME /data
EXPOSE 8087/tcp 8087/udp 8088/tcp 8089/tcp 8080/tcp 8443/tcp 8446/tcp 8090/tcp 19023/tcp 8554/tcp 1935/tcp 8000/udp 8001/udp 64738/tcp 64738/udp
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 CMD ["golangtakserver", "selftest"]
ENTRYPOINT ["golangtakserver"]
CMD ["run"]
