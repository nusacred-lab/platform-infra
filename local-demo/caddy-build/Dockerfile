FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY main.go ./
RUN mkdir -p /out && CGO_ENABLED=0 go list -mod=readonly -deps . > /out/go-packages.txt && CGO_ENABLED=0 GOMAXPROCS=4 go build -p=4 -mod=readonly -trimpath -ldflags='-s -w' -o /out/caddy .

# This probe uses manually installed certificates and has no outbound connections.
FROM scratch
COPY --from=build /out/caddy /usr/bin/caddy
COPY --from=build /out/go-packages.txt /usr/share/nusacred/go-packages.txt
USER 65532:65532
CMD ["/usr/bin/caddy", "version"]
