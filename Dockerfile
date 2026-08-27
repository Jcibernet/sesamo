# Sésamo production image: multi-stage, distroless, static binary.
# Build:  docker build -t sesamo .
# Run:    docker run -p 7777:7777 -e SESAMO_DATABASE_URL=... sesamo serve
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build version, stamped into the binary (sesamo version). Declared here,
# after the dependency layers, so changing it does not invalidate the
# go mod download cache. Release builds pass --build-arg VERSION=vX.Y.Z.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /sesamo ./cmd/sesamo

# Distroless static: no shell, no libc, no package manager — the binary
# and CA certs, nothing else. Runs as nonroot (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /sesamo /sesamo
EXPOSE 7777
ENTRYPOINT ["/sesamo"]
CMD ["serve"]
