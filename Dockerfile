# syntax=docker/dockerfile:1
# go-duckdb ships a glibc-linked libduckdb.a; musl (Alpine) cannot link it. Use Debian (glibc).
#
# EKS managed nodes are usually linux/amd64. Building on Apple Silicon defaults to arm64 and
# yields "exec format error" on the cluster — build with:
#   docker build --platform linux/amd64 -t <image:tag> .
FROM golang:1.25-bookworm AS builder

# DinD/k8s often hit slow IPv6 to deb.debian.org (apt retries ~30s per index). Force IPv4.
# Cache mounts speed repeat builds (same runner / BuildKit layer cache).
# hadolint ignore=DL3008
RUN --mount=type=cache,target=/var/cache/apt,id=apt-arch-builder \
    --mount=type=cache,target=/var/lib/apt/lists,id=apt-lists-builder \
    set -eux; \
    printf 'Acquire::ForceIPv4 "true";\n' >/etc/apt/apt.conf.d/99force-ipv4; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      gcc g++ libc6-dev libsqlite3-dev python3; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -o iota ./cmd/iota

FROM debian:bookworm-slim

# hadolint ignore=DL3008
RUN --mount=type=cache,target=/var/cache/apt,id=apt-arch-runtime \
    --mount=type=cache,target=/var/lib/apt/lists,id=apt-lists-runtime \
    set -eux; \
    printf 'Acquire::ForceIPv4 "true";\n' >/etc/apt/apt.conf.d/99force-ipv4; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      python3 ca-certificates libsqlite3-0 libstdc++6; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/iota /app/iota
COPY --from=builder /build/engines/iota /app/engines/iota
# Ship bundled detection rules in-image (no per-rule Kubernetes ConfigMap).
COPY --from=builder /build/rules /app/rules

RUN mkdir -p /data/events /data/rules /data/state && \
    chmod +x /app/iota

VOLUME ["/data/events", "/data/rules", "/data/state"]

EXPOSE 8080

ENTRYPOINT ["/app/iota"]
CMD ["--mode=watch", "--events-dir=/data/events", "--rules=/data/rules", "--state=/data/state/iota.db"]
