FROM golang:1.24-alpine AS builder

# g++ provides libstdc++ for linking go-duckdb (CGO).
# hadolint ignore=DL3018
RUN apk add --no-cache gcc g++ musl-dev sqlite-dev python3

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -o iota ./cmd/iota

FROM alpine:3.19

# hadolint ignore=DL3018
RUN apk add --no-cache python3 sqlite-libs ca-certificates libstdc++

WORKDIR /app

COPY --from=builder /build/iota /app/iota
COPY --from=builder /build/engines/iota /app/engines/iota

RUN mkdir -p /data/events /data/rules /data/state && \
    chmod +x /app/iota

VOLUME ["/data/events", "/data/rules", "/data/state"]

EXPOSE 8080

ENTRYPOINT ["/app/iota"]
CMD ["--mode=watch", "--events-dir=/data/events", "--rules=/data/rules", "--state=/data/state/iota.db"]
