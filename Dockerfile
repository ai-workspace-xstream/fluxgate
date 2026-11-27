# Multi-stage build for Fluxgate lightweight L7 proxy
FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev cmake build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY tests ./tests
COPY examples ./examples

RUN cargo build --release --bin fluxgate \
    && strip target/release/fluxgate

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 fluxgate \
    && useradd -u 10001 -g 10001 -m -s /usr/sbin/nologin fluxgate \
    && mkdir -p /etc/fluxgate /var/lib/fluxgate/acme \
    && chown -R 10001:10001 /etc/fluxgate /var/lib/fluxgate

COPY --from=builder /src/target/release/fluxgate /usr/local/bin/fluxgate

USER 10001:10001
EXPOSE 8080 9102

ENTRYPOINT ["fluxgate"]
CMD ["run", "--config", "/etc/fluxgate/Fluxgatefile"]
