# syntax=docker/dockerfile:1.7

FROM rust:1-alpine AS builder

WORKDIR /src

RUN apk add --no-cache \
        build-base \
        ca-certificates \
        clang \
        cmake \
        ninja-build \
        perl \
        pkgconf

COPY Cargo.toml Cargo.lock build.rs ./
COPY protos ./protos
COPY src ./src

ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    if [ -n "$CARGO_FEATURES" ]; then \
        cargo build --release --locked --bin shitspeak-rs --features "$CARGO_FEATURES"; \
    else \
        cargo build --release --locked --bin shitspeak-rs; \
    fi \
    && cp target/release/shitspeak-rs /tmp/shitspeak-rs

FROM alpine:3.20 AS runtime

RUN addgroup -S shitspeak \
    && adduser -S -G shitspeak -h /app -s /sbin/nologin shitspeak \
    && apk add --no-cache ca-certificates \
    && mkdir -p /app/data /app/s2s-state \
    && chown -R shitspeak:shitspeak /app

COPY --from=builder /tmp/shitspeak-rs /usr/local/bin/shitspeak-rs

USER shitspeak
WORKDIR /app

EXPOSE 64738/tcp 64738/udp 64739/tcp 64740/udp 64741/tcp 64742/udp 64750/tcp

ENTRYPOINT ["/usr/local/bin/shitspeak-rs"]