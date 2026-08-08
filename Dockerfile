# Build a static-ish binary, then ship it on a minimal runtime image.
FROM rust:1.95-slim AS build

# rusqlite is vendored ("bundled" feature) and compiles SQLite from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libc6-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release && \
    rm -rf src

COPY src ./src
# Touch so cargo does not reuse the stub's fingerprint.
# Frontend assets are baked into the binary with include_str!, so they must be
# present at compile time. Without this COPY the build fails here rather than at
# runtime — which is the right place, but only if the directory is copied at all.
COPY assets ./assets
COPY templates ./templates
RUN touch src/main.rs src/lib.rs && cargo build --release


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/* && \
    useradd --system --uid 10001 --create-home xenon

COPY --from=build /src/target/release/xenon /usr/local/bin/xenon

# The data directory must be a mounted volume: it holds both xenon.db and the
# blob store, and losing either one loses published resources.
ENV XENON_DATA_DIR=/data \
    XENON_PORT=8787
RUN mkdir -p /data && chown xenon:xenon /data
VOLUME ["/data"]

USER xenon
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD ["/usr/local/bin/xenon", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/xenon"]
