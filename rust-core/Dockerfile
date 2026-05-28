FROM rustlang/rust:nightly-slim AS builder

WORKDIR /usr/src/dvel

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY src/ ./src/
COPY benches/ ./benches/

RUN cargo build --release --features "bft parallel" --bin dvel-bft-node

FROM debian:bookworm-slim

WORKDIR /var/lib/dvel

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/dvel/target/release/dvel-bft-node /usr/local/bin/dvel-bft-node

EXPOSE 9001 7001

ENTRYPOINT ["dvel-bft-node"]
