FROM rust:latest AS builder

WORKDIR /app

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./src ./src
RUN cargo build --release

FROM debian:latest as client

COPY --from=builder /app/target/release/client /app/client
RUN apt-get update && apt-get -y install ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app/

CMD ["/app/client"]

FROM debian:latest as server

COPY --from=builder /app/target/release/quote_server /app/server
RUN apt-get update && apt-get -y install ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app/

EXPOSE 8000

CMD ["/app/server"]

FROM debian:latest as guide

COPY --from=builder /app/target/release/guide /app/guide
RUN apt-get update && apt-get -y install ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app/

EXPOSE 4001
EXPOSE 4002
EXPOSE 4003

CMD ["/app/guide"]
