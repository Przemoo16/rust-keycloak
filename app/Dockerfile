FROM docker.io/rust:1.78-slim-buster AS deps

WORKDIR /opt/app

RUN apt-get update \
    && apt-get upgrade -y \
    # Install dependencies for the OpenSSL (required by the "reqwest" package)
    && apt-get install --no-install-recommends -y make perl \
    && rm -rf /var/lib/apt/lists/*

RUN cargo init
COPY ./Cargo.toml ./Cargo.lock ./


FROM deps as dev

EXPOSE 80

RUN cargo install cargo-watch

RUN cargo build \
    && rm -f ./target/debug/deps/app*

COPY ./src ./src

CMD ["cargo", "watch", "-x", "run"]


FROM deps as build

RUN cargo build --release \
    && rm -f ./target/release/deps/app*

COPY ./src ./src
RUN cargo build --release


FROM docker.io/debian:12.5-slim

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 80

COPY --from=build /opt/app/target/release/app /usr/local/bin/app

CMD ["app"]

