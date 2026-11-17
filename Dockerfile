FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p banshee-server

FROM debian:bookworm-slim
# ca-certificates: to talk to Let's Encrypt
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 banshee && mkdir /data && chown banshee /data
COPY --from=build /src/target/release/banshee-server /usr/local/bin/banshee-server
USER banshee
ENV BANSHEE_BIND=0.0.0.0:7700 BANSHEE_DATA=/data
VOLUME /data
# 8080: the Let's Encrypt challenge (map the host's port 80 to it)
EXPOSE 7700/udp 8080/tcp
CMD ["banshee-server"]
