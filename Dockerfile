FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p banshee-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 banshee && mkdir /data && chown banshee /data
COPY --from=build /src/target/release/banshee-server /usr/local/bin/banshee-server
USER banshee
ENV BANSHEE_BIND=0.0.0.0:7700 BANSHEE_DATA=/data
VOLUME /data
EXPOSE 7700/udp
CMD ["banshee-server"]
