# Banshee

A voice chat server you run yourself, written in Rust. Wisp whispers, Banshee
screams: it's the server side for [Wisp](https://github.com/TimKunze96/wisp),
so a group can talk without a TeamSpeak license.

It's an early prototype. What works: channels, text chat and voice relayed to
everyone in your channel, over QUIC (encrypted, one UDP port). Voice is Opus;
the server only forwards it and never decodes anything.

## Running a server

```sh
docker compose up -d
docker compose logs banshee   # shows the certificate fingerprint
```

It listens on UDP port 7700. Settings are environment variables:

- `BANSHEE_CHANNELS`: channel names, comma separated (default `Lobby,Gaming,AFK`)
- `BANSHEE_BIND`: address and port (default `0.0.0.0:7700`)
- `BANSHEE_DATA`: where the certificate is kept (default `/data` in Docker)

The server makes its own certificate on first start and keeps it in the data
volume. Clients pin its fingerprint, so there's no domain or CA needed.

## Trying it

```sh
cargo run -p banshee-client --bin banshee-cli -- 127.0.0.1:7700 yourname <fingerprint>
```

Lines you type are chat, `/join <id>` switches channel, `/quit` leaves.

## Layout

- `crates/proto`: the wire protocol (control messages, framing, voice datagrams)
- `crates/server`: the server
- `crates/client`: a client library (for Wisp) and `banshee-cli`

## Next

Voice in Wisp, accounts and permissions, then screen sharing and streaming.

## License

MIT
