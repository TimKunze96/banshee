# Banshee

A voice chat server you run yourself, written in Rust. Wisp whispers, Banshee
screams: it's the server side for [Wisp](https://github.com/TimKunze96/wisp),
so a group can talk without a TeamSpeak license.

What works: a channel tree with passwords, user limits, talk power and
temporary channels; channel, server and private chat; pokes; whispering;
roles with permissions (Admin, Moderator, Member and Guest to start with, all
editable); kicks, bans and server mutes; one-time tokens that hand out roles.
Everything runs over QUIC (encrypted, one UDP port). Voice is Opus; the
server only forwards it and never decodes anything.

People are known by a key their client makes and keeps, so roles and bans
stick across reconnects and name changes.

## Running a server

```sh
docker compose up -d
docker compose logs banshee   # shows the certificate fingerprint and admin token
```

On first start the server prints a token. Whoever redeems it becomes admin
(in Wisp: admin window, Privilege keys, Use key), and it's gone after that.

That pulls the image from `ghcr.io/timkunze96/banshee`; `docker compose up -d
--build` builds it from the source instead.

It listens on UDP port 7700. Settings are environment variables:

- `BANSHEE_CHANNELS`: channels for a new server, comma separated (default `Lobby,Gaming,AFK`)
- `BANSHEE_BIND`: address and port (default `0.0.0.0:7700`)
- `BANSHEE_DATA`: where the certificate and `state.json` live (default `/data` in Docker)

Channels, roles, accounts, bans and tokens are kept in `state.json`. After
the first start, channels are managed from a client.

The server makes its own certificate on first start and keeps it in the data
volume. Clients pin its fingerprint, so there's no domain or CA needed.

## Connecting with Wisp

Add a bookmark in Wisp with the address `banshee://your-host:7700#fingerprint`.

## Trying it

```sh
cargo run -p banshee-client --bin banshee-cli -- 127.0.0.1:7700 yourname <fingerprint>
```

Lines you type are chat, `/join <id>` switches channel, `/redeem <token>`
uses a token, `/quit` leaves. Its identity is kept in `banshee-identity.der`.

## Layout

- `crates/proto`: the wire protocol (control messages, framing, voice datagrams)
- `crates/server`: the server
- `crates/client`: a client library (for Wisp) and `banshee-cli`

## Next

File sharing, avatars, then screen sharing and streaming.

## License

MIT
