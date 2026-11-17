# Banshee

A voice chat server you run yourself, written in Rust. Wisp whispers, Banshee
screams: it's the server side for [Wisp](https://github.com/TimKunze96/wisp),
so a group can talk without a TeamSpeak license.

What works: a channel tree with passwords, user limits, talk power and
temporary channels; channel, server and private chat; pokes; whispering;
roles with permissions (Admin, Moderator, Member and Guest to start with, all
editable); kicks, bans and server mutes; one-time tokens that hand out roles;
channel files; avatars; offline messages and a server log; screen sharing.
Everything runs over QUIC (encrypted, one UDP port). Voice is Opus and
screens are H.264; the server only forwards them and never decodes anything.

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
- `BANSHEE_DATA`: where the certificate, database and files live (default `/data` in Docker)
- `BANSHEE_MAX_FILE_MB`: biggest file upload (default 500)
- `BANSHEE_DOMAIN`: get a Let's Encrypt certificate for this domain (see below)
- `BANSHEE_ACME_EMAIL`: optional, for Let's Encrypt's expiry mails

Channels, roles, accounts, bans, tokens, offline messages and the log are
kept in `banshee.db` (SQLite), channel files under `files/` and avatars under
`avatars/`. A `state.json` from an older version is taken over on start.
After the first start, channels are managed from a client.

### With a domain

Point a domain at the server (an A record, AAAA for IPv6), set `BANSHEE_DOMAIN`
in `compose.yml`, and make sure UDP 7700 and TCP 80 reach it (TCP 80 only
for Let's Encrypt's check). The server gets a certificate on start, renews
it on its own and keeps it in the data volume. The link people share is then
just `banshee://voice.example.com`.

If it can't get one, the log says so and it retries every hour; until then it
uses its own certificate.

### Without a domain

The server makes its own certificate on first start and keeps it in the data
volume. Clients pin its fingerprint, which the log shows.

## Connecting with Wisp

Add a bookmark in Wisp with the address `banshee://voice.example.com` (with a
domain) or `banshee://your-host:7700#fingerprint` (without one). The port can
be left out when it's 7700.

## Trying it

```sh
cargo run -p banshee-client --bin banshee-cli -- 127.0.0.1:7700 yourname <fingerprint>
```

Lines you type are chat, `/join <id>` switches channel, `/redeem <token>`
uses a token, `/avatar <file>` sets a picture, `/quit` leaves. Its identity
is kept in `banshee-identity.der`.

## Layout

- `crates/proto`: the wire protocol (control messages, framing, voice datagrams, video streams)
- `crates/server`: the server
- `crates/client`: a client library (for Wisp) and `banshee-cli`

## License

MIT
