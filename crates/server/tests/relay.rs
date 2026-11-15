use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use banshee_client::{
    ChannelEdit, ChatTarget, Client, ClientMsg, Identity, Leave, NewChannel, Options, ServerMsg, Whisper,
};
use banshee_server::{Config, Server};

const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(300);

struct Running {
    addr: SocketAddr,
    fp: String,
    token: Option<String>,
    task: tokio::task::JoinHandle<()>,
}

fn data_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}

/// A server on a fresh data dir (or the one left by `start` before, with `keep`).
async fn start(name: &str, keep: bool) -> Running {
    let dir = data_dir(name);
    if !keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    let server = Server::bind(Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir,
        channels: vec!["Lobby".into(), "Games".into()],
    })
    .unwrap();
    let (addr, fp, token) = (server.local_addr().unwrap(), server.fingerprint().to_string(), server.admin_token());
    Running { addr, fp, token, task: tokio::spawn(server.run()) }
}

async fn connect(s: &Running, name: &str, id: &Identity) -> anyhow::Result<Client> {
    Client::connect(s.addr, Options { name, identity: id, fingerprint: Some(&s.fp), password: None }).await
}

/// The next event that matches, skipping the rest.
async fn wait_for(client: &mut Client, want: impl Fn(&ServerMsg) -> bool) -> ServerMsg {
    tokio::time::timeout(WAIT, async {
        loop {
            let e = client.next_event().await.expect("disconnected");
            if want(&e) {
                return e;
            }
        }
    })
    .await
    .expect("event didn't come")
}

/// Wait until the server has dealt with everything sent so far, by sending
/// a chat to ourselves and waiting for it.
async fn sync(c: &mut Client) {
    let me = c.you;
    c.send(ClientMsg::Chat { to: ChatTarget::User(me), text: "sync".into() });
    wait_for(c, |e| matches!(e, ServerMsg::Chat { text, .. } if text == "sync")).await;
}

async fn admin(s: &Running, name: &str) -> Client {
    let mut a = connect(s, name, &Identity::generate()).await.unwrap();
    a.send(ClientMsg::Redeem { token: s.token.clone().unwrap() });
    wait_for(&mut a, |e| matches!(e, ServerMsg::Notice { .. })).await;
    a
}

fn moved(id: u32, channel: u32) -> impl Fn(&ServerMsg) -> bool {
    move |e| matches!(e, ServerMsg::UserChanged(u) if u.id == id && u.channel == channel)
}

#[tokio::test]
async fn chat_and_voice_stay_in_the_channel() {
    let s = start("relay", false).await;
    let mut a = connect(&s, "A", &Identity::generate()).await.unwrap();
    let mut b = connect(&s, "B", &Identity::generate()).await.unwrap();
    let mut c = connect(&s, "C", &Identity::generate()).await.unwrap();
    assert_eq!(c.users.len(), 3);

    let games = c.channels[1].id;
    c.join(games);
    wait_for(&mut a, moved(c.you, games)).await;
    wait_for(&mut b, moved(c.you, games)).await;
    let me = c.you;
    wait_for(&mut c, moved(me, games)).await;

    a.chat("hi B");
    let chat = wait_for(&mut b, |e| matches!(e, ServerMsg::Chat { .. })).await;
    assert_eq!(chat, ServerMsg::Chat { from: a.you, to: ChatTarget::Channel, text: "hi B".into() });
    // the sender gets its own line back
    wait_for(&mut a, |e| matches!(e, ServerMsg::Chat { .. })).await;

    a.send_voice(1, b"opus frame").unwrap();
    let v = tokio::time::timeout(WAIT, b.recv_voice()).await.unwrap().unwrap();
    assert_eq!((v.from, v.seq, v.whisper, v.opus.as_slice()), (a.you, 1, false, &b"opus frame"[..]));

    // C is in another channel and hears and reads nothing
    assert!(tokio::time::timeout(QUIET, c.recv_voice()).await.is_err());
    assert!(tokio::time::timeout(QUIET, c.next_event()).await.is_err());
    // A doesn't hear itself
    assert!(tokio::time::timeout(QUIET, a.recv_voice()).await.is_err());

    let a_id = a.you;
    a.close().await;
    let left = wait_for(&mut b, |e| matches!(e, ServerMsg::UserLeft { .. })).await;
    assert_eq!(left, ServerMsg::UserLeft { id: a_id, reason: Leave::Quit });
}

#[tokio::test]
async fn refuses_a_wrong_fingerprint() {
    let s = start("pinning", false).await;
    let wrong = "00".repeat(32);
    let id = Identity::generate();
    let opts = Options { name: "A", identity: &id, fingerprint: Some(&wrong), password: None };
    assert!(Client::connect(s.addr, opts).await.is_err());
}

#[tokio::test]
async fn refuses_empty_names() {
    let s = start("names", false).await;
    let err = connect(&s, "  ", &Identity::generate()).await.err().unwrap();
    assert!(err.to_string().contains("names need"), "{err}");
}

#[tokio::test]
async fn keeps_certificate_roles_and_channels() {
    let s = start("restart", false).await;
    let id = Identity::generate();
    let mut a = connect(&s, "A", &id).await.unwrap();
    assert_eq!(a.users[0].role, 3, "new people are members");
    a.send(ClientMsg::Redeem { token: s.token.clone().unwrap() });
    let notice = wait_for(&mut a, |e| matches!(e, ServerMsg::Notice { .. })).await;
    assert_eq!(notice, ServerMsg::Notice { text: "You're Admin now".into() });
    let new = NewChannel { name: "Raid".into(), permanent: true, ..Default::default() };
    a.send(ClientMsg::CreateChannel(new));
    wait_for(&mut a, |e| matches!(e, ServerMsg::Channels(c) if c.len() == 3)).await;
    a.close().await;
    s.task.abort();
    let _ = s.task.await;

    let again = start("restart", true).await;
    assert_eq!(again.fp, s.fp);
    assert_eq!(again.token, None, "the admin token is used up");
    let a = connect(&again, "A", &id).await.unwrap();
    assert_eq!(a.users.iter().find(|u| u.id == a.you).unwrap().role, 1);
    assert_eq!(a.channels.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Lobby", "Games", "Raid"]);
}

#[tokio::test]
async fn members_cant_moderate() {
    let s = start("members", false).await;
    let mut a = connect(&s, "A", &Identity::generate()).await.unwrap();
    let b = connect(&s, "B", &Identity::generate()).await.unwrap();
    a.send(ClientMsg::Kick { user: b.you, reason: String::new(), server: true });
    let err = wait_for(&mut a, |e| matches!(e, ServerMsg::Error { .. })).await;
    assert_eq!(err, ServerMsg::Error { message: "you're not allowed to do that".into() });
    a.send(ClientMsg::CreateChannel(NewChannel { name: "Mine".into(), permanent: true, ..Default::default() }));
    wait_for(&mut a, |e| matches!(e, ServerMsg::Error { .. })).await;
}

#[tokio::test]
async fn temporary_channels_go_when_empty() {
    let s = start("temp", false).await;
    let mut a = connect(&s, "A", &Identity::generate()).await.unwrap();
    a.send(ClientMsg::CreateChannel(NewChannel { name: "Quick".into(), ..Default::default() }));
    let ServerMsg::Channels(list) = wait_for(&mut a, |e| matches!(e, ServerMsg::Channels(_))).await else {
        unreachable!()
    };
    let quick = list.iter().find(|c| c.name == "Quick").unwrap().id;
    assert!(!list.iter().find(|c| c.id == quick).unwrap().permanent);
    let me = a.you;
    wait_for(&mut a, moved(me, quick)).await;
    a.join(a.channels[0].id);
    wait_for(&mut a, |e| matches!(e, ServerMsg::Channels(c) if c.len() == 2)).await;
}

#[tokio::test]
async fn kicks_and_bans() {
    let s = start("bans", false).await;
    let mut admin = admin(&s, "Admin").await;
    let mallory_id = Identity::generate();
    let mut mallory = connect(&s, "Mallory", &mallory_id).await.unwrap();
    let games = admin.channels[1].id;
    mallory.join(games);
    wait_for(&mut admin, moved(mallory.you, games)).await;

    admin.send(ClientMsg::Kick { user: mallory.you, reason: "out".into(), server: false });
    let me = mallory.you;
    wait_for(&mut mallory, moved(me, admin.channels[0].id)).await;
    let notice = wait_for(&mut mallory, |e| matches!(e, ServerMsg::Notice { .. })).await;
    assert_eq!(notice, ServerMsg::Notice { text: "Admin kicked you from the channel: out".into() });

    // Mallory can't kick back
    mallory.send(ClientMsg::Kick { user: admin.you, reason: String::new(), server: true });
    wait_for(&mut mallory, |e| matches!(e, ServerMsg::Error { .. })).await;

    admin.send(ClientMsg::Ban { user: mallory.you, reason: "spam".into(), secs: Some(600) });
    let gone = ServerMsg::UserLeft { id: mallory.you, reason: Leave::Banned { by: admin.you, reason: "spam".into() } };
    assert_eq!(wait_for(&mut mallory, |e| matches!(e, ServerMsg::UserLeft { .. })).await, gone);
    assert!(tokio::time::timeout(WAIT, mallory.next_event()).await.unwrap().is_none(), "connection closed");
    assert_eq!(wait_for(&mut admin, |e| matches!(e, ServerMsg::UserLeft { .. })).await, gone);

    let err = connect(&s, "Mallory", &mallory_id).await.err().unwrap();
    assert!(err.to_string().contains("banned"), "{err}");
    // the address is banned too
    let err = connect(&s, "M2", &Identity::generate()).await.err().unwrap();
    assert!(err.to_string().contains("banned"), "{err}");

    admin.send(ClientMsg::ListBans);
    let ServerMsg::Bans(bans) = wait_for(&mut admin, |e| matches!(e, ServerMsg::Bans(_))).await else { unreachable!() };
    assert_eq!(bans.len(), 1);
    admin.send(ClientMsg::Unban { id: bans[0].id });
    wait_for(&mut admin, |e| matches!(e, ServerMsg::Bans(b) if b.is_empty())).await;
    connect(&s, "Mallory", &mallory_id).await.unwrap();
}

#[tokio::test]
async fn channel_passwords() {
    let s = start("passwords", false).await;
    let mut admin = admin(&s, "Admin").await;
    let games = admin.channels[1].id;
    let edit = ChannelEdit { password: Some(Some("sesame".into())), ..Default::default() };
    admin.send(ClientMsg::EditChannel { id: games, edit });
    wait_for(&mut admin, |e| matches!(e, ServerMsg::Channels(c) if c[1].has_password)).await;

    let mut b = connect(&s, "B", &Identity::generate()).await.unwrap();
    b.join(games);
    assert_eq!(
        wait_for(&mut b, |e| matches!(e, ServerMsg::NeedPassword { .. })).await,
        ServerMsg::NeedPassword { channel: games, wrong: false }
    );
    b.send(ClientMsg::Join { channel: games, password: Some("nope".into()) });
    assert_eq!(
        wait_for(&mut b, |e| matches!(e, ServerMsg::NeedPassword { .. })).await,
        ServerMsg::NeedPassword { channel: games, wrong: true }
    );
    b.send(ClientMsg::Join { channel: games, password: Some("sesame".into()) });
    let me = b.you;
    wait_for(&mut b, moved(me, games)).await;
    // admins don't need it
    admin.join(games);
    let me = admin.you;
    wait_for(&mut admin, moved(me, games)).await;
}

#[tokio::test]
async fn private_messages_and_pokes() {
    let s = start("private", false).await;
    let mut a = connect(&s, "A", &Identity::generate()).await.unwrap();
    let mut b = connect(&s, "B", &Identity::generate()).await.unwrap();
    let mut c = connect(&s, "C", &Identity::generate()).await.unwrap();
    a.send(ClientMsg::Chat { to: ChatTarget::User(b.you), text: "psst".into() });
    let want = ServerMsg::Chat { from: a.you, to: ChatTarget::User(b.you), text: "psst".into() };
    assert_eq!(wait_for(&mut b, |e| matches!(e, ServerMsg::Chat { .. })).await, want);
    assert_eq!(wait_for(&mut a, |e| matches!(e, ServerMsg::Chat { .. })).await, want);
    a.send(ClientMsg::Poke { user: b.you, text: "hey".into() });
    let poke = wait_for(&mut b, |e| matches!(e, ServerMsg::Poke { .. })).await;
    assert_eq!(poke, ServerMsg::Poke { from: a.you, text: "hey".into() });
    sync(&mut a).await;
    assert!(tokio::time::timeout(QUIET, c.next_event()).await.is_err(), "C saw none of it");
}

#[tokio::test]
async fn who_gets_heard() {
    let s = start("talk", false).await;
    let admin = admin(&s, "Admin").await;
    let mut a = connect(&s, "A", &Identity::generate()).await.unwrap();
    let b = connect(&s, "B", &Identity::generate()).await.unwrap();
    let games = admin.channels[1].id;
    b.join(games);
    wait_for(&mut a, moved(b.you, games)).await;

    // a whisper reaches B in the other channel, and only B
    a.send(ClientMsg::SetWhisper(Some(Whisper { channels: vec![], users: vec![b.you] })));
    sync(&mut a).await;
    a.send_voice(1, b"w").unwrap();
    let v = tokio::time::timeout(WAIT, b.recv_voice()).await.unwrap().unwrap();
    assert!(v.whisper);
    assert!(tokio::time::timeout(QUIET, admin.recv_voice()).await.is_err());
    a.send(ClientMsg::SetWhisper(None));
    sync(&mut a).await;

    // a moderated lobby: members (talk power 10) need it granted
    let lobby = admin.channels[0].id;
    let edit = ChannelEdit { talk_power: Some(20), ..Default::default() };
    admin.send(ClientMsg::EditChannel { id: lobby, edit });
    wait_for(&mut a, |e| matches!(e, ServerMsg::Channels(c) if c[0].talk_power == 20)).await;
    a.send_voice(2, b"x").unwrap();
    assert!(tokio::time::timeout(QUIET, admin.recv_voice()).await.is_err());
    admin.send(ClientMsg::GrantTalk { user: a.you, granted: true });
    wait_for(&mut a, |e| matches!(e, ServerMsg::UserChanged(u) if u.talk_granted)).await;
    a.send_voice(3, b"y").unwrap();
    assert_eq!(tokio::time::timeout(WAIT, admin.recv_voice()).await.unwrap().unwrap().seq, 3);

    // a server mute silences them again
    admin.send(ClientMsg::ServerMute { user: a.you, muted: true });
    wait_for(&mut a, |e| matches!(e, ServerMsg::UserChanged(u) if u.server_muted)).await;
    a.send_voice(4, b"z").unwrap();
    assert!(tokio::time::timeout(QUIET, admin.recv_voice()).await.is_err());
}
