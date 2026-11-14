use std::time::Duration;

use banshee_client::{Client, ServerMsg};
use banshee_server::{Config, Server};

const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(300);

async fn start(name: &str) -> (std::net::SocketAddr, String) {
    let server = Server::bind(Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name),
        channels: vec!["Lobby".into(), "Games".into()],
    })
    .unwrap();
    let out = (server.local_addr().unwrap(), server.fingerprint().to_string());
    tokio::spawn(server.run());
    out
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

#[tokio::test]
async fn chat_and_voice_stay_in_the_channel() {
    let (addr, fp) = start("relay").await;
    let mut a = Client::connect(addr, "A", Some(&fp)).await.unwrap();
    let mut b = Client::connect(addr, "B", Some(&fp)).await.unwrap();
    let mut c = Client::connect(addr, "C", Some(&fp)).await.unwrap();
    assert_eq!(c.users.len(), 3);

    let games = c.channels[1].id;
    c.join(games);
    let moved = |e: &ServerMsg| matches!(e, ServerMsg::UserMoved { .. });
    wait_for(&mut a, moved).await;
    wait_for(&mut b, moved).await;
    wait_for(&mut c, moved).await;

    a.chat("hi B");
    let chat = wait_for(&mut b, |e| matches!(e, ServerMsg::Chat { .. })).await;
    assert_eq!(chat, ServerMsg::Chat { from: a.you, channel: a.channels[0].id, text: "hi B".into() });
    // the sender gets its own line back
    wait_for(&mut a, |e| matches!(e, ServerMsg::Chat { .. })).await;

    a.send_voice(1, b"opus frame").unwrap();
    let v = tokio::time::timeout(WAIT, b.recv_voice()).await.unwrap().unwrap();
    assert_eq!((v.from, v.seq, v.opus.as_slice()), (a.you, 1, &b"opus frame"[..]));

    // C is in another channel and hears and reads nothing
    assert!(tokio::time::timeout(QUIET, c.recv_voice()).await.is_err());
    assert!(tokio::time::timeout(QUIET, c.next_event()).await.is_err());
    // A doesn't hear itself
    assert!(tokio::time::timeout(QUIET, a.recv_voice()).await.is_err());

    let a_id = a.you;
    a.close().await;
    let left = wait_for(&mut b, |e| matches!(e, ServerMsg::UserLeft { .. })).await;
    assert_eq!(left, ServerMsg::UserLeft { id: a_id });
}

#[tokio::test]
async fn refuses_a_wrong_fingerprint() {
    let (addr, _) = start("pinning").await;
    let wrong = "00".repeat(32);
    assert!(Client::connect(addr, "A", Some(&wrong)).await.is_err());
}

#[tokio::test]
async fn refuses_empty_names() {
    let (addr, fp) = start("names").await;
    let err = Client::connect(addr, "  ", Some(&fp)).await.err().unwrap();
    assert!(err.to_string().contains("names need"), "{err}");
}

#[tokio::test]
async fn keeps_its_certificate() {
    let (_, first) = start("keeps-cert").await;
    let (_, second) = start("keeps-cert").await;
    assert_eq!(first, second);
}
