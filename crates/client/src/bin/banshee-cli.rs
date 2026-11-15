//! Talk to a Banshee server from the terminal: lines are chat, `/join <id>`
//! changes channel, `/redeem <token>` uses a token, `/quit` leaves. The
//! identity lives in `banshee-identity.der` in the current directory.
//!
//! banshee-cli <host:port> <name> [fingerprint]

use std::collections::HashMap;

use anyhow::{Context, Result};
use banshee_client::{Client, ClientMsg, Identity, Options, ServerMsg};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [addr, name, rest @ ..] = args.as_slice() else {
        eprintln!("usage: banshee-cli <host:port> <name> [fingerprint]");
        std::process::exit(2);
    };
    let addr = tokio::net::lookup_host(addr).await?.next().context("no address for that host")?;
    let identity = Identity::load_or_create("banshee-identity.der".as_ref())?;
    let opts = Options { name, identity: &identity, fingerprint: rest.first().map(String::as_str), password: None };
    let mut client = Client::connect(addr, opts).await?;
    println!("connected, server fingerprint {}", client.fingerprint);
    for c in &client.channels {
        println!("  channel {}: {}", c.id, c.name);
    }
    let mut names: HashMap<u32, String> = client.users.iter().map(|u| (u.id, u.name.clone())).collect();
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let Some(line) = line? else { break };
                match line.split_once(' ') {
                    Some(("/join", id)) => match id.trim().parse() {
                        Ok(id) => client.join(id),
                        Err(_) => println!("/join takes a channel id"),
                    },
                    Some(("/redeem", token)) => client.send(ClientMsg::Redeem { token: token.trim().into() }),
                    _ if line.trim() == "/quit" => break,
                    _ if line.trim().is_empty() => {}
                    _ => client.chat(&line),
                }
            }
            event = client.next_event() => {
                let Some(event) = event else { println!("disconnected"); break };
                let name = |id: u32| names.get(&id).cloned().unwrap_or_else(|| format!("#{id}"));
                match event {
                    ServerMsg::UserJoined(u) => {
                        println!("{} joined", u.name);
                        names.insert(u.id, u.name);
                    }
                    ServerMsg::UserLeft { id, reason } => {
                        println!("{} left ({reason:?})", name(id));
                        names.remove(&id);
                    }
                    ServerMsg::UserChanged(u) => {
                        names.insert(u.id, u.name);
                    }
                    ServerMsg::Chat { from, text, .. } => println!("<{}> {text}", name(from)),
                    ServerMsg::Poke { from, text } => println!("{} pokes you: {text}", name(from)),
                    ServerMsg::Notice { text } => println!("{text}"),
                    ServerMsg::Error { message } => println!("error: {message}"),
                    other => println!("{other:?}"),
                }
            }
        }
    }
    client.close().await;
    Ok(())
}
