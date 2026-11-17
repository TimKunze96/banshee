//! Watching shared screens: which layer each watcher gets, and the stream
//! that carries it to them.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use banshee_proto::video::{self, Packet};
use banshee_proto::{Quality, UserId};
use bytes::Bytes;
use tokio::sync::mpsc;

/// Packets waiting for a watcher before they start getting skipped (video
/// and sound, so about half a second).
const QUEUE: usize = 32;
/// How long a watcher stays on a layer before trying the next better one;
/// doubles each time that fails right away.
const PATIENCE: Duration = Duration::from_secs(4);
const MAX_PATIENCE: Duration = Duration::from_secs(60);
/// Trouble this soon after going up means going up was the problem.
const TOO_SOON: Duration = Duration::from_secs(5);
/// How often the connection is checked for congestion.
const CHECK_EVERY: Duration = Duration::from_millis(500);

pub struct Watcher {
    tx: mpsc::Sender<Bytes>,
    pub quality: Quality,
    /// The layer they get.
    layer: u8,
    /// The layer they should get; we switch at its next keyframe.
    target: u8,
    /// Skipping video until the next keyframe.
    waiting: bool,
    /// Their connection showed trouble (set by the forwarding task).
    congested: Arc<AtomicBool>,
    changed: Instant,
    patience: Duration,
}

/// What a packet means for the sharer.
#[derive(Default)]
pub struct Asks {
    /// Layers that need a keyframe, and whether that can't wait.
    pub keyframes: Vec<(u8, bool)>,
}

impl Asks {
    fn keyframe(&mut self, layer: u8, now: bool) {
        match self.keyframes.iter_mut().find(|(l, _)| *l == layer) {
            Some((_, n)) => *n |= now,
            None => self.keyframes.push((layer, now)),
        }
    }
}

impl Watcher {
    /// A watcher of a stream with `layers` layers, and the stream to them.
    pub fn start(conn: quinn::Connection, from: UserId, quality: Quality, layers: usize) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        let congested = Arc::new(AtomicBool::new(false));
        tokio::spawn(forward(conn, from, rx, congested.clone()));
        let layer = start_layer(quality, layers);
        Self {
            tx,
            quality,
            layer,
            target: layer,
            waiting: true,
            congested,
            changed: Instant::now(),
            patience: PATIENCE,
        }
    }

    /// The layer they need a keyframe on to get going.
    pub fn wants(&self) -> u8 {
        self.target
    }

    /// Change what they asked for; the layer that needs a keyframe, if any.
    pub fn set_quality(&mut self, quality: Quality, layers: usize) -> Option<u8> {
        self.quality = quality;
        self.patience = PATIENCE;
        let target = match quality {
            Quality::Layer(_) => start_layer(quality, layers),
            // from a thumbnail's smallest layer straight to Auto's start;
            // already better than that, stay
            Quality::Auto => self.layer.min(start_layer(quality, layers)),
        };
        self.retarget(target)
    }

    fn retarget(&mut self, target: u8) -> Option<u8> {
        self.target = target;
        self.changed = Instant::now();
        (target != self.layer).then_some(target)
    }

    /// Pass a packet on if it's for them. False once they're gone.
    pub fn offer(&mut self, packet: &Packet, bytes: &Bytes, layers: usize, asks: &mut Asks) -> bool {
        if packet.is_audio() {
            return !matches!(self.tx.try_send(bytes.clone()), Err(mpsc::error::TrySendError::Closed(_)));
        }
        let track = packet.track;
        if track == self.layer {
            self.adapt(layers, asks);
        }
        if track == self.target && track != self.layer {
            if !packet.keyframe {
                asks.keyframe(track, false);
                return true;
            }
            self.layer = track;
            self.waiting = false;
        }
        if track != self.layer {
            return true;
        }
        if self.waiting && !packet.keyframe {
            asks.keyframe(track, false);
            return true;
        }
        match self.tx.try_send(bytes.clone()) {
            Ok(()) => self.waiting = false,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.waiting = true;
                self.congested.store(true, Ordering::Relaxed);
                asks.keyframe(track, false);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
        }
        true
    }

    /// On Auto: down a layer when their connection struggles, up again
    /// after a while without trouble.
    fn adapt(&mut self, layers: usize, asks: &mut Asks) {
        if self.quality != Quality::Auto {
            return;
        }
        let since = self.changed.elapsed();
        if self.congested.swap(false, Ordering::Relaxed) {
            if since < TOO_SOON {
                self.patience = (self.patience * 2).min(MAX_PATIENCE);
            }
            let lower = (self.layer + 1).min(layers.saturating_sub(1) as u8);
            if let Some(l) = self.retarget(lower) {
                asks.keyframe(l, true);
            }
        } else if self.target == self.layer && self.layer > 0 && since >= self.patience {
            if let Some(l) = self.retarget(self.layer - 1) {
                asks.keyframe(l, true);
            }
        } else if since >= MAX_PATIENCE {
            self.patience = PATIENCE;
        }
    }
}

/// Where a watcher starts: what they asked for, or on Auto the second best
/// layer (going up from there once it runs well).
fn start_layer(quality: Quality, layers: usize) -> u8 {
    let last = layers.saturating_sub(1) as u8;
    match quality {
        Quality::Layer(l) => l.min(last),
        Quality::Auto => 1.min(last),
    }
}

/// Copy packets onto a stream to one watcher until they stop watching (the
/// sender goes away) or the stream breaks. Flags congestion: lost packets
/// or a round trip much longer than usual (queues filling up somewhere).
async fn forward(
    conn: quinn::Connection,
    from: UserId,
    mut packets: mpsc::Receiver<Bytes>,
    congested: Arc<AtomicBool>,
) {
    let Ok(mut send) = conn.open_uni().await else { return };
    if send.write_all(&video::watcher_header(from)).await.is_err() {
        return;
    }
    let mut check = tokio::time::interval(CHECK_EVERY);
    let mut last = conn.stats().path;
    let mut best_rtt = last.rtt;
    loop {
        tokio::select! {
            packet = packets.recv() => match packet {
                Some(p) => {
                    if send.write_chunk(p).await.is_err() {
                        return;
                    }
                }
                None => break,
            },
            _ = check.tick() => {
                let now = conn.stats().path;
                best_rtt = best_rtt.min(now.rtt);
                if now.congestion_events > last.congestion_events || now.rtt > best_rtt * 2 + Duration::from_millis(80) {
                    congested.store(true, Ordering::Relaxed);
                }
                last = now;
            }
        }
    }
    let _ = send.finish();
}
