//! Admin-socket client: owns the unix connection, auto-subscribes and
//! re-snapshots on (re)connect, never blocks the UI, reconnects forever.
//! Wire contract is gk-core::protocol over NDJSON JSON-RPC.

use std::path::PathBuf;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

use gk_core::protocol::{method, JsonRpcVersion, RpcRequest};

/// A request the app wants written to the daemon. Ids starting `c-` are
/// client-internal (resync round-trips); everything else is passed through
/// to the app so it can correlate replies in the event stream.
pub struct Cmd {
    pub id: String,
    pub method: &'static str,
    pub params: Option<Value>,
}

pub fn cmd(id: impl Into<String>, method: &'static str, params: Option<Value>) -> Cmd {
    Cmd { id: id.into(), method, params }
}

/// Liveness as seen by the UI. `up` flips false on any socket error; the
/// task keeps retrying and re-issues subscribe + snapshots when it returns,
/// flipping `synced` once fresh snapshots have been served.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConnStatus {
    pub up: bool,
    pub synced: bool,
}

/// Spawn the connection task: (command sender, inbound-line receiver, status).
pub fn spawn(
    socket: PathBuf,
) -> (
    mpsc::UnboundedSender<Cmd>,
    mpsc::UnboundedReceiver<Value>,
    watch::Receiver<ConnStatus>,
) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel::<Value>();
    let (st_tx, st_rx) = watch::channel(ConnStatus { up: false, synced: false });

    tokio::spawn(async move {
        loop {
            match UnixStream::connect(&socket).await {
                Ok(stream) => {
                    let (r, mut w) = stream.into_split();
                    let mut lines = BufReader::new(r).lines();

                    // Fresh session: subscribe + full snapshots. The app
                    // replaces its live/pending tables wholesale on the c-*
                    // responses, so reconnects self-heal by construction.
                    let resync = [
                        cmd("c-sub", method::SUBSCRIBE, None),
                        cmd("c-live", method::LIST_GRANTS, None),
                        cmd("c-pend", method::LIST_PENDING, None),
                    ];
                    for c in &resync {
                        if write_req(&mut w, c).await.is_err() {
                            break;
                        }
                    }
                    st_tx.send(ConnStatus { up: true, synced: false }).ok();

                    loop {
                        tokio::select! {
                            biased; // decisions take priority over socket reads
                            c = cmd_rx.recv() => {
                                match c {
                                    Some(c) => {
                                        if write_req(&mut w, &c).await.is_err() { break; }
                                    }
                                    None => return, // app dropped the sender
                                }
                            }
                            l = lines.next_line() => {
                                match l {
                                    Ok(Some(line)) => {
                                        if let Ok(v) = serde_json::from_str::<Value>(&line) {
                                            // subscribe re-ack == daemon-contract
                                            // handshake complete; snapshots ride
                                            // down the same stream for the app.
                                            if v.get("id").and_then(|i| i.as_str())
                                                == Some("c-sub")
                                            {
                                                st_tx.send(ConnStatus { up: true, synced: true }).ok();
                                            }
                                            if ev_tx.send(v).is_err() {
                                                return; // app gone
                                            }
                                        }
                                    }
                                    _ => break, // EOF / IO error -> reconnect
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    st_tx.send(ConnStatus { up: false, synced: false }).ok();
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    });

    (cmd_tx, ev_rx, st_rx)
}

async fn write_req(w: &mut tokio::net::unix::OwnedWriteHalf, c: &Cmd) -> std::io::Result<()> {
    let r = RpcRequest {
        jsonrpc: JsonRpcVersion::V2_0,
        id: c.id.clone(),
        method: c.method.into(),
        params: c.params.clone(),
    };
    w.write_all(format!("{}\n", serde_json::to_string(&r)?).as_bytes()).await
}
