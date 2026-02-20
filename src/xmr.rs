// Xibo player Rust implementation, (c) 2022-2024 Georg Brandl.
// Licensed under the GNU AGPL, version 3 or later.

//! Receive, decrypt and handle incoming XMR messages from CMS.

use crate::config::{CmsSettings, PlayerSettings};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use rsa::RsaPrivateKey;
use serde::{de::Error, Deserialize, Deserializer};
use serde_json::from_slice;
use std::io::ErrorKind;
use std::time::{Duration as StdDuration, Instant};
use time::{Duration, OffsetDateTime};
use tungstenite::{connect, stream::MaybeTlsStream, Error as WsError, Message as WsMessage};

/// Possible messages to forward to the collect thread.
#[derive(Debug)]
pub enum Message {
    CollectNow,
    Screenshot,
    Purge,
    WebHook(String),
    Command(String),
}

#[derive(Clone)]
pub struct Handle {
    sender: Sender<Control>,
}

impl Handle {
    pub fn update_settings(&self, settings: &PlayerSettings) {
        if self
            .sender
            .send(Control::Update(TransportConfig::from_settings(settings)))
            .is_err()
        {
            log::warn!("XMR manager is no longer running; unable to update transport settings");
        }
    }
}

pub struct Manager {
    private_key: RsaPrivateKey,
    sender: Sender<Message>,
    control: Receiver<Control>,
    channel: String,
    config: TransportConfig,
    shutdown: bool,
}

const HEARTBEAT: &[u8] = b"H";
const RECV_TIMEOUT: StdDuration = StdDuration::from_secs(1);
const IDLE_TIMEOUT: StdDuration = StdDuration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransportConfig {
    network_address: String,
    websocket_address: String,
    xmr_type: String,
    xmr_cms_key: String,
}

impl TransportConfig {
    fn from_settings(settings: &PlayerSettings) -> Self {
        Self {
            network_address: settings.xmr_network_address.clone(),
            websocket_address: settings.xmr_websocket_address.clone(),
            xmr_type: settings.xmr_type.clone(),
            xmr_cms_key: settings.xmr_cms_key.clone(),
        }
    }
}

#[derive(Debug)]
enum Control {
    Update(TransportConfig),
}

#[derive(Debug)]
enum Transport {
    WebSocket(String),
    Zmq(String),
}

#[derive(Debug, PartialEq, Eq)]
enum TransportExit {
    Disconnected,
    Reconfigured,
    Shutdown,
}

impl Manager {
    pub fn new(
        settings: &CmsSettings,
        player: &PlayerSettings,
        private_key: RsaPrivateKey,
    ) -> Result<(Self, Receiver<Message>, Handle)> {
        let (sender, receiver) = unbounded();
        let (ctl_sender, control) = unbounded();

        Ok((
            Self {
                private_key,
                sender,
                control,
                channel: settings.xmr_channel(),
                config: TransportConfig::from_settings(player),
                shutdown: false,
            },
            receiver,
            Handle { sender: ctl_sender },
        ))
    }

    pub fn run(mut self) {
        let mut backoff = StdDuration::from_secs(1);
        let mut warned_no_transport = false;
        loop {
            if self.shutdown {
                return;
            }
            if self.apply_pending_updates() {
                backoff = StdDuration::from_secs(1);
                warned_no_transport = false;
            }

            let transports = self.preferred_transports();
            if transports.is_empty() {
                if !warned_no_transport {
                    log::warn!(
                        "XMR disabled: no valid websocket or ZMQ address from CMS (xmrType={})",
                        self.config.xmr_type
                    );
                    warned_no_transport = true;
                }
                if self.wait_for_update(StdDuration::from_secs(30)) {
                    backoff = StdDuration::from_secs(1);
                    warned_no_transport = false;
                }
                continue;
            }
            warned_no_transport = false;

            let mut reconfigured = false;
            for transport in transports {
                match self.run_transport(&transport) {
                    Ok(TransportExit::Shutdown) => return,
                    Ok(TransportExit::Reconfigured) => {
                        reconfigured = true;
                        break;
                    }
                    Ok(TransportExit::Disconnected) => {
                        log::warn!("XMR transport disconnected: {:?}", transport);
                    }
                    Err(e) => {
                        log::error!("XMR transport {:?} failed: {:#}", transport, e);
                    }
                }

                if self.apply_pending_updates() {
                    reconfigured = true;
                    break;
                }
            }

            if reconfigured {
                backoff = StdDuration::from_secs(1);
                continue;
            }

            if self.wait_for_update(backoff) {
                backoff = StdDuration::from_secs(1);
                continue;
            }
            backoff = std::cmp::min(backoff.saturating_mul(2), StdDuration::from_secs(60));
        }
    }

    fn apply_pending_updates(&mut self) -> bool {
        let mut changed = false;
        while let Ok(Control::Update(config)) = self.control.try_recv() {
            if config != self.config {
                log::info!("reconfiguring XMR transport settings");
                self.config = config;
                changed = true;
            }
        }
        changed
    }

    fn wait_for_update(&mut self, timeout: StdDuration) -> bool {
        match self.control.recv_timeout(timeout) {
            Ok(Control::Update(config)) => {
                self.config = config;
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => {
                log::warn!("XMR control channel disconnected, shutting down");
                self.shutdown = true;
                false
            }
        }
    }

    fn preferred_transports(&self) -> Vec<Transport> {
        let ws = normalized(&self.config.websocket_address);
        let zmq = normalized(&self.config.network_address);
        let mut transports = vec![];
        match self.config.xmr_type.trim().to_ascii_lowercase().as_str() {
            "websocket" | "ws" | "wss" => {
                if let Some(ws) = ws {
                    transports.push(Transport::WebSocket(ws));
                }
                if let Some(zmq) = zmq {
                    transports.push(Transport::Zmq(zmq));
                }
            }
            "zmq" | "tcp" => {
                if let Some(zmq) = zmq {
                    transports.push(Transport::Zmq(zmq));
                }
                if let Some(ws) = ws {
                    transports.push(Transport::WebSocket(ws));
                }
            }
            _ => {
                if let Some(ws) = ws {
                    transports.push(Transport::WebSocket(ws));
                }
                if let Some(zmq) = zmq {
                    transports.push(Transport::Zmq(zmq));
                }
            }
        }
        transports
    }

    fn run_transport(&mut self, transport: &Transport) -> Result<TransportExit> {
        match transport {
            Transport::WebSocket(url) => self.run_websocket(url),
            Transport::Zmq(addr) => self.run_zmq(addr),
        }
    }

    fn run_zmq(&mut self, connect: &str) -> Result<TransportExit> {
        log::info!("connecting XMR via ZMQ: {connect}");

        let context = zmq::Context::new();
        let socket = context
            .socket(zmq::SUB)
            .context("creating XMR ZMQ socket")?;
        socket
            .connect(connect)
            .with_context(|| format!("connecting XMR ZMQ socket to {connect}"))?;
        socket.set_linger(0)?;
        socket.set_subscribe(self.channel.as_bytes())?;
        socket.set_subscribe(HEARTBEAT)?;
        socket.set_rcvtimeo(RECV_TIMEOUT.as_millis() as i32)?;

        let mut last_recv = Instant::now();
        loop {
            if self.apply_pending_updates() {
                return Ok(TransportExit::Reconfigured);
            }

            let parts = match socket.recv_multipart(0) {
                Ok(parts) => {
                    last_recv = Instant::now();
                    parts
                }
                Err(zmq::Error::EAGAIN) => {
                    if last_recv.elapsed() >= IDLE_TIMEOUT {
                        log::warn!(
                            "ZMQ silent for {}s, giving up",
                            last_recv.elapsed().as_secs()
                        );
                        return Ok(TransportExit::Disconnected);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            if parts.len() != 3 {
                log::warn!(
                    "ignoring malformed ZMQ XMR multipart with {} parts",
                    parts.len()
                );
                continue;
            }

            let channel = parts[0].trim_ascii();
            if channel == HEARTBEAT {
                continue;
            }
            if channel != self.channel.as_bytes() {
                continue;
            }

            match JsonMessage::decrypt(&self.private_key, &parts[1], &parts[2]) {
                Ok(json_msg) => {
                    log::debug!("got XMR message via ZMQ: {:?}", json_msg);
                    if let Some(msg) = json_msg.into_msg() {
                        if self.sender.send(msg).is_err() {
                            return Ok(TransportExit::Shutdown);
                        }
                    }
                }
                Err(e) => {
                    log::error!("handling ZMQ XMR message: {:#}", e);
                }
            }
        }
    }

    fn run_websocket(&mut self, url: &str) -> Result<TransportExit> {
        if self.config.xmr_cms_key.is_empty() {
            anyhow::bail!("no xmrCmsKey available for WebSocket auth");
        }

        log::info!("connecting XMR via WebSocket: {url}");

        let (mut socket, _) =
            connect(url).with_context(|| format!("connecting XMR WebSocket to {url}"))?;
        match socket.get_mut() {
            MaybeTlsStream::Plain(tcp) => {
                tcp.set_read_timeout(Some(RECV_TIMEOUT))
                    .context("setting websocket read timeout")?;
            }
            MaybeTlsStream::Rustls(tls) => {
                tls.get_mut()
                    .set_read_timeout(Some(RECV_TIMEOUT))
                    .context("setting websocket read timeout")?;
            }
            MaybeTlsStream::NativeTls(tls) => {
                tls.get_mut()
                    .set_read_timeout(Some(RECV_TIMEOUT))
                    .context("setting websocket read timeout")?;
            }
            _ => {
                log::warn!("unknown TLS stream type, read timeout not set");
            }
        }

        // Send init handshake to authenticate with the XMR relay
        let init_msg = serde_json::json!({
            "type": "init",
            "key": self.config.xmr_cms_key,
            "channel": self.channel,
        });
        socket
            .send(WsMessage::Text(init_msg.to_string()))
            .context("sending WebSocket init message")?;
        log::debug!("sent WebSocket XMR init for channel {}", self.channel);

        let mut last_recv = Instant::now();
        loop {
            if self.apply_pending_updates() {
                return Ok(TransportExit::Reconfigured);
            }

            let frame = match socket.read() {
                Ok(msg) => {
                    last_recv = Instant::now();
                    msg
                }
                Err(WsError::Io(ref e))
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    if last_recv.elapsed() >= IDLE_TIMEOUT {
                        log::warn!(
                            "WebSocket silent for {}s, giving up",
                            last_recv.elapsed().as_secs()
                        );
                        return Ok(TransportExit::Disconnected);
                    }
                    continue
                }
                Err(WsError::ConnectionClosed) | Err(WsError::AlreadyClosed) => {
                    return Ok(TransportExit::Disconnected);
                }
                Err(e) => return Err(e.into()),
            };

            match frame {
                WsMessage::Text(text) => {
                    if let Some(exit) = self.process_ws_text(&text)? {
                        return Ok(exit);
                    }
                }
                WsMessage::Binary(data) => {
                    if let Ok(text) = std::str::from_utf8(&data) {
                        if let Some(exit) = self.process_ws_text(text)? {
                            return Ok(exit);
                        }
                    } else {
                        log::debug!("ignoring non-UTF8 binary WebSocket frame");
                    }
                }
                WsMessage::Ping(data) => {
                    socket.send(WsMessage::Pong(data))?;
                }
                WsMessage::Close(_) => return Ok(TransportExit::Disconnected),
                WsMessage::Pong(_) => {}
                _ => {}
            }
        }
    }

    /// Process a plaintext WebSocket text frame.
    /// The XMR relay sends either "H" (heartbeat) or a raw JSON action payload.
    fn process_ws_text(&mut self, text: &str) -> Result<Option<TransportExit>> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        if text == "H" {
            return Ok(None);
        }

        match serde_json::from_str::<JsonMessage>(text) {
            Ok(json_msg) => {
                log::debug!("got XMR message via WebSocket: {:?}", json_msg);
                if let Some(msg) = json_msg.into_msg() {
                    if self.sender.send(msg).is_err() {
                        return Ok(Some(TransportExit::Shutdown));
                    }
                }
            }
            Err(e) => {
                log::warn!("ignoring unparseable WebSocket XMR message: {}", e);
            }
        }
        Ok(None)
    }
}

fn normalized(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.into())
    }
}


#[derive(Debug, Deserialize)]
struct JsonMessage {
    action: String,
    #[serde(rename = "createdDt")]
    #[serde(deserialize_with = "deserialize_datetime")]
    created: OffsetDateTime,
    #[serde(default)]
    ttl: i64,
    #[serde(rename = "triggerCode")]
    #[serde(default)]
    trigger_code: Option<String>, // for webhooks
    #[serde(rename = "commandCode")]
    #[serde(default)]
    command_code: Option<String>, // for commands
}

impl JsonMessage {
    /// Decrypt a ZMQ-style sealed message (base64-encoded RSA+ARC4).
    fn decrypt(private_key: &RsaPrivateKey, key: &[u8], content: &[u8]) -> Result<Self> {
        let enc_key = BASE64.decode(key.trim_ascii())?;
        let mut msg = BASE64.decode(content.trim_ascii())?;
        let msg_key = decrypt_private_key(&enc_key, private_key)?;
        arc4::Arc4::with_key(&msg_key).encrypt(&mut msg);
        Ok(from_slice(&msg)?)
    }

    fn is_expired(&self) -> bool {
        self.created + Duration::seconds(self.ttl) < OffsetDateTime::now_utc()
    }

    fn into_msg(self) -> Option<Message> {
        if self.is_expired() {
            return None;
        }
        match &*self.action {
            "collectNow" => Some(Message::CollectNow),
            // we treat this the same as a collect, which will re-send the pubkey
            "rekeyAction" => Some(Message::CollectNow),
            "screenShot" => Some(Message::Screenshot),
            "purgeAll" => Some(Message::Purge),
            "triggerWebhook" => self.trigger_code.map(Message::WebHook),
            "commandAction" => self.command_code.map(Message::Command),
            _ => {
                log::info!("got unsupported XMR action {:?}", self.action);
                None
            }
        }
    }
}

fn deserialize_datetime<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<OffsetDateTime, D::Error> {
    let s = <String as Deserialize>::deserialize(d)?;
    OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| D::Error::custom("invalid datetime string"))
}

fn decrypt_private_key(enc_key: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let dec_data = private_key
        .decrypt(rsa::Pkcs1v15Encrypt, enc_key)
        .context("failed to decrypt PK")?;
    Ok(dec_data)
}

#[test]
fn test_decrypt() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDJg84myV3VE+v53gQKVbX+6pQrveSfZTcs/a3mikxhXO32peqh
OP2namgoixfBBwK6wzRjRzOHdsB4yQPTMRTZIsipTYHyIqYl5/6AxoRGAsjZtmaB
MNsxrBxMCGlWEKLPwSCecT8EbCrfl3GArf56SEglxDRyx7pDRRnAihPgMQIBEQKB
gAQ7xwUeC6blhxvWaX8kOIeBs4QlVXmrABVh1Wa5wzfTs0BXYoJPt+IsL11bH7E7
TpQO23QaPD4Ba03U5TCJotumgDf0zIfVx5p7GrpK4oqI4o+PX7gWCzurXaqmQiYq
CfZCCeHF+Z2KV2OmhXq3tvlx8Ne4gOiZ65K2vNhNiAEZAkEA1wAyT/hFPUoDnqYD
UfRJEQM1XyRxa0MTkUJh4UO+WCp+d2OtEuydMUdfSu9oGPUNPsMaXr3SzsE8rhp8
1iXB1QJBAO/xQqxO0YvYnDJgQFTXB34Lv66pCHkbBddvYnByfxqeIQJM9o61grUK
LCLjrZ9qPqa87xcYLPP4i8/iPuMKtu0CQQCXw+dHghLB2eRv/LcMrG/PxgeOdBPT
PmgqTPnML9GnpYZyZHoredhfBTQ05Tpr+EWVtuVwDYW/Hv2oErJ5C5fhAkEAm0HB
usmWpchlEYmTCbhQJGH0gBMFe4n0uJNd0EoWAioVW9dyXFdUk0LRQ8B/ZyahAnpA
WjzRywo8WVYosQbu1QJBAIK8lUC6fBRr2ElLltNV/cmR2To5rUYSQJJB9rDw9Inv
cwFD2YnuxuF9szIeWPTmHUl6aXRIByuKNexbHqTeNhY=
-----END RSA PRIVATE KEY-----
";
    use rsa::pkcs1::DecodeRsaPrivateKey;
    let privkey = rsa::RsaPrivateKey::from_pkcs1_pem(pem).unwrap();
    let msg = JsonMessage::decrypt(
        &privkey,
        b"uKgfpneak5Qx5vppLlJZEEcFQ5Y/xrk45ysmnsIVQGvndFR0R86pPRRDPxvqSBgCDb\
                                 4xInqC8fQLApEzEjULL4QwERycgfHWMY+KSAEDjaS2/3IvSUPa+XYZVZssC/jddIar\
                                 ZvqHdfylHqm1IiL6Tgaps05BYeyDYynRmngW8NM=",
        b"TOwhZC5mz2N0GoQvUDXsXVDfC3A6Ov5I+raxOsBvvhOLgPFlpz2VxWTsvq5TX8JJ/b\
                                 gCSdfpe5DTA0bEvwXzDst1KtGjK1Nvdg==",
    )
    .unwrap();
    assert_eq!(msg.action, "screenShot");
}

#[test]
fn test_ws_plaintext_collect_now() {
    let payload = r#"{"action":"collectNow","createdDt":"2099-01-01T00:00:00+00:00","ttl":120}"#;
    let msg: JsonMessage = serde_json::from_str(payload).unwrap();
    assert_eq!(msg.action, "collectNow");
    assert_eq!(msg.ttl, 120);
    assert!(!msg.is_expired());
    assert!(matches!(msg.into_msg(), Some(Message::CollectNow)));
}

#[test]
fn test_ws_plaintext_command_action() {
    let payload = r#"{"action":"commandAction","createdDt":"2099-01-01T00:00:00+00:00","ttl":120,"commandCode":"reboot"}"#;
    let msg: JsonMessage = serde_json::from_str(payload).unwrap();
    assert_eq!(msg.action, "commandAction");
    assert_eq!(msg.command_code.as_deref(), Some("reboot"));
}

#[test]
fn test_ws_plaintext_webhook() {
    let payload = r#"{"action":"triggerWebhook","createdDt":"2099-01-01T00:00:00+00:00","ttl":120,"triggerCode":"myTrigger"}"#;
    let msg: JsonMessage = serde_json::from_str(payload).unwrap();
    assert_eq!(msg.trigger_code.as_deref(), Some("myTrigger"));
}

#[test]
fn test_ws_plaintext_expired() {
    let payload = r#"{"action":"collectNow","createdDt":"2020-01-01T00:00:00+00:00","ttl":1}"#;
    let msg: JsonMessage = serde_json::from_str(payload).unwrap();
    assert!(msg.is_expired());
    assert!(msg.into_msg().is_none());
}
