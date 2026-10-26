//! One OpenConnect tunnel (Cisco AnyConnect, Fortinet, and later GlobalProtect).
//!
//! Two steps, like NetworkManager does it: the `oc-auth` helper signs in with
//! libopenconnect (forms, certificate trust, browser SSO all become prompts in
//! the app), then `openconnect.exe` runs the tunnel with the session cookie and
//! the pinned server certificate.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use molehill_core::ipc::{Answer, Event, Prompt, TunnelState};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::components;
use crate::netstats;
use crate::openconnect_auth::{AuthRequest, AuthResult, HelperAnswer, HelperEvent};
use crate::server::{Manager, TunnelCmd, status};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct Spec {
    pub protocol: String,
    pub server: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub group: Option<String>,
    pub pin: Option<String>,
    pub sso: bool,
    /// Already signed in (by the app, with the user's client certificate).
    pub auth: Option<Box<AuthResult>>,
}

#[derive(Clone, Copy, PartialEq)]
enum Purpose {
    Form,
    Trust,
    WebAuth,
}

struct Session {
    mgr: Arc<Manager>,
    id: String,
    name: String,
    state: TunnelState,
    local_ip: Option<String>,
    since: Option<u64>,
    prompt_seq: u64,
    pending: Option<(u64, Purpose)>,
    last_error: Option<String>,
}

pub async fn run(mgr: Arc<Manager>, id: String, name: String, spec: Spec, mut cmds: UnboundedReceiver<TunnelCmd>) {
    let mut s = Session { mgr, id, name, state: TunnelState::Disconnected, local_ip: None, since: None, prompt_seq: 0, pending: None, last_error: None };
    let result = s.run(spec, &mut cmds).await;
    s.clear_prompt();
    s.local_ip = None;
    s.since = None;
    match result {
        Ok(()) => s.set(TunnelState::Disconnected, ""),
        Err(e) => {
            warn!("{}: {e:#}", s.name);
            s.set(TunnelState::Failed, format!("{e:#}"));
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Forwards each line of `pipe` into `tx`.
fn pump(pipe: impl AsyncRead + Unpin + Send + 'static, tx: mpsc::UnboundedSender<String>) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(pipe).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

impl Session {
    fn set(&mut self, state: TunnelState, detail: impl Into<String>) {
        self.state = state;
        let mut st = status(&self.id, &self.name, state, detail);
        st.local_ip = self.local_ip.clone();
        st.since_unix = self.since;
        self.mgr.set_status(st);
    }

    fn log(&mut self, line: String) {
        let l = line.to_ascii_lowercase();
        if l.contains("error") || l.contains("fail") || l.contains("refused") || l.contains("denied") {
            self.last_error = Some(line.clone());
        }
        self.mgr.emit(Event::Log { id: self.id.clone(), line });
    }

    fn prompt(&mut self, purpose: Purpose, prompt: Prompt) {
        self.clear_prompt();
        self.prompt_seq += 1;
        self.pending = Some((self.prompt_seq, purpose));
        self.mgr.show_prompt(&self.id, self.prompt_seq, prompt);
        let detail = if purpose == Purpose::WebAuth { "Finish signing in in your browser" } else { "Waiting for you" };
        self.set(TunnelState::Authenticating, detail);
    }

    fn clear_prompt(&mut self) {
        if self.pending.take().is_some() {
            self.mgr.clear_prompt(&self.id);
        }
    }

    async fn run(&mut self, spec: Spec, cmds: &mut UnboundedReceiver<TunnelCmd>) -> Result<()> {
        self.set(TunnelState::Connecting, "Signing in");
        let dir = components::openconnect_dir().ok_or_else(|| anyhow!("OpenConnect is not installed. Install it from Components."))?;
        let auth = match spec.auth.clone() {
            Some(auth) => *auth,
            None => match self.authenticate(&spec, &dir, cmds).await? {
                Some(auth) => auth,
                None => return Ok(()), // cancelled by the user
            },
        };
        self.tunnel(&spec, &dir, auth, cmds).await
    }

    /// Step 1: the sign-in helper. `Ok(None)` means the user cancelled.
    async fn authenticate(&mut self, spec: &Spec, dir: &std::path::Path, cmds: &mut UnboundedReceiver<TunnelCmd>) -> Result<Option<AuthResult>> {
        let mut helper = Command::new(std::env::current_exe()?)
            .arg("oc-auth")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting the sign-in helper")?;
        crate::job::adopt(&helper);
        let mut input = helper.stdin.take().unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        pump(helper.stdout.take().unwrap(), tx);
        let (etx, mut erx) = mpsc::unbounded_channel();
        pump(helper.stderr.take().unwrap(), etx);

        let req = AuthRequest {
            dir: dir.to_path_buf(),
            protocol: spec.protocol.clone(),
            server: spec.server.clone(),
            username: spec.username.clone(),
            password: spec.password.clone(),
            group: spec.group.clone(),
            pin: spec.pin.clone(),
            sso: spec.sso,
            saml_login: false,
            cert: None,
            key: None,
        };
        send_line(&mut input, &serde_json::to_string(&req)?).await?;

        let mut erx_open = true;
        loop {
            tokio::select! {
                line = rx.recv() => {
                    let Some(line) = line else {
                        let code = helper.wait().await.ok().and_then(|s| s.code());
                        bail!("The sign-in helper stopped unexpectedly (code {code:?}). {}", self.last_error.clone().unwrap_or_default());
                    };
                    let Ok(ev) = serde_json::from_str::<HelperEvent>(&line) else {
                        self.log(line);
                        continue;
                    };
                    match ev {
                        HelperEvent::Log { line } => self.log(line),
                        HelperEvent::Form { banner, error, fields } => self.prompt(Purpose::Form, Prompt::Form { banner, error, fields }),
                        HelperEvent::TrustCert { pin, reason } => {
                            let host = spec.server.clone();
                            self.prompt(Purpose::Trust, Prompt::TrustCert { host, pin, reason });
                        }
                        HelperEvent::OpenUrl { url } => self.prompt(Purpose::WebAuth, Prompt::OpenUrl { url }),
                        HelperEvent::PasswordRejected => self.mgr.emit(Event::AuthFailed { id: self.id.clone() }),
                        HelperEvent::Done(result) => {
                            self.clear_prompt();
                            return Ok(Some(result));
                        }
                        HelperEvent::Failed { message } => {
                            self.clear_prompt();
                            if message == "Cancelled" {
                                return Ok(None);
                            }
                            bail!("{message}");
                        }
                    }
                }
                line = erx.recv(), if erx_open => match line {
                    Some(line) => self.log(line),
                    None => erx_open = false,
                },
                cmd = cmds.recv() => match cmd {
                    Some(TunnelCmd::Answer { prompt_id, answer }) => {
                        let Some((pid, purpose)) = self.pending else { continue };
                        if pid != prompt_id {
                            continue;
                        }
                        let reply = match (purpose, answer) {
                            // The helper is waiting for the browser, not reading answers.
                            (Purpose::WebAuth, Answer::Cancel) => {
                                let _ = helper.start_kill();
                                return Ok(None);
                            }
                            (_, Answer::Cancel) => HelperAnswer::Cancel,
                            (Purpose::Form, Answer::Form { values }) => HelperAnswer::Form { values },
                            (Purpose::Trust, Answer::Text { value }) => HelperAnswer::Trust { accept: value == "trust" },
                            _ => continue,
                        };
                        self.clear_prompt();
                        self.set(TunnelState::Authenticating, "Signing in");
                        send_line(&mut input, &serde_json::to_string(&reply)?).await?;
                    }
                    Some(TunnelCmd::SsoCallback { url }) => {
                        if !matches!(self.pending, Some((_, Purpose::WebAuth))) {
                            continue;
                        }
                        self.clear_prompt();
                        self.set(TunnelState::Authenticating, "Signing in");
                        send_line(&mut input, &serde_json::to_string(&HelperAnswer::Callback { url })?).await?;
                    }
                    // Disconnect while signing in: just stop the helper.
                    Some(TunnelCmd::Disconnect) | None => {
                        let _ = helper.start_kill();
                        return Ok(None);
                    }
                },
            }
        }
    }

    /// Step 2: `openconnect.exe` with the cookie.
    async fn tunnel(&mut self, spec: &Spec, dir: &std::path::Path, auth: AuthResult, cmds: &mut UnboundedReceiver<TunnelCmd>) -> Result<()> {
        self.set(TunnelState::Connecting, "Starting the tunnel");
        let ifname = format!("Molehill-{}", &self.id[..self.id.len().min(8)]);
        // A ghost adapter by this name would make openconnect give up ("Set up tun device failed").
        let alias = ifname.clone();
        match tokio::task::spawn_blocking(move || netstats::remove_stale_wintun(&alias)).await {
            Ok(Ok(0)) | Err(_) => {}
            Ok(Ok(_)) => self.log(format!("Removed a stale {ifname} adapter left by an earlier session")),
            Ok(Err(e)) => warn!("{}: {e:#}", self.name),
        }
        // Just the path: on Windows openconnect runs `cscript.exe /e:JScript "<script>"` itself.
        let script = dir.join("vpnc-script-win.js").display().to_string();
        let mut cmd = Command::new(dir.join("openconnect.exe"));
        cmd.arg(format!("--protocol={}", spec.protocol))
            .arg("--cookie-on-stdin")
            .arg("--non-inter")
            .arg(format!("--interface={ifname}"))
            .arg(format!("--script={script}"));
        if let Some(pin) = &auth.pin {
            cmd.arg(format!("--servercert={pin}"));
        }
        if let Some(r) = &auth.resolve {
            cmd.arg(format!("--resolve={r}"));
        }
        cmd.arg(&auth.connect_url);
        let mut child = cmd
            .current_dir(dir)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting openconnect.exe")?;
        crate::job::adopt(&child);
        info!("{}: openconnect started (pid {:?})", self.name, child.id());
        {
            let mut stdin = child.stdin.take().unwrap();
            send_line(&mut stdin, &auth.cookie).await?;
        }
        let (tx, mut lines) = mpsc::unbounded_channel();
        pump(child.stdout.take().unwrap(), tx.clone());
        pump(child.stderr.take().unwrap(), tx);

        let mut stopping = false;
        let mut lines_open = true;
        let mut kill_at: Option<Instant> = None;
        let mut stats = tokio::time::interval(Duration::from_secs(2));
        stats.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let far = || Instant::now() + Duration::from_secs(86400);
        let exit = loop {
            tokio::select! {
                line = lines.recv(), if lines_open => {
                    let Some(line) = line else { lines_open = false; continue };
                    self.on_output(&line);
                    self.log(line);
                }
                _ = stats.tick(), if self.state == TunnelState::Connected => {
                    let alias = ifname.clone();
                    if let Ok(Some((bytes_in, bytes_out))) = tokio::task::spawn_blocking(move || netstats::interface_bytes(&alias)).await {
                        self.mgr.emit(Event::Stats { id: self.id.clone(), bytes_in, bytes_out });
                    }
                }
                cmd = cmds.recv(), if !stopping => match cmd {
                    Some(TunnelCmd::Answer { .. } | TunnelCmd::SsoCallback { .. }) => {}
                    Some(TunnelCmd::Disconnect) | None => {
                        stopping = true;
                        self.set(TunnelState::Disconnecting, "Closing");
                        // Ctrl+C makes openconnect log out and restore routes and DNS.
                        if let Some(pid) = child.id() {
                            stop_gracefully(pid).await;
                        }
                        kill_at = Some(Instant::now() + Duration::from_secs(10));
                    }
                },
                status = child.wait() => break status?,
                _ = tokio::time::sleep_until(kill_at.unwrap_or_else(far)), if kill_at.is_some() => {
                    warn!("{}: openconnect did not exit, killing it", self.name);
                    let _ = child.start_kill();
                    kill_at = None;
                }
            }
        };
        info!("{}: openconnect exited with {exit}", self.name);
        if stopping {
            Ok(())
        } else {
            Err(anyhow!("{}", self.last_error.clone().unwrap_or_else(|| format!("OpenConnect exited ({exit})"))))
        }
    }

    fn on_output(&mut self, line: &str) {
        // Cisco / GlobalProtect: "Connected as 10.1.2.3, using SSL, with DTLS in progress"
        // Fortinet: "Configured as 10.1.2.3, with SSL connected and DTLS disabled"
        if let Some(rest) = line.strip_prefix("Connected as ").or_else(|| line.strip_prefix("Configured as ")) {
            let ip = rest.split([',', ' ']).next().unwrap_or("").to_string();
            self.local_ip = (!ip.is_empty()).then_some(ip.clone());
            if self.since.is_none() {
                self.since = Some(now_unix());
            }
            self.last_error = None;
            self.set(TunnelState::Connected, ip);
            return;
        }
        let l = line.to_ascii_lowercase();
        if self.state == TunnelState::Connected && (l.contains("reconnect") || l.contains("dead peer detection detected")) {
            self.set(TunnelState::Reconnecting, "Connection lost, reconnecting");
        } else if self.state == TunnelState::Reconnecting && l.contains("established dtls") {
            self.set(TunnelState::Connected, self.local_ip.clone().unwrap_or_default());
        }
    }
}

async fn send_line(stdin: &mut ChildStdin, line: &str) -> Result<()> {
    stdin.write_all(format!("{line}\n").as_bytes()).await?;
    stdin.flush().await?;
    Ok(())
}

/// Sends Ctrl+C to openconnect.exe through the `oc-stop` helper (attaching to
/// another process's console can't be done from the service itself).
async fn stop_gracefully(pid: u32) {
    let Ok(exe) = std::env::current_exe() else { return };
    let child: std::io::Result<Child> = Command::new(exe).arg("oc-stop").arg(pid.to_string()).creation_flags(CREATE_NO_WINDOW).spawn();
    if let Ok(mut c) = child {
        let _ = tokio::time::timeout(Duration::from_secs(5), c.wait()).await;
    }
}
