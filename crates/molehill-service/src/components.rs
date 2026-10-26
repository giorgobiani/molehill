//! Third-party components Molehill drives, and how to install / update them.
//!
//! OpenVPN: the community MSI from swupdate.openvpn.org, installed with only
//! the core and drivers (no OpenVPN GUI). The latest version comes from the
//! GitHub releases of OpenVPN/openvpn; the MSI must carry a valid Authenticode
//! signature from OpenVPN Inc. before it runs.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use molehill_core::ipc::ComponentInfo;
use molehill_core::{APP_VERSION, paths, version};
use tracing::{info, warn};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows::core::{HSTRING, PCWSTR};

use crate::security;

pub const OPENVPN: &str = "openvpn";
pub const OPENCONNECT: &str = "openconnect";
const OPENVPN_FEATURES: &str = "OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn user_agent() -> String {
    format!("Molehill/{APP_VERSION} (+https://github.com/giorgobiani/molehill)")
}

pub(crate) fn reg_string(subkey: &str, value: &str) -> Option<String> {
    let (subkey, value) = (HSTRING::from(subkey), HSTRING::from(value));
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    let err = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if err.is_err() {
        return None;
    }
    let len = (size as usize / 2).saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..len]))
}

/// `openvpn.exe` from the registry (set by the MSI), else the default path.
pub fn openvpn_exe() -> Option<PathBuf> {
    reg_string(r"SOFTWARE\OpenVPN", "exe_path")
        .map(PathBuf::from)
        .into_iter()
        .chain([PathBuf::from(r"C:\Program Files\OpenVPN\bin\openvpn.exe")])
        .find(|p| p.is_file())
}

pub fn openvpn_bin_dir() -> Option<PathBuf> {
    openvpn_exe().and_then(|p| p.parent().map(PathBuf::from))
}

fn openvpn_version() -> Option<String> {
    use std::os::windows::process::CommandExt;
    let out = Command::new(openvpn_exe()?).arg("--version").creation_flags(CREATE_NO_WINDOW).output().ok()?;
    // "OpenVPN 2.7.8 [git:...] x86_64-w64-mingw32 ..."
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    first.strip_prefix("OpenVPN ")?.split_whitespace().next().map(str::to_string)
}

struct Release {
    version: String,
    msi_url: String,
}

fn latest_openvpn() -> Result<Release> {
    let body = http().get("https://api.github.com/repos/OpenVPN/openvpn/releases?per_page=30")
        .header("User-Agent", &user_agent())
        .header("Accept", "application/vnd.github+json")
        .call()?
        .body_mut()
        .read_to_string()?;
    let releases: serde_json::Value = serde_json::from_str(&body)?;
    let latest = releases
        .as_array()
        .ok_or_else(|| anyhow!("unexpected GitHub response"))?
        .iter()
        .filter(|r| !r["prerelease"].as_bool().unwrap_or(true) && !r["draft"].as_bool().unwrap_or(true))
        .filter_map(|r| r["tag_name"].as_str())
        .filter(|t| t.starts_with('v') && t[1..].split('.').all(|p| p.parse::<u32>().is_ok()))
        .max_by(|a, b| version::parse(a).cmp(&version::parse(b)))
        .ok_or_else(|| anyhow!("no OpenVPN release found"))?
        .trim_start_matches('v')
        .to_string();

    // Installer re-spins bump the I00x suffix; take the newest that exists.
    let mut msi_url = None;
    for n in 1..=9 {
        let url = format!("https://swupdate.openvpn.org/community/releases/OpenVPN-{latest}-I{n:03}-amd64.msi");
        match http().head(&url).header("User-Agent", &user_agent()).call() {
            Ok(_) => msi_url = Some(url),
            Err(_) if msi_url.is_some() => break,
            Err(_) if n >= 3 => break,
            Err(_) => {}
        }
    }
    let msi_url = msi_url.ok_or_else(|| anyhow!("OpenVPN {latest} has no Windows installer yet"))?;
    Ok(Release { version: latest, msi_url })
}

/// Installed versions (local, fast) and latest versions (online).
pub fn query() -> Vec<ComponentInfo> {
    let latest = match latest_openvpn() {
        Ok(r) => Some(r.version),
        Err(e) => {
            warn!("checking for OpenVPN updates: {e:#}");
            None
        }
    };
    let openconnect_latest = match latest_openconnect() {
        Ok(v) => Some(v),
        Err(e) => {
            warn!("checking for OpenConnect updates: {e:#}");
            None
        }
    };
    describe(latest, openconnect_latest)
}

/// Re-detects what's installed without going online; latest versions come
/// from the previous check.
pub fn query_local(previous: &[ComponentInfo]) -> Vec<ComponentInfo> {
    let latest = |id: &str| previous.iter().find(|c| c.id == id).and_then(|c| c.latest.clone());
    describe(latest(OPENVPN), latest(OPENCONNECT))
}

fn describe(latest: Option<String>, openconnect_latest: Option<String>) -> Vec<ComponentInfo> {
    vec![
        ComponentInfo {
            id: OPENVPN.into(),
            name: "OpenVPN".into(),
            description: "Tunnel engine for .ovpn profiles, with the DCO and TAP network drivers".into(),
            installed: openvpn_version(),
            latest,
            required: true,
        },
        ComponentInfo {
            id: OPENCONNECT.into(),
            name: "OpenConnect".into(),
            description: "Tunnel engine for Cisco AnyConnect, Fortinet and GlobalProtect, with the Wintun driver".into(),
            installed: openconnect_version(),
            latest: openconnect_latest,
            required: false,
        },
    ]
}

/// Downloads, verifies and installs the latest version of `component`.
/// Returns a message for the user on success.
pub fn install(component: &str, progress: impl Fn(&str)) -> Result<String> {
    match component {
        OPENVPN => install_openvpn(&progress),
        OPENCONNECT => install_openconnect(&progress),
        _ => bail!("unknown component `{component}`"),
    }
}

fn install_openvpn(progress: &impl Fn(&str)) -> Result<String> {
    progress("Looking up the latest version…");
    let release = latest_openvpn()?;
    let installed = openvpn_version();
    if installed.as_deref().is_some_and(|i| !version::is_newer(&release.version, i)) {
        return Ok(format!("OpenVPN {} is already up to date.", release.version));
    }

    let dir = paths::service_dir().join("downloads");
    security::private_dir(&dir)?;
    let file = dir.join(release.msi_url.rsplit('/').next().unwrap_or("openvpn.msi"));
    download(&release.msi_url, &file, progress)?;

    progress("Verifying the installer signature…");
    verify_signature(&file)?;

    progress(&format!("Installing OpenVPN {}…", release.version));
    let log = dir.join("openvpn-install.log");
    let mut cmd = Command::new(crate::security::system32("msiexec.exe"));
    cmd.arg("/i").arg(&file).args(["/qn", "/norestart", "/l*v"]).arg(&log);
    // Fresh installs get only what Molehill needs. Upgrades keep whatever
    // features an existing installation already had.
    if installed.is_none() {
        cmd.arg(format!("ADDLOCAL={OPENVPN_FEATURES}"));
    }
    let code = cmd.status().context("running msiexec")?.code().unwrap_or(-1);
    let _ = std::fs::remove_file(&file);
    info!("msiexec exited with {code}");
    match code {
        0 => Ok(format!("OpenVPN {} installed.", release.version)),
        1641 | 3010 => Ok(format!("OpenVPN {} installed. Restart Windows to finish.", release.version)),
        1618 => bail!("Another installation is in progress. Try again when it finishes."),
        _ => bail!("The OpenVPN installer failed (code {code}). Log: {}", log.display()),
    }
}

fn download(url: &str, dest: &PathBuf, progress: &impl Fn(&str)) -> Result<()> {
    progress("Downloading…");
    let resp = http().get(url).header("User-Agent", &user_agent()).call()?;
    let total: Option<u64> = resp.headers().get("content-length").and_then(|v| v.to_str().ok()?.parse().ok());
    let mut reader = resp.into_body().into_reader();
    let mut out = std::fs::File::create(dest)?;
    let mut buf = vec![0u8; 64 * 1024];
    let (mut done, mut last_pct) = (0u64, 0u64);
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut out, &buf[..n])?;
        done += n as u64;
        if let Some(total) = total.filter(|t| *t > 0) {
            let pct = done * 100 / total;
            if pct >= last_pct + 10 {
                last_pct = pct;
                progress(&format!("Downloading… {pct}%"));
            }
        }
    }
    Ok(())
}

fn verify_signature(file: &PathBuf) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let script = format!(
        "$s = Get-AuthenticodeSignature -LiteralPath '{}'; \
         if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=OpenVPN Inc\\.') {{ exit 1 }}",
        file.display().to_string().replace('\'', "''")
    );
    let ok = Command::new(crate::security::system32(r"WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .status()?
        .success();
    if !ok {
        let _ = std::fs::remove_file(file);
        bail!("The downloaded installer is not signed by OpenVPN Inc. It was deleted.");
    }
    Ok(())
}

// ── OpenConnect ─────────────────────────────────────────────────────────
//
// Upstream publishes no signed Windows installer. Every tagged release's CI
// pipeline keeps its Windows builds forever (job
// `persist-windows-builds-for-tagged-releases`), so Molehill downloads that
// artifact over HTTPS from the official gitlab.com/openconnect project, takes
// the 64-bit GnuTLS NSIS installer out of it and runs it silently.

const OPENCONNECT_PROJECT: &str = "https://gitlab.com/api/v4/projects/openconnect%2Fopenconnect";

pub fn openconnect_dir() -> Option<PathBuf> {
    paths::openconnect_dir()
}

fn openconnect_version() -> Option<String> {
    use std::os::windows::process::CommandExt;
    let exe = openconnect_dir()?.join("openconnect.exe");
    let out = Command::new(exe).arg("--version").creation_flags(CREATE_NO_WINDOW).output().ok()?;
    // "OpenConnect version v9.21"
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let line = text.lines().find(|l| l.starts_with("OpenConnect version"))?;
    Some(line.rsplit(' ').next()?.trim_start_matches('v').to_string())
}

/// Newest tagged release, e.g. "9.21".
fn latest_openconnect() -> Result<String> {
    let body = http().get(&format!("{OPENCONNECT_PROJECT}/releases?per_page=20"))
        .header("User-Agent", &user_agent())
        .call()?
        .body_mut()
        .read_to_string()?;
    let releases: serde_json::Value = serde_json::from_str(&body)?;
    releases
        .as_array()
        .ok_or_else(|| anyhow!("unexpected GitLab response"))?
        .iter()
        .filter(|r| !r["upcoming_release"].as_bool().unwrap_or(false))
        .filter_map(|r| r["tag_name"].as_str())
        .filter(|t| t.starts_with('v') && t[1..].split('.').all(|p| p.parse::<u32>().is_ok()))
        .max_by(|a, b| version::parse(a).cmp(&version::parse(b)))
        .map(|t| t.trim_start_matches('v').to_string())
        .ok_or_else(|| anyhow!("no OpenConnect release found"))
}

fn install_openconnect(progress: &impl Fn(&str)) -> Result<String> {
    use std::os::windows::process::CommandExt;
    progress("Looking up the latest version…");
    let latest = latest_openconnect()?;
    if openconnect_version().is_some_and(|i| !version::is_newer(&latest, &i)) {
        return Ok(format!("OpenConnect {latest} is already up to date."));
    }
    let dir = paths::service_dir().join("downloads");
    security::private_dir(&dir)?;
    let zip = dir.join(format!("openconnect-{latest}-windows.zip"));
    let url = format!("{OPENCONNECT_PROJECT}/jobs/artifacts/v{latest}/download?job=persist-windows-builds-for-tagged-releases");
    download(&url, &zip, progress)?;

    progress("Unpacking…");
    let installer_name = format!("openconnect-installer-MinGW64-GnuTLS-v{latest}.exe");
    let status = Command::new(crate::security::system32("tar.exe"))
        .arg("-xf")
        .arg(&zip)
        .arg("-C")
        .arg(&dir)
        .arg(&installer_name)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .context("running tar")?;
    let _ = std::fs::remove_file(&zip);
    let installer = dir.join(&installer_name);
    if !status.success() || !installer.is_file() {
        bail!("The OpenConnect download didn't contain {installer_name}.");
    }

    progress(&format!("Installing OpenConnect {latest}…"));
    // NSIS: /S silent. Stop running tunnels first is enforced by the caller.
    let code = Command::new(&installer).arg("/S").status().context("running the OpenConnect installer")?.code().unwrap_or(-1);
    let _ = std::fs::remove_file(&installer);
    info!("OpenConnect installer exited with {code}");
    if code != 0 || openconnect_dir().is_none() {
        bail!("The OpenConnect installer failed (code {code}).");
    }
    // NSIS adds shortcuts nobody needs next to Molehill.
    let _ = std::fs::remove_file(r"C:\Users\Public\Desktop\openconnect.exe.lnk");
    Ok(format!("OpenConnect {latest} installed."))
}

/// One HTTP client for all version checks and downloads. Without timeouts a
/// black-holed host would block the Components page, and the service's
/// shutdown behind it.
fn http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_recv_body(Some(Duration::from_secs(600)))
        .build()
        .into()
}
