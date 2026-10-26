//! Traffic counters of a network adapter, stale Wintun adapters, and console
//! control for openconnect.

use anyhow::{Context, Result, bail};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CR_SUCCESS, DiUninstallDevice, SP_DEVINFO_DATA, SetupDiCreateDeviceInfoList,
    SetupDiDestroyDeviceInfoList, SetupDiOpenDeviceInfoW,
};
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, HWND};
use windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceAliasToLuid, GetIfEntry2, MIB_IF_ROW2};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::System::Console::{AttachConsole, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler};
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW};
use windows::core::{HSTRING, PWSTR};

use crate::components::reg_string;

/// Network adapters: one subkey per adapter GUID, with `Connection\Name`.
const NETWORK_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// (received, sent) bytes of the adapter called `alias`.
pub fn interface_bytes(alias: &str) -> Option<(u64, u64)> {
    let alias = HSTRING::from(alias);
    let mut luid = NET_LUID_LH::default();
    unsafe { ConvertInterfaceAliasToLuid(&alias, &mut luid) }.ok().ok()?;
    let mut row = MIB_IF_ROW2 { InterfaceLuid: luid, ..Default::default() };
    unsafe { GetIfEntry2(&mut row) }.ok().ok()?;
    Some((row.InOctets, row.OutOctets))
}

/// Removes Wintun adapters called `alias` that are no longer present: left
/// behind when openconnect couldn't clean up (killed, crashed, rebooted while
/// connected). openconnect finds such a ghost by name, fails to open it and
/// gives up instead of creating a new one. Returns how many were removed.
pub fn remove_stale_wintun(alias: &str) -> Result<usize> {
    let mut removed = 0;
    for guid in subkeys(NETWORK_KEY)? {
        let conn = format!(r"{NETWORK_KEY}\{guid}\Connection");
        if reg_string(&conn, "Name").as_deref() != Some(alias) {
            continue;
        }
        let Some(instance) = reg_string(&conn, "PnPInstanceId") else { continue };
        if !instance.to_ascii_uppercase().starts_with(r"SWD\WINTUN\") {
            continue;
        }
        let id = HSTRING::from(instance.as_str());
        let mut devinst = 0;
        // Present: in use, or usable as it is.
        if unsafe { CM_Locate_DevNodeW(&mut devinst, &id, CM_LOCATE_DEVNODE_NORMAL) } == CR_SUCCESS {
            continue;
        }
        uninstall_device(&id).with_context(|| format!("removing {instance}"))?;
        removed += 1;
    }
    Ok(removed)
}

/// Like `pnputil /remove-device`; works on devices that aren't present.
fn uninstall_device(instance: &HSTRING) -> Result<()> {
    unsafe {
        let set = SetupDiCreateDeviceInfoList(None, None)?;
        let mut data = SP_DEVINFO_DATA { cbSize: size_of::<SP_DEVINFO_DATA>() as u32, ..Default::default() };
        let result = SetupDiOpenDeviceInfoW(set, instance, None, 0, Some(&mut data)).and_then(|()| DiUninstallDevice(HWND::default(), set, &data, 0, None));
        let _ = SetupDiDestroyDeviceInfoList(set);
        Ok(result?)
    }
}

fn subkeys(path: &str) -> Result<Vec<String>> {
    let path = HSTRING::from(path);
    let mut key = HKEY::default();
    unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &path, None, KEY_READ, &mut key) }.ok()?;
    let mut names = Vec::new();
    let mut buf = [0u16; 256];
    let err = loop {
        let mut len = buf.len() as u32;
        let err = unsafe { RegEnumKeyExW(key, names.len() as u32, Some(PWSTR(buf.as_mut_ptr())), &mut len, None, None, None, None) };
        if err.is_err() {
            break err;
        }
        names.push(String::from_utf16_lossy(&buf[..len as usize]));
    };
    let _ = unsafe { RegCloseKey(key) };
    if err != ERROR_NO_MORE_ITEMS {
        bail!("reading {path}: {}", err.to_hresult().message());
    }
    Ok(names)
}

/// `oc-stop <pid>`: delivers Ctrl+C to a console process (openconnect.exe),
/// which makes it disconnect cleanly.
pub fn send_ctrl_c(pid: u32) -> Result<()> {
    unsafe {
        let _ = FreeConsole();
        AttachConsole(pid)?;
        // Don't let the Ctrl+C stop this helper too.
        SetConsoleCtrlHandler(None, true)?;
        GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)?;
        let _ = FreeConsole();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_adapter_by_that_name() {
        assert_eq!(remove_stale_wintun("Molehill-no-such-adapter").unwrap(), 0);
    }
}
