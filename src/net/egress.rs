//! Physical network egress detection using OS kernel interface types and NDIS
//! hardware flags (zero hardcoded commercial client names).

#[cfg(all(windows, test))]
const VIRTUAL_ADAPTER_QUERY: &str = r#"
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference='Stop'
try {
    ConvertTo-Json -Compress -InputObject @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and -not $_.HardwareInterface } | ForEach-Object { $_.Name + '|' + $_.InterfaceDescription })
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"#;

#[cfg(all(windows, test))]
fn active_virtual_adapters() -> Result<Vec<String>, String> {
    let output = crate::system::powershell::output(VIRTUAL_ADAPTER_QUERY).map_err(|e| {
        format!("Не удалось запустить Windows PowerShell для проверки сетевых адаптеров: {e}")
    })?;
    parse_virtual_adapters(output)
}

#[cfg(all(windows, test))]
fn parse_virtual_adapters(output: std::process::Output) -> Result<Vec<String>, String> {
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Не удалось проверить сетевые адаптеры через Windows PowerShell ({}): {}",
            output.status,
            detail.trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| {
        format!("Некорректный ответ Windows PowerShell при проверке адаптеров: {e}")
    })
}

/// Standard IANA `ifType` check: PPP (23), proprietary virtual/internal (53),
/// and L3 tunnel encapsulation (131) are virtual tunnel interfaces, whereas
/// Ethernet (6) and IEEE 802.11 Wi-Fi (71) are physical NICs.
#[cfg(any(windows, test))]
fn is_iana_tunnel_type(if_type: u32) -> bool {
    const IF_TYPE_PPP: u32 = 23;
    const IF_TYPE_PROP_VIRTUAL: u32 = 53;
    const IF_TYPE_TUNNEL: u32 = 131;
    matches!(if_type, IF_TYPE_PPP | IF_TYPE_PROP_VIRTUAL | IF_TYPE_TUNNEL)
}

#[cfg(test)]
mod adapter_preflight_tests {
    #[test]
    fn classifies_iana_interface_types_by_kernel_code_without_vendor_names() {
        assert!(super::is_iana_tunnel_type(23)); // IF_TYPE_PPP
        assert!(super::is_iana_tunnel_type(53)); // IF_TYPE_PROP_VIRTUAL
        assert!(super::is_iana_tunnel_type(131)); // IF_TYPE_TUNNEL
        assert!(!super::is_iana_tunnel_type(6)); // IF_TYPE_ETHERNET_CSMACD
        assert!(!super::is_iana_tunnel_type(71)); // IF_TYPE_IEEE80211
    }

    #[cfg(windows)]
    #[test]
    fn queries_adapters_without_path_and_ignores_shadow_powershell() {
        use crate::system::{powershell, process::no_window};
        use std::{
            process::Command,
            time::{Duration, Instant},
        };

        const CHILD: &str = "ABR_TEST_POWERSHELL_ENVIRONMENT";
        if let Ok(mode) = std::env::var(CHILD) {
            if mode != "shadow" {
                let error = no_window(&mut Command::new("powershell.exe"))
                    .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
                    .output()
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                assert_eq!(error.to_string(), "program not found");
            }
            let executable = powershell::executable().unwrap();
            assert!(executable.is_absolute());
            assert!(!executable.starts_with(std::env::current_dir().unwrap()));
            super::active_virtual_adapters().unwrap();
            return;
        }

        for mode in ["empty", "unset", "shadow"] {
            let directory = tempfile::Builder::new()
                .prefix("adapter query путь ")
                .tempdir()
                .unwrap();
            if mode == "shadow" {
                std::fs::write(
                    directory.path().join("powershell.exe"),
                    b"not an executable",
                )
                .unwrap();
            }
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            no_window(&mut cmd);
            cmd.args([
                "--exact",
                "net::egress::adapter_preflight_tests::queries_adapters_without_path_and_ignores_shadow_powershell",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .current_dir(directory.path());
            match mode {
                "unset" => {
                    cmd.env_remove("PATH");
                }
                "shadow" => {
                    cmd.env("PATH", directory.path());
                }
                _ => {
                    cmd.env("PATH", "");
                }
            }
            let mut child = cmd.spawn().unwrap();
            let started = Instant::now();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "{mode}: {status}");
                    break;
                }
                if started.elapsed() > Duration::from_secs(30) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{mode}: adapter query timed out");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn adapter_query_handles_empty_lists_unicode_and_query_failures() {
        fn query(body: &str) -> Result<Vec<String>, String> {
            let script = format!(
                "function Get-NetAdapter {{ {body} }}\n{}",
                super::VIRTUAL_ADAPTER_QUERY
            );
            let output = crate::system::powershell::command()
                .unwrap()
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .unwrap();
            super::parse_virtual_adapters(output)
        }
        assert!(query("return @()").unwrap().is_empty());
        assert_eq!(
            query("[pscustomobject]@{Name='Сеть';InterfaceDescription='Userspace Tunnel';Status='Up';HardwareInterface=$false}")
                .unwrap(),
            ["Сеть|Userspace Tunnel"]
        );
        assert_eq!(
            query(
                r#"
                [pscustomobject]@{Name='Ethernet';InterfaceDescription='PCIe Gigabit';Status='Up';HardwareInterface=$true}
                [pscustomobject]@{Name='Tunnel0';InterfaceDescription='Virtual Tunnel';Status='Disconnected';HardwareInterface=$false}
                [pscustomobject]@{Name='Сеть';InterfaceDescription='L3 Tunnel A';Status='Up';HardwareInterface=$false}
                [pscustomobject]@{Name='utun1';InterfaceDescription='L3 Tunnel B';Status='Up';HardwareInterface=$false}
            "#
            )
            .unwrap(),
            ["Сеть|L3 Tunnel A", "utun1|L3 Tunnel B"]
        );
        let error = query("throw 'Ошибка службы адаптеров'").unwrap_err();
        assert!(error.contains("Ошибка службы адаптеров"), "{error}");
        for response in ["", "not json"] {
            let output = crate::system::powershell::command()
                .unwrap()
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!("Write-Output '{response}'"),
                ])
                .output()
                .unwrap();
            assert!(super::parse_virtual_adapters(output).is_err());
        }
    }
}

#[cfg(target_os = "windows")]
fn if_entry_type(if_index: u32) -> Option<u32> {
    #[repr(C)]
    struct MibIfRow {
        wsz_name: [u16; 256],
        dw_index: u32,
        dw_type: u32,
        dw_mtu: u32,
        dw_speed: u32,
        dw_phys_addr_len: u32,
        b_phys_addr: [u8; 8],
        dw_admin_status: u32,
        dw_oper_status: u32,
        dw_last_change: u32,
        dw_in_octets: u32,
        dw_in_ucast_pkts: u32,
        dw_in_nucast_pkts: u32,
        dw_in_discards: u32,
        dw_in_errors: u32,
        dw_in_unknown_protos: u32,
        dw_out_octets: u32,
        dw_out_ucast_pkts: u32,
        dw_out_nucast_pkts: u32,
        dw_out_discards: u32,
        dw_out_errors: u32,
        dw_out_qlen: u32,
        dw_descr_len: u32,
        b_descr: [u8; 256],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIfEntry(pIfRow: *mut MibIfRow) -> u32;
    }

    let mut row: MibIfRow = unsafe { std::mem::zeroed() };
    row.dw_index = if_index;
    if unsafe { GetIfEntry(&mut row) } != 0 {
        return None;
    }
    Some(row.dw_type)
}

#[cfg(target_os = "windows")]
fn is_tunnel_iface(if_index: u32) -> bool {
    if_entry_type(if_index).is_some_and(is_iana_tunnel_type)
}

/// Physical default route (skips virtual L3 tunnel adapters via OS interface flags).
pub fn detect_physical() -> Option<(u32, String)> {
    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        struct MibIpForwardRow {
            dw_forward_dest: u32,
            dw_forward_mask: u32,
            dw_forward_policy: u32,
            dw_forward_next_hop: u32,
            dw_forward_if_index: u32,
            dw_forward_type: u32,
            dw_forward_proto: u32,
            dw_forward_age: u32,
            dw_forward_next_hop_as: u32,
            dw_forward_metric1: u32,
            dw_forward_metric2: u32,
            dw_forward_metric3: u32,
            dw_forward_metric4: u32,
            dw_forward_metric5: u32,
        }
        #[link(name = "iphlpapi")]
        extern "system" {
            fn GetBestRoute(
                dwDestAddr: u32,
                dwSourceAddr: u32,
                pBestRoute: *mut MibIpForwardRow,
            ) -> u32;
        }

        let mut row: MibIpForwardRow = unsafe { std::mem::zeroed() };
        let dest: u32 = u32::from_ne_bytes([8, 8, 8, 8]);
        if unsafe { GetBestRoute(dest, 0, &mut row) } == 0
            && !is_tunnel_iface(row.dw_forward_if_index)
        {
            let gw = row.dw_forward_next_hop.to_ne_bytes();
            if gw != [0, 0, 0, 0] {
                return Some((
                    row.dw_forward_if_index,
                    format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]),
                ));
            }
        }

        // Pure NDIS HardwareInterface / Virtual properties — zero vendor names.
        let ps = r#"
$phys = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.Status -eq 'Up' -and $_.HardwareInterface -and -not $_.Virtual
} | ForEach-Object { $_.ifIndex })
$def = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
$mine = @($def | Where-Object { $phys -contains $_.ifIndex -and $_.NextHop -ne '0.0.0.0' })
if ($mine.Count -gt 0) {
    $best = $mine | Sort-Object { [int]$_.RouteMetric } | Select-Object -First 1
    Write-Output ("{0}|{1}" -f $best.ifIndex, $best.NextHop)
}
"#;
        let out = crate::system::powershell::output(ps).ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Some((idx, gw)) = s.split_once('|') {
            if let Ok(i) = idx.trim().parse::<u32>() {
                let gw = gw.trim().to_string();
                if i > 0 && !gw.is_empty() && gw != "0.0.0.0" {
                    return Some((i, gw));
                }
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        for n in 0..=15 {
            let cand = format!("en{n}");
            if let Ok(out) = crate::system::command::output(
                "/usr/sbin/ipconfig",
                ["getoption", cand.as_str(), "router"],
            ) {
                if out.status.success() {
                    let gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !gw.is_empty() && gw.contains('.') && !gw.starts_with("169.254.") {
                        if let Ok(c_name) = std::ffi::CString::new(cand.as_str()) {
                            let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
                            if idx > 0 {
                                return Some((idx, gw));
                            }
                        }
                    }
                }
            }
            if let Ok(out) = crate::system::command::output(
                "/sbin/route",
                ["-n", "get", "-ifscope", cand.as_str(), "8.8.8.8"],
            ) {
                if out.status.success() {
                    let txt = String::from_utf8_lossy(&out.stdout);
                    let mut gateway = String::new();
                    for line in txt.lines() {
                        let l = line.trim();
                        if l.starts_with("gateway:") {
                            gateway = l.trim_start_matches("gateway:").trim().to_string();
                        }
                    }
                    if !gateway.is_empty() && gateway.contains('.') {
                        if let Ok(c_name) = std::ffi::CString::new(cand.as_str()) {
                            let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
                            if idx > 0 {
                                return Some((idx, gateway));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    None
}
