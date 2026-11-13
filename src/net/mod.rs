//! Network layer: local HTTP/SOCKS5 proxy gateway, PAC auto-routing,
//! Chrome GLIC unlock, and deep cleanup of legacy / third-party DNS remnants.
pub mod config;
pub mod egress;
pub mod gemini_apps;
pub mod health;
pub mod hosts;
pub mod local_proxy;
pub mod proxy_config;
pub mod proxy_session;
pub mod socket;

use std::fs;
use std::path::{Path, PathBuf};

pub(super) struct ConfigurationLock(fs::File);

impl Drop for ConfigurationLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(super) fn configuration_lock() -> Result<ConfigurationLock, String> {
    config::ensure_directory()?;
    lock_configuration_file(&config::directory().join("network-update.lock"))
}

fn lock_configuration_file(path: &Path) -> Result<ConfigurationLock, String> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Блокировка настройки сети: {e}"))?;
    file.try_lock().map_err(|e| match e {
        fs::TryLockError::WouldBlock => {
            "Настройки сети уже обновляются другим процессом. Повторите через пару секунд.".into()
        }
        other => format!("Блокировка настройки сети: {other}"),
    })?;
    Ok(ConfigurationLock(file))
}

pub fn flush_dns_cache() -> Result<(), String> {
    #[cfg(windows)]
    let commands: &[(&str, &[&str])] = &[("ipconfig", &["/flushdns"])];
    #[cfg(target_os = "macos")]
    let commands: &[(&str, &[&str])] = &[
        ("dscacheutil", &["-flushcache"]),
        ("killall", &["-HUP", "mDNSResponder"]),
    ];
    #[cfg(not(any(windows, target_os = "macos")))]
    let commands: &[(&str, &[&str])] = &[];
    let mut errors = Vec::new();
    for (program, args) in commands {
        match crate::system::command::output(program, *args) {
            Ok(out) if out.status.success() => {}
            Ok(out) => errors.push(format!("{program}: {}", out.status)),
            Err(error) => errors.push(format!("{program}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Не удалось обновить кэш DNS: {}",
            errors.join("; ")
        ))
    }
}

/// Remove legacy DNS relays, `/etc/hosts` blackholes, `/etc/resolver` rules,
/// and (when `deep_third_party` is true) remnants from older bypass tools
/// (`vesln1`, `ConfeDEN` / `AntigravityBypass`, `AntigravityBypassRussia`).
pub fn clean_legacy_network(deep_third_party: bool) -> Result<Vec<String>, String> {
    let _lock = configuration_lock()?;
    let mut cleaned = Vec::new();
    let mut errors = Vec::new();

    if let Some(note) = stop_legacy_dns_daemon() {
        cleaned.push(note);
    }

    let hosts_mode = config::directory().join("hosts-mode");
    if hosts_mode.exists() && fs::remove_file(&hosts_mode).is_ok() {
        cleaned.push("удалён устаревший маркер hosts-mode".into());
    }

    match hosts::remove_entries() {
        Ok(true) => cleaned.push("очищены правила и заглушки в системном hosts".into()),
        Ok(false) => {}
        Err(error) => errors.push(error),
    }

    let tcp_restore = if deep_third_party {
        socket::restore_os_network_stack()
    } else {
        socket::restore_current_network_stack()
    };
    if let Err(error) = tcp_restore {
        errors.push(error);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(note) = gemini_apps::clean_google_proxy_bypass_domains() {
            cleaned.push(note);
        }
        match clean_resolver_directory(Path::new("/etc/resolver"), deep_third_party) {
            Ok(count) if count > 0 => {
                cleaned.push(format!("очищено объектов в /etc/resolver: {count}"))
            }
            Ok(_) => {}
            Err(error) => errors.push(error),
        }
        if deep_third_party {
            cleaned.extend(clean_macos_third_party_dirs());
        }
    }

    #[cfg(target_os = "windows")]
    if deep_third_party {
        if let Some(note) = clean_windows_legacy_nrpt() {
            cleaned.push(note);
        }
    }

    if !cleaned.is_empty() || deep_third_party {
        let _ = flush_dns_cache();
    }

    if errors.is_empty() {
        Ok(cleaned)
    } else {
        Err(errors.join("; "))
    }
}

pub fn resolver_has_gate_files() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
    #[cfg(target_os = "macos")]
    {
        let Ok(entries) = fs::read_dir("/etc/resolver") else {
            return false;
        };
        entries.flatten().any(|entry| {
            entry.path().is_file()
                && hosts::is_legacy_or_gate_host(&entry.file_name().to_string_lossy())
        })
    }
}

pub fn legacy_daemon_present() -> bool {
    #[cfg(target_os = "macos")]
    {
        [
            "/Library/LaunchDaemons/com.antigravity.bypass.russia.plist",
            "/Library/LaunchDaemons/com.antigravity.bypass.watchdog.plist",
            "/Library/LaunchDaemons/com.antigravity.bypass.dns.plist",
            "/Library/LaunchDaemons/com.antigravity.bypass.plist",
        ]
        .iter()
        .any(|p| Path::new(p).exists())
    }
    #[cfg(target_os = "windows")]
    {
        crate::system::command::output("schtasks", ["/Query", "/TN", "AntigravityBypassRussia"])
            .is_ok_and(|o| o.status.success())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

fn stop_legacy_dns_daemon() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let labels = [
            "com.antigravity.bypass.russia",
            "com.antigravity.bypass.watchdog",
            "com.antigravity.bypass.dns",
            "com.antigravity.bypass",
        ];
        let daemon_bin = Path::new("/Library/Application Support/AntigravityBypassRussia/ag_dns");
        let mut stopped = Vec::new();
        for label in labels {
            let plist = PathBuf::from(format!("/Library/LaunchDaemons/{label}.plist"));
            if !plist.exists() {
                continue;
            }
            let _ = crate::system::command::output("launchctl", ["bootout", &format!("system/{label}")]);
            let _ = crate::system::command::output(
                "launchctl",
                ["unload", "-w", &plist.to_string_lossy()],
            );
            let _ = crate::system::journal::restore(&plist).or_else(|_| {
                fs::remove_file(&plist)
                    .map(|_| true)
                    .map_err(|e| e.to_string())
            });
            stopped.push(label);
        }
        if daemon_bin.exists() && fs::remove_file(daemon_bin).is_ok() && stopped.is_empty() {
            stopped.push("ag_dns");
        }
        if let Ok(uid) = local_proxy::user_id() {
            let _ = crate::system::command::output(
                "launchctl",
                [
                    "asuser",
                    &uid.to_string(),
                    "/bin/launchctl",
                    "unsetenv",
                    "GRPC_DNS_RESOLVER",
                ],
            );
        }
        (!stopped.is_empty()).then(|| {
            format!(
                "остановлены и удалены старые фоновые демоны ({})",
                stopped.join(", ")
            )
        })
    }
    #[cfg(target_os = "windows")]
    {
        let out = crate::system::command::output(
            "schtasks",
            ["/Query", "/TN", "AntigravityBypassRussia"],
        )
        .ok()?;
        if !out.status.success() {
            return None;
        }
        let _ = crate::system::command::output(
            "schtasks",
            ["/End", "/TN", "AntigravityBypassRussia"],
        );
        let _ = crate::system::command::output(
            "schtasks",
            ["/Delete", "/TN", "AntigravityBypassRussia", "/F"],
        );
        Some("удалена старая служба DNS AntigravityBypassRussia".into())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

pub(crate) fn clean_resolver_directory(dir: &Path, deep_third_party: bool) -> Result<usize, String> {
    if !dir.exists() {
        return Ok(0);
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("Чтение {}: {e}", dir.display()))?;
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_file() && hosts::is_legacy_or_gate_host(&name) {
            let text = fs::read_to_string(&path).unwrap_or_default();
            if deep_third_party
                || text.contains("Antigravity")
                || crate::system::journal::has_record(&path)
            {
                if crate::system::journal::has_record(&path) {
                    let _ = crate::system::journal::restore(&path);
                }
                if path.exists() && fs::remove_file(&path).is_ok() {
                    removed += 1;
                } else if !path.exists() {
                    removed += 1;
                }
            }
        } else if deep_third_party && path.is_dir() {
            if let Some(domain) = name.strip_suffix(".ag-backups") {
                if hosts::is_legacy_or_gate_host(domain) && !dir.join(domain).exists() {
                    if fs::remove_dir_all(&path).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
    }
    if fs::read_dir(dir).is_ok_and(|mut it| it.next().is_none()) {
        let _ = fs::remove_dir(dir);
    }
    Ok(removed)
}

#[cfg(target_os = "macos")]
fn clean_macos_third_party_dirs() -> Vec<String> {
    let mut notes = Vec::new();
    let confeden_dir = Path::new("/Library/Application Support/AntigravityBypass");
    if confeden_dir.exists() {
        let mut removed_any = false;
        let routes_json = confeden_dir.join("owned_routes_macos.json");
        if let Ok(bytes) = fs::read(&routes_json) {
            if let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
                for item in items {
                    if let Some(ip) = item.get("ip").and_then(|v| v.as_str()) {
                        if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                            let _ = crate::system::command::output(
                                "/sbin/route",
                                ["-n", "delete", "-host", ip],
                            );
                        }
                    }
                }
                let _ = crate::system::command::output(
                    "networksetup",
                    ["-setadditionalroutes", "Wi-Fi"],
                );
            }
        }
        for file in [
            "iface.conf",
            "known_good_ips.json",
            "quarantine.json",
            "upstream.conf",
            "watchdog.log",
            "ag_dns",
            "owned_routes_macos.json",
            "macos-instant-fix.py",
        ] {
            let target = confeden_dir.join(file);
            if target.exists() && fs::remove_file(&target).is_ok() {
                removed_any = true;
            }
        }
        if fs::read_dir(confeden_dir).is_ok_and(|mut it| it.next().is_none()) {
            let _ = fs::remove_dir(confeden_dir);
            removed_any = true;
        }
        if removed_any {
            notes.push("удалены хвосты стороннего обходчика в /Library/Application Support/AntigravityBypass".into());
        }
    }
    let old_root_dir = Path::new("/Library/Application Support/AntigravityBypassRussia");
    if old_root_dir.exists() {
        for file in ["ag_dns", "stdout.log", "stderr.log"] {
            let _ = fs::remove_file(old_root_dir.join(file));
        }
        if fs::read_dir(old_root_dir).is_ok_and(|mut it| it.next().is_none())
            && fs::remove_dir(old_root_dir).is_ok()
        {
            notes.push("удалена пустая системная папка старой DNS-службы".into());
        }
    }
    notes
}

#[cfg(target_os = "windows")]
fn clean_windows_legacy_nrpt() -> Option<String> {
    let script = "Get-DnsClientNrptRule | Where-Object { $_.Comment -like '*Antigravity*' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }";
    let out = crate::system::powershell::output(script).ok()?;
    out.status
        .success()
        .then(|| "проверены и очищены старые правила NRPT".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_writers_are_exclusive_and_unlock_without_deleting_the_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network-update.lock");
        let foreground = lock_configuration_file(&path).unwrap();
        let inherited = foreground.0.try_clone().unwrap();
        assert!(lock_configuration_file(&path).is_err());
        drop(foreground);
        let background = lock_configuration_file(&path).unwrap();
        assert!(lock_configuration_file(&path).is_err());
        drop(background);
        drop(inherited);
        assert!(path.exists());
        assert!(lock_configuration_file(&path).is_ok());
    }

    #[test]
    fn resolver_cleanup_removes_owned_rules_and_orphaned_backups_while_preserving_user_files() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = dir.path().join("resolver");
        fs::create_dir_all(&resolver).unwrap();
        fs::write(
            resolver.join("gemini.google.com"),
            "# Antigravity-Bypass\nnameserver 127.0.0.1\n",
        )
        .unwrap();
        fs::write(
            resolver.join("makersuite.google.com"),
            "nameserver 45.155.204.190\n",
        )
        .unwrap();
        let orphan = resolver.join("daily-cloudcode-pa.googleapis.com.ag-backups");
        fs::create_dir_all(&orphan).unwrap();
        fs::write(orphan.join("legacy.json"), "{}").unwrap();
        fs::write(resolver.join("corp.internal"), "nameserver 10.0.0.53\n").unwrap();

        let count = clean_resolver_directory(&resolver, true).unwrap();
        assert_eq!(count, 3);
        assert!(!resolver.join("gemini.google.com").exists());
        assert!(!resolver.join("makersuite.google.com").exists());
        assert!(!orphan.exists());
        assert!(resolver.join("corp.internal").exists());
    }
}
