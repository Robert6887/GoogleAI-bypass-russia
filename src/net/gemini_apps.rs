//! System PAC auto-configuration (for Gemini Web / AI Studio / Gemini.app WebKit)
//! and Chrome built-in Gemini ("Ask Gemini" / GLIC) `Local State` unlock & rollback.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PacOriginal {
    url: Option<String>,
    enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PacBackup {
    schema: u32,
    services: BTreeMap<String, PacOriginal>,
}

fn pac_backup_path() -> PathBuf {
    super::config::directory().join("pac-session.json")
}

pub fn is_managed_pac_url(url: &str) -> bool {
    url.trim()
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.strip_suffix("/proxy.pac"))
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| port != 0)
}

/// Extract enabled macOS network services eligible for PAC auto-configuration from
/// `networksetup -listnetworkserviceorder`: physical `en*` adapters and enabled
/// virtual tunnel services (`Device:` empty), skipping disabled (`*`) entries and
/// L2 bridge interfaces (`bridge*`).
pub fn parse_pac_services(order_text: &str) -> Vec<String> {
    let mut services = Vec::new();
    let mut pending_service: Option<String> = None;
    for raw_line in order_text.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix('(') {
            if let Some((tag, after)) = rest.split_once(')') {
                if tag == "*" {
                    pending_service = None;
                    continue;
                }
                if !tag.is_empty() && tag.bytes().all(|b| b.is_ascii_digit()) {
                    let name = after.trim();
                    pending_service = (!name.is_empty()).then(|| name.to_string());
                    continue;
                }
                if line.starts_with("(Hardware Port:") {
                    if let (Some(service), Some((_, dev_part))) =
                        (pending_service.take(), line.rsplit_once("Device:"))
                    {
                        let dev = dev_part.trim_end_matches(')').trim();
                        let is_physical_en = dev.starts_with("en")
                            && !dev[2..].is_empty()
                            && dev[2..].bytes().all(|b| b.is_ascii_digit());
                        let is_tunnel_service = dev.is_empty();
                        if is_physical_en || is_tunnel_service {
                            services.push(service);
                        }
                    }
                }
            }
        }
    }
    services
}

pub fn parse_autoproxy(text: &str) -> (Option<String>, bool) {
    let mut url = None;
    let mut enabled = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(val) = line.strip_prefix("URL:") {
            let trimmed = val.trim();
            if !trimmed.is_empty() && trimmed != "(null)" {
                url = Some(trimmed.to_string());
            }
        } else if let Some(val) = line.strip_prefix("Enabled:") {
            enabled = val.trim().eq_ignore_ascii_case("yes");
        }
    }
    (url, enabled)
}

fn load_pac_backup() -> Result<Option<PacBackup>, String> {
    match fs::read(pac_backup_path()) {
        Ok(bytes) => {
            let backup: PacBackup = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(Some(backup))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn save_pac_backup(backup: &PacBackup) -> Result<(), String> {
    super::config::ensure_directory()?;
    let path = pac_backup_path();
    crate::system::fs_utils::robust_write_file(
        &path,
        &serde_json::to_vec_pretty(backup).map_err(|e| e.to_string())?,
    )?;
    super::config::inherit_directory_owner(&path)
}

pub fn is_google_proxy_bypass_entry(entry: &str) -> bool {
    let lower = entry.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = lower.strip_prefix("*.").unwrap_or(&lower);
    matches!(
        host,
        "googleapis.com"
            | "gemini.google.com"
            | "aistudio.google.com"
            | "clients6.google.com"
            | "ai.google.dev"
            | "makersuite.google.com"
            | "notebooklm.google.com"
    ) || super::hosts::is_legacy_or_gate_host(host)
}

/// Remove only Google AI domains injected into macOS `ProxyBypassDomains` by
/// older SmartDNS scripts so CFNetwork and Chromium do not skip `/proxy.pac`.
/// Returns `Some(cleaned_list)` only when at least one Google AI domain was removed.
pub fn filter_google_proxy_bypass_domains(raw_text: &str) -> Option<Vec<String>> {
    let existing: Vec<String> = raw_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.contains("aren't any"))
        .map(ToOwned::to_owned)
        .collect();
    let mut cleaned: Vec<String> = existing
        .iter()
        .filter(|entry| !is_google_proxy_bypass_entry(entry))
        .cloned()
        .collect();
    if cleaned.len() == existing.len() {
        return None;
    }
    if cleaned.is_empty() {
        cleaned.push("*.local".to_string());
        cleaned.push("169.254/16".to_string());
    }
    Some(cleaned)
}

pub fn proxy_bypass_blocks_google() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
    #[cfg(target_os = "macos")]
    {
        let Ok(order) = crate::system::command::output("networksetup", ["-listnetworkserviceorder"])
        else {
            return false;
        };
        if !order.status.success() {
            return false;
        }
        for service in parse_pac_services(&String::from_utf8_lossy(&order.stdout)) {
            if let Ok(out) = crate::system::command::output(
                "networksetup",
                ["-getproxybypassdomains", service.as_str()],
            ) {
                if out.status.success()
                    && filter_google_proxy_bypass_domains(&String::from_utf8_lossy(&out.stdout))
                        .is_some()
                {
                    return true;
                }
            }
        }
        false
    }
}

pub fn clean_google_proxy_bypass_domains() -> Option<String> {
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
    #[cfg(target_os = "macos")]
    {
        let order =
            crate::system::command::output("networksetup", ["-listnetworkserviceorder"]).ok()?;
        if !order.status.success() {
            return None;
        }
        let mut cleaned_services = 0usize;
        for service in parse_pac_services(&String::from_utf8_lossy(&order.stdout)) {
            let Ok(out) = crate::system::command::output(
                "networksetup",
                ["-getproxybypassdomains", service.as_str()],
            ) else {
                continue;
            };
            if !out.status.success() {
                continue;
            }
            if let Some(cleaned) =
                filter_google_proxy_bypass_domains(&String::from_utf8_lossy(&out.stdout))
            {
                let mut args = vec!["-setproxybypassdomains".to_string(), service];
                args.extend(cleaned);
                if crate::system::command::output("networksetup", args)
                    .is_ok_and(|r| r.status.success())
                {
                    cleaned_services += 1;
                }
            }
        }
        (cleaned_services > 0).then(|| {
            format!(
                "удалены исключения Google AI из ProxyBypassDomains ({cleaned_services} служб)"
            )
        })
    }
}

pub fn enable_system_pac(pac_url: &str) -> Result<Vec<String>, String> {
    if !is_managed_pac_url(pac_url) {
        return Err("Системный PAC должен указывать на локальный 127.0.0.1".into());
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pac_url;
        return Ok(Vec::new());
    }
    #[cfg(target_os = "macos")]
    {
        let _ = clean_google_proxy_bypass_domains();
        let order = crate::system::command::output("networksetup", ["-listnetworkserviceorder"])
            .map_err(|e| e.to_string())?;
        if !order.status.success() {
            return Err("Не удалось получить список сетевых служб macOS".into());
        }
        let services = parse_pac_services(&String::from_utf8_lossy(&order.stdout));
        if services.is_empty() {
            return Err("Не найдена активная сетевая служба macOS для настройки PAC".into());
        }
        let mut backup = load_pac_backup()?.unwrap_or(PacBackup {
            schema: 1,
            services: BTreeMap::new(),
        });
        backup.schema = 1;
        let mut applied = Vec::new();
        let mut skipped_custom = 0usize;
        let mut errors = Vec::new();
        for service in services {
            let current_out = crate::system::command::output(
                "networksetup",
                ["-getautoproxyurl", service.as_str()],
            )
            .map_err(|e| e.to_string())?;
            if !current_out.status.success() {
                errors.push(format!(
                    "{service}: {}",
                    String::from_utf8_lossy(&current_out.stderr).trim()
                ));
                continue;
            }
            let (cur_url, cur_enabled) =
                parse_autoproxy(&String::from_utf8_lossy(&current_out.stdout));
            if cur_enabled && !cur_url.as_deref().is_some_and(is_managed_pac_url) {
                // Never overwrite a corporate or user-configured PAC URL.
                skipped_custom += 1;
                continue;
            }
            backup.services.entry(service.clone()).or_insert(PacOriginal {
                url: cur_url,
                enabled: cur_enabled,
            });
            save_pac_backup(&backup)?;
            let set_url = crate::system::command::output(
                "networksetup",
                ["-setautoproxyurl", service.as_str(), pac_url],
            )
            .map_err(|e| e.to_string())?;
            let set_on = crate::system::command::output(
                "networksetup",
                ["-setautoproxystate", service.as_str(), "on"],
            )
            .map_err(|e| e.to_string())?;
            if set_url.status.success() && set_on.status.success() {
                applied.push(service);
            } else {
                let detail = format!(
                    "{} {}",
                    String::from_utf8_lossy(&set_url.stderr).trim(),
                    String::from_utf8_lossy(&set_on.stderr).trim()
                );
                errors.push(format!("{service}: {}", detail.trim()));
            }
        }
        if applied.is_empty() && skipped_custom == 0 {
            return Err(if errors.is_empty() {
                "Системный PAC не применён ни к одной сетевой службе".into()
            } else {
                errors.join("; ")
            });
        }
        if !applied.is_empty() {
            let _ = crate::system::command::output("dscacheutil", ["-flushcache"]);
            let deadline = Instant::now() + Duration::from_millis(1500);
            while Instant::now() < deadline && !pac_active() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(applied)
    }
}

pub fn disable_system_pac() -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    return Ok(());
    #[cfg(target_os = "macos")]
    {
        let backup = load_pac_backup()?;
        let mut errors = Vec::new();
        let mut handled_services = std::collections::BTreeSet::new();
        if let Some(backup) = &backup {
            for (service, orig) in &backup.services {
                handled_services.insert(service.clone());
                let Ok(current_out) = crate::system::command::output(
                    "networksetup",
                    ["-getautoproxyurl", service.as_str()],
                ) else {
                    continue;
                };
                if !current_out.status.success() {
                    continue;
                }
                let (cur_url, cur_enabled) =
                    parse_autoproxy(&String::from_utf8_lossy(&current_out.stdout));
                if cur_enabled
                    && !cur_url.as_deref().is_some_and(is_managed_pac_url)
                    && cur_url != orig.url
                {
                    // User configured another PAC afterwards; leave it intact.
                    continue;
                }
                if let Some(orig_url) = &orig.url {
                    let _ = crate::system::command::output(
                        "networksetup",
                        ["-setautoproxyurl", service.as_str(), orig_url.as_str()],
                    );
                }
                let desired_state = if orig.enabled { "on" } else { "off" };
                match crate::system::command::output(
                    "networksetup",
                    ["-setautoproxystate", service.as_str(), desired_state],
                ) {
                    Ok(out) if out.status.success() => {}
                    Ok(out) => errors.push(format!(
                        "{service}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    )),
                    Err(e) => errors.push(format!("{service}: {e}")),
                }
            }
        }
        // Also turn off any orphaned 127.0.0.1:<port>/proxy.pac left on active
        // services when our backup file was absent (e.g., third-party local PAC).
        if let Ok(order) =
            crate::system::command::output("networksetup", ["-listnetworkserviceorder"])
        {
            if order.status.success() {
                for service in parse_pac_services(&String::from_utf8_lossy(&order.stdout)) {
                    if handled_services.contains(&service) {
                        continue;
                    }
                    let Ok(current_out) = crate::system::command::output(
                        "networksetup",
                        ["-getautoproxyurl", service.as_str()],
                    ) else {
                        continue;
                    };
                    if !current_out.status.success() {
                        continue;
                    }
                    let (cur_url, cur_enabled) =
                        parse_autoproxy(&String::from_utf8_lossy(&current_out.stdout));
                    if cur_enabled && cur_url.as_deref().is_some_and(is_managed_pac_url) {
                        let _ = crate::system::command::output(
                            "networksetup",
                            ["-setautoproxystate", service.as_str(), "off"],
                        );
                    }
                }
            }
        }
        if errors.is_empty() {
            match fs::remove_file(pac_backup_path()) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err(errors.join("; "))
        }
    }
}

pub fn pac_active() -> bool {
    #[cfg(not(target_os = "macos"))]
    return false;
    #[cfg(target_os = "macos")]
    {
        if !pac_backup_path().exists() {
            return false;
        }
        let Ok(out) = crate::system::command::output("scutil", ["--proxy"]) else {
            return false;
        };
        if !out.status.success() {
            return false;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let enabled = text
            .lines()
            .any(|l| l.trim() == "ProxyAutoConfigEnable : 1");
        let managed = text.lines().any(|l| {
            l.trim()
                .strip_prefix("ProxyAutoConfigURLString :")
                .is_some_and(|u| is_managed_pac_url(u.trim()))
        });
        enabled && managed
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChromeGlicBackup {
    pub schema: u32,
    pub top_keys: BTreeMap<String, Option<serde_json::Value>>,
    pub profile_eligibility: BTreeMap<String, Option<serde_json::Value>>,
}

fn chrome_glic_backup_path() -> PathBuf {
    super::config::directory().join("chrome-glic-backup.json")
}

pub fn chrome_user_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        crate::system::env::expand_env_vars(r"%LOCALAPPDATA%\Google\Chrome\User Data")
    }
    #[cfg(target_os = "macos")]
    {
        crate::system::env::expand_env_vars("~/Library/Application Support/Google/Chrome")
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        crate::system::env::expand_env_vars("~/.config/google-chrome")
    }
}

pub fn chrome_local_state_path() -> PathBuf {
    chrome_user_data_dir().join("Local State")
}

pub fn chrome_installed() -> bool {
    chrome_local_state_path().is_file()
}

pub fn chrome_running() -> bool {
    #[cfg(target_os = "macos")]
    {
        crate::system::command::output("pgrep", ["-x", "Google Chrome"])
            .is_ok_and(|out| out.status.success())
    }
    #[cfg(windows)]
    {
        crate::system::process::snapshot().is_ok_and(|list| {
            list.iter().any(|p| {
                p.executable
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("chrome.exe"))
            })
        })
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
fn exact_pids(process_name: &str) -> Vec<i32> {
    let Ok(out) = crate::system::command::output("pgrep", ["-x", process_name]) else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<i32>().ok())
        .filter(|pid| *pid > 1)
        .collect()
}

pub fn stop_gemini_desktop() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
    #[cfg(target_os = "macos")]
    {
        let mut pids = exact_pids("Gemini");
        pids.extend(exact_pids("GeminiAppLauncher"));
        if pids.is_empty() {
            return false;
        }
        for pid in &pids {
            unsafe {
                libc::kill(*pid, libc::SIGTERM);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if exact_pids("Gemini").is_empty() && exact_pids("GeminiAppLauncher").is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        true
    }
}

pub fn quit_chrome() -> Result<(), String> {
    if !chrome_running() {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        let gui_uid = fs::metadata(crate::system::env::expand_env_vars("~"))
            .ok()
            .map(|m| m.uid())
            .unwrap_or(0);
        if unsafe { libc::geteuid() } == 0 && gui_uid != 0 {
            let _ = crate::system::command::output(
                "launchctl",
                [
                    "asuser".into(),
                    gui_uid.to_string(),
                    "/usr/bin/osascript".into(),
                    "-e".into(),
                    "tell application \"Google Chrome\" to quit".into(),
                ],
            );
        } else {
            let _ = crate::system::command::output(
                "osascript",
                ["-e", "tell application \"Google Chrome\" to quit"],
            );
        }
        let osa_deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < osa_deadline {
            if !chrome_running() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        // Fallback if Terminal lacks AppleEvents TCC permission: Chromium's POSIX
        // ShutdownDetector treats SIGTERM on the main browser PID as a clean quit.
        for pid in exact_pids("Google Chrome") {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = crate::system::command::output("taskkill", ["/IM", "chrome.exe"]);
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        if !chrome_running() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err("Google Chrome не закрылся вовремя — закройте его вручную (⌘Q) и повторите".into())
}

const CHROME_COUNTRY_KEYS: [&str; 4] = [
    "variations_country",
    "variations_permanent_consistency_country",
    "variations_safe_seed_permanent_consistency_country",
    "variations_safe_seed_session_consistency_country",
];

pub fn state_needs_glic_unlock(root: &serde_json::Value) -> bool {
    let Some(obj) = root.as_object() else {
        return false;
    };
    if obj.get("variations_country").and_then(|v| v.as_str()) != Some("us") {
        return true;
    }
    if let Some(arr) = obj
        .get("variations_permanent_consistency_country")
        .and_then(|v| v.as_array())
    {
        if arr.last().and_then(|v| v.as_str()) != Some("us") {
            return true;
        }
    }
    if let Some(cache) = obj
        .get("profile")
        .and_then(|p| p.get("info_cache"))
        .and_then(|c| c.as_object())
    {
        for info in cache.values() {
            if info.get("is_glic_eligible").and_then(|v| v.as_bool()) != Some(true) {
                return true;
            }
        }
    }
    false
}

pub fn chrome_glic_needs_unlock() -> bool {
    let Ok(bytes) = fs::read(chrome_local_state_path()) else {
        return false;
    };
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    state_needs_glic_unlock(&root)
}

pub fn patch_local_state_json(
    root: &mut serde_json::Value,
    backup: &mut ChromeGlicBackup,
) -> Result<usize, String> {
    let obj = root
        .as_object_mut()
        .ok_or("Local State не является JSON-объектом")?;
    backup.schema = 1;
    for key in CHROME_COUNTRY_KEYS {
        backup
            .top_keys
            .entry(key.to_string())
            .or_insert_with(|| obj.get(key).cloned());
    }
    obj.insert("variations_country".into(), serde_json::json!("us"));
    let perm = match obj
        .get("variations_permanent_consistency_country")
        .and_then(|v| v.as_array())
    {
        Some(arr) if !arr.is_empty() => {
            let mut next = arr.clone();
            if let Some(last) = next.last_mut() {
                *last = serde_json::json!("us");
            }
            serde_json::Value::Array(next)
        }
        _ => serde_json::json!(["us"]),
    };
    obj.insert("variations_permanent_consistency_country".into(), perm);
    obj.insert(
        "variations_safe_seed_permanent_consistency_country".into(),
        serde_json::json!("us"),
    );
    obj.insert(
        "variations_safe_seed_session_consistency_country".into(),
        serde_json::json!("us"),
    );
    let mut profiles = 0usize;
    if let Some(cache) = obj
        .get_mut("profile")
        .and_then(|p| p.as_object_mut())
        .and_then(|p| p.get_mut("info_cache"))
        .and_then(|c| c.as_object_mut())
    {
        for (name, info) in cache.iter_mut() {
            if let Some(info_obj) = info.as_object_mut() {
                backup
                    .profile_eligibility
                    .entry(name.clone())
                    .or_insert_with(|| info_obj.get("is_glic_eligible").cloned());
                info_obj.insert("is_glic_eligible".into(), serde_json::json!(true));
                profiles += 1;
            }
        }
    }
    Ok(profiles)
}

pub fn restore_local_state_json(
    root: &mut serde_json::Value,
    backup: &ChromeGlicBackup,
) -> Result<(), String> {
    let obj = root
        .as_object_mut()
        .ok_or("Local State не является JSON-объектом")?;
    for (key, orig) in &backup.top_keys {
        match orig {
            Some(val) => {
                obj.insert(key.clone(), val.clone());
            }
            None => {
                obj.remove(key);
            }
        }
    }
    if let Some(cache) = obj
        .get_mut("profile")
        .and_then(|p| p.as_object_mut())
        .and_then(|p| p.get_mut("info_cache"))
        .and_then(|c| c.as_object_mut())
    {
        for (name, orig) in &backup.profile_eligibility {
            if let Some(info_obj) = cache.get_mut(name).and_then(|v| v.as_object_mut()) {
                match orig {
                    Some(val) => {
                        info_obj.insert("is_glic_eligible".into(), val.clone());
                    }
                    None => {
                        info_obj.remove("is_glic_eligible");
                    }
                }
            }
        }
    }
    Ok(())
}

fn write_chrome_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    crate::system::fs_utils::robust_write_file(path, &bytes)?;
    super::config::inherit_directory_owner(path)
}

fn load_chrome_backup() -> Result<Option<ChromeGlicBackup>, String> {
    match fs::read(chrome_glic_backup_path()) {
        Ok(bytes) => {
            let backup: ChromeGlicBackup =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(Some(backup))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn save_chrome_backup(backup: &ChromeGlicBackup) -> Result<(), String> {
    super::config::ensure_directory()?;
    let path = chrome_glic_backup_path();
    crate::system::fs_utils::robust_write_file(
        &path,
        &serde_json::to_vec_pretty(backup).map_err(|e| e.to_string())?,
    )?;
    super::config::inherit_directory_owner(&path)
}

pub fn unlock_chrome_glic() -> Result<usize, String> {
    if chrome_running() {
        return Err("Сначала полностью закройте Google Chrome (⌘Q)".into());
    }
    let state_path = chrome_local_state_path();
    if !state_path.is_file() {
        return Err("Профиль Google Chrome (Local State) не найден".into());
    }
    let bytes = fs::read(&state_path).map_err(|e| format!("Чтение Local State: {e}"))?;
    let mut root: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("Разбор Local State: {e}"))?;
    let mut backup = load_chrome_backup()?.unwrap_or_default();
    let profiles = patch_local_state_json(&mut root, &mut backup)?;
    save_chrome_backup(&backup)?;
    write_chrome_json(&state_path, &root)?;
    // Remove cached binary VariationsSeedV2 files so Chrome does not overwrite
    // "us" with a stale regional seed on startup; Chrome re-fetches a signed seed via PAC.
    let chrome_dir = chrome_user_data_dir();
    for seed_name in ["VariationsSeedV2", "VariationsSafeSeedV2"] {
        let seed = chrome_dir.join(seed_name);
        if seed.is_file() {
            let _ = fs::remove_file(seed);
        }
    }
    Ok(profiles)
}

fn clear_chrome_seed_cache() {
    let chrome_dir = chrome_user_data_dir();
    for seed_name in ["VariationsSeedV2", "VariationsSafeSeedV2"] {
        let seed = chrome_dir.join(seed_name);
        if seed.is_file() {
            let _ = fs::remove_file(seed);
        }
    }
}

/// Reset unbacked `Local State` country overrides so Chrome re-detects its natural
/// regional Variations seed on next startup.
pub fn reset_unbacked_local_state_json(root: &mut serde_json::Value) -> bool {
    let Some(obj) = root.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    for key in CHROME_COUNTRY_KEYS {
        if obj.remove(key).is_some() {
            changed = true;
        }
    }
    if let Some(cache) = obj
        .get_mut("profile")
        .and_then(|p| p.as_object_mut())
        .and_then(|p| p.get_mut("info_cache"))
        .and_then(|c| c.as_object_mut())
    {
        for info in cache.values_mut() {
            if let Some(info_obj) = info.as_object_mut() {
                if info_obj.remove("is_glic_eligible").is_some() {
                    changed = true;
                }
            }
        }
    }
    changed
}

pub fn restore_chrome_glic() -> Result<(), String> {
    let Some(backup) = load_chrome_backup()? else {
        return Ok(());
    };
    let state_path = chrome_local_state_path();
    if state_path.is_file() {
        if chrome_running() {
            quit_chrome()?;
        }
        let bytes = fs::read(&state_path).map_err(|e| e.to_string())?;
        if let Ok(mut root) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            restore_local_state_json(&mut root, &backup)?;
            write_chrome_json(&state_path, &root)?;
            clear_chrome_seed_cache();
        }
    }
    match fs::remove_file(chrome_glic_backup_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn reset_third_party_chrome_glic() -> Result<bool, String> {
    if chrome_glic_backup_path().is_file() {
        return Ok(false);
    }
    let state_path = chrome_local_state_path();
    if !state_path.is_file() || chrome_glic_needs_unlock() {
        return Ok(false);
    }
    if chrome_running() {
        quit_chrome()?;
    }
    let bytes = fs::read(&state_path).map_err(|e| e.to_string())?;
    let mut root: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if !reset_unbacked_local_state_json(&mut root) {
        return Ok(false);
    }
    write_chrome_json(&state_path, &root)?;
    clear_chrome_seed_cache();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enabled_physical_and_tunnel_services_and_skips_bridges_and_disabled() {
        let sample = "\
An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(3) Tunnel A
(Hardware Port: com.example.packet-tunnel.a, Device: )

(4) Tunnel B
(Hardware Port: org.example.packet-tunnel.b, Device: )
";
        assert_eq!(
            parse_pac_services(sample),
            vec![
                "Wi-Fi".to_string(),
                "Tunnel A".to_string(),
                "Tunnel B".to_string()
            ]
        );
    }

    #[test]
    fn parses_autoproxy_and_recognizes_managed_loopback_pac_only() {
        assert_eq!(
            parse_autoproxy("URL: (null)\nEnabled: No\n"),
            (None, false)
        );
        assert_eq!(
            parse_autoproxy("URL: http://127.0.0.1:53129/proxy.pac\nEnabled: Yes\n"),
            (Some("http://127.0.0.1:53129/proxy.pac".into()), true)
        );
        assert!(is_managed_pac_url("http://127.0.0.1:53129/proxy.pac"));
        assert!(!is_managed_pac_url("http://corp.example/proxy.pac"));
        assert!(!is_managed_pac_url("http://127.0.0.1:0/proxy.pac"));
    }

    #[test]
    fn patches_and_surgically_restores_chrome_local_state_without_losing_unrelated_fields() {
        let mut state = serde_json::json!({
            "variations_country": "tr",
            "variations_permanent_consistency_country": ["157.0.8103.52", "tr"],
            "variations_safe_seed_permanent_consistency_country": "ru",
            "variations_safe_seed_session_consistency_country": "ru",
            "browser": { "custom_tab": 42 },
            "profile": {
                "info_cache": {
                    "Default": { "name": "Work", "is_glic_eligible": false },
                    "Profile 1": { "name": "Personal", "is_glic_eligible": true }
                }
            }
        });
        let original = state.clone();
        assert!(state_needs_glic_unlock(&state));
        let mut backup = ChromeGlicBackup::default();
        assert_eq!(patch_local_state_json(&mut state, &mut backup).unwrap(), 2);
        assert!(!state_needs_glic_unlock(&state));
        assert_eq!(state["variations_country"], "us");
        assert_eq!(
            state["variations_permanent_consistency_country"],
            serde_json::json!(["157.0.8103.52", "us"])
        );
        assert_eq!(
            state["profile"]["info_cache"]["Default"]["is_glic_eligible"],
            true
        );
        // Simulate Chrome adding a new setting afterwards; surgical restore must keep it.
        state["browser"]["new_pref"] = serde_json::json!("preserved");
        restore_local_state_json(&mut state, &backup).unwrap();
        assert_eq!(state["variations_country"], original["variations_country"]);
        assert_eq!(
            state["variations_permanent_consistency_country"],
            original["variations_permanent_consistency_country"]
        );
        assert_eq!(
            state["profile"]["info_cache"]["Default"]["is_glic_eligible"],
            false
        );
        assert_eq!(state["browser"]["new_pref"], "preserved");
    }

    #[test]
    fn strips_google_entries_from_proxy_bypass_domains_and_preserves_custom_ones() {
        let polluted = "*.local\n169.254/16\n*.googleapis.com\ngemini.google.com\ncorp.internal\n";
        assert_eq!(
            filter_google_proxy_bypass_domains(polluted),
            Some(vec![
                "*.local".to_string(),
                "169.254/16".to_string(),
                "corp.internal".to_string()
            ])
        );
        assert_eq!(
            filter_google_proxy_bypass_domains("*.local\n169.254/16\ncorp.internal\n"),
            None
        );
    }

    #[test]
    fn resets_unbacked_third_party_local_state_while_preserving_browser_prefs() {
        let mut state = serde_json::json!({
            "variations_country": "us",
            "variations_permanent_consistency_country": ["157.0.0.1", "us"],
            "browser": { "tab": 7 },
            "profile": { "info_cache": { "Default": { "name": "Main", "is_glic_eligible": true } } }
        });
        assert!(reset_unbacked_local_state_json(&mut state));
        assert!(state.get("variations_country").is_none());
        assert!(state["profile"]["info_cache"]["Default"]
            .get("is_glic_eligible")
            .is_none());
        assert_eq!(state["browser"]["tab"], 7);
    }
}
