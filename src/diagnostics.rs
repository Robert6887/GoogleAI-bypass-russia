//! Local, opt-in support reports. Export an allowlist, never raw configuration, proxy credentials, or logs.
mod platform;

use crate::{
    core::{autopatch, detector, patcher},
    net, system,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

const MAX_TEXT: u64 = 1024 * 1024;

fn unavailable(reason: &str) -> Value {
    json!({"status": reason})
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    let file = File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        _ => "read_failed",
    })?;
    if !file.metadata().map_err(|_| "read_failed")?.is_file() {
        return Err("not_a_file");
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| "read_failed")?;
    if data.len() as u64 > limit {
        return Err("size_limit");
    }
    Ok(data)
}

fn error_stage(error: &str) -> &'static str {
    if error.starts_with("DNS:") {
        "dns"
    } else if error.starts_with("TCP:") {
        "tcp"
    } else if error.starts_with("TLS") {
        "tls_or_certificate"
    } else if error.starts_with("HTTP") {
        "http"
    } else {
        "transport"
    }
}

fn connection(report: net::health::ConnReport) -> Value {
    let resolved: Vec<IpAddr> = report
        .resolved
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let connected = report.connected.and_then(|s| s.parse::<SocketAddr>().ok());
    json!({
        "host": report.host,
        "resolved": resolved,
        "connected": connected,
        "latency_ms": report.latency_ms,
        "used_ipv6": report.used_ipv6,
        "looks_like_google": report.looks_like_google,
        "http_status": report.http_status,
        "status": if report.error.is_some() { "failed" } else { "transport_available" },
        "error_stage": report.error.as_deref().map(error_stage)
    })
}

fn bounded_jobs(jobs: Vec<(String, Box<dyn FnOnce() -> Value + Send>)>, budget: Duration) -> Value {
    let (tx, rx) = mpsc::channel();
    let mut results = serde_json::Map::new();
    let count = jobs.len();
    for (name, job) in jobs {
        results.insert(name.clone(), unavailable("timeout"));
        let tx = tx.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job))
                .unwrap_or_else(|_| unavailable("collector_failed"));
            let _ = tx.send((name, result));
        });
    }
    drop(tx);
    let deadline = Instant::now() + budget;
    for _ in 0..count {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match rx.recv_timeout(left) {
            Ok((name, value)) => {
                results.insert(name, value);
            }
            Err(_) => break,
        }
    }
    Value::Object(results)
}

fn config_summary(config: &net::config::Config) -> Value {
    json!({
        "status": "ok",
        "mode": "local-gateway",
        "watch_region_errors": config.watch_region_errors,
        "log_root_count": config.log_roots.len(),
        "log_reading": "bounded recent language-server logs"
    })
}

fn recent_events(path: &Path) -> Value {
    let mut file = match File::open(path) {
        Ok(v) => v,
        Err(_) => return unavailable("unavailable"),
    };
    let size = match file.metadata() {
        Ok(m) if m.is_file() => m.len(),
        _ => return unavailable("read_failed"),
    };
    let offset = size.saturating_sub(64 * 1024);
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return unavailable("read_failed");
    }
    let mut bytes = Vec::new();
    if file.take(64 * 1024).read_to_end(&mut bytes).is_err() {
        return unavailable("read_failed");
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut events: Vec<_> = text
        .lines()
        .skip(usize::from(offset > 0))
        .filter_map(event_summary)
        .collect();
    events.drain(..events.len().saturating_sub(100));
    json!({"status": "ok", "events": events, "scope": "recognized events only"})
}

fn event_summary(line: &str) -> Option<Value> {
    let (time, message) = line.strip_prefix('[')?.split_once("] ")?;
    let timestamp = time.parse::<u64>().ok()?;
    let kind = if message.starts_with("Автопатч: обновлён патч") {
        "autopatch_applied"
    } else if message.starts_with("Автопатч отложен") {
        "autopatch_deferred"
    } else if message.starts_with("Региональный отказ: ") {
        "region_refusal"
    } else {
        return None;
    };
    Some(json!({"timestamp_ms": timestamp, "kind": kind}))
}

fn version_text(value: &str) -> Option<String> {
    let valid =
        regex::Regex::new(r"^[0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?(?:[-+][0-9A-Za-z.-]{1,32})?$")
            .unwrap();
    valid.is_match(value).then(|| value.to_owned())
}

fn installations() -> Value {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for root in detector::find_installations().into_iter().take(64) {
        let mut versions = BTreeSet::new();
        for relative in [
            "package.json",
            "resources/app/package.json",
            "Contents/Resources/app/package.json",
        ] {
            if let Ok(bytes) = read_limited(&root.join(relative), MAX_TEXT) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(v) = value["version"].as_str().and_then(version_text) {
                        versions.insert(v);
                    }
                }
            }
        }
        let mut targets = Vec::new();
        for target in detector::find_targets_in_path(&root).into_iter().take(32) {
            if !seen.insert(target.path.clone()) {
                continue;
            }
            let size = fs::metadata(&target.path).ok().map(|m| m.len());
            let inspected = size.is_some_and(|n| n <= 256 * 1024 * 1024);
            let state = if inspected {
                format!("{:?}", patcher::check_target_state(&target))
            } else {
                "not_inspected".into()
            };
            if inspected && target.kind == detector::TargetKind::IdeAsar {
                if let Some(v) = crate::core::asar::read_asar_package_version(&target.path)
                    .as_deref()
                    .and_then(version_text)
                {
                    versions.insert(v);
                }
            }
            let proxy_env = matches!(
                target.kind,
                detector::TargetKind::LanguageServer | detector::TargetKind::AgyCli
            )
            .then(|| inspected && patcher::proxy_env_ready(&target));
            targets.push(json!({
                "component": format!("{:?}", target.kind),
                "size_bytes": size,
                "architecture": binary_architecture(&target.path),
                "patch_state": state,
                "proxy_env_ready": proxy_env
            }));
        }
        if !targets.is_empty() || !versions.is_empty() {
            result.push(json!({
                "installation": result.len() + 1,
                "versions": versions,
                "targets": targets
            }));
        }
    }
    json!({
        "status": "ok",
        "installations": result,
        "paths": "omitted",
        "discovery": "standard locations and PATH"
    })
}

fn binary_architecture(path: &Path) -> Option<&'static str> {
    let mut file = File::open(path).ok()?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header).ok()?;
    let machine = if header.starts_with(b"MZ") {
        let offset = u32::from_le_bytes(header[60..64].try_into().ok()?);
        if offset > 1024 * 1024 {
            return None;
        }
        file.seek(SeekFrom::Start(offset as u64)).ok()?;
        let mut pe = [0u8; 6];
        file.read_exact(&mut pe).ok()?;
        if !pe.starts_with(b"PE\0\0") {
            return None;
        }
        match u16::from_le_bytes([pe[4], pe[5]]) {
            0x8664 => 7,
            0xaa64 => 12,
            _ => return None,
        }
    } else if header.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        u32::from_le_bytes(header[4..8].try_into().ok()?) & 0x00ff_ffff
    } else if header.starts_with(&[0xfe, 0xed, 0xfa, 0xcf]) {
        u32::from_be_bytes(header[4..8].try_into().ok()?) & 0x00ff_ffff
    } else if matches!(
        header[..4],
        [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    ) {
        return Some("universal");
    } else {
        return None;
    };
    match machine {
        7 => Some("x86_64"),
        12 => Some("aarch64"),
        _ => None,
    }
}

fn fingerprint(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut hash = Sha256::new();
    let mut remaining = 64 * 1024 * 1024usize;
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            return Some(format!("{:x}", hash.finalize()));
        }
        remaining = remaining.checked_sub(n)?;
        hash.update(&buffer[..n]);
    }
}

fn gateway_summary() -> Value {
    let installed = fingerprint(&net::local_proxy::installed_exe());
    let current = std::env::current_exe().ok().and_then(|p| fingerprint(&p));
    let same = installed
        .as_ref()
        .zip(current.as_ref())
        .map(|(a, b)| a == b);
    json!({
        "status": "ok",
        "listener_alive": net::local_proxy::listener_alive(),
        "local_port": net::local_proxy::saved_port(),
        "autopatch_enabled": autopatch::is_enabled(),
        "installed_binary_sha256": installed,
        "current_binary_sha256": current,
        "installed_matches_current": same,
    })
}

fn legacy_conflicts() -> Value {
    json!({
        "status": "ok",
        "hosts_has_gate_overrides": net::hosts::has_gate_overrides(),
        "resolver_has_gate_files": net::resolver_has_gate_files(),
        "legacy_daemon_present": net::legacy_daemon_present(),
        "proxy_bypass_blocks_google": net::gemini_apps::proxy_bypass_blocks_google(),
        "system_pac_active": net::gemini_apps::pac_active(),
        "chrome_glic_unlocked": net::gemini_apps::chrome_installed()
            .then(|| !net::gemini_apps::chrome_glic_needs_unlock()),
    })
}

pub fn collect() -> Value {
    let started = net::config::now_ms();
    let route_ips: Vec<Ipv4Addr> = Vec::new();
    let mut jobs: Vec<(String, Box<dyn FnOnce() -> Value + Send>)> = vec![
        ("installations".into(), Box::new(installations)),
        ("gateway".into(), Box::new(gateway_summary)),
        ("legacy_conflicts".into(), Box::new(legacy_conflicts)),
        (
            "autopatch".into(),
            Box::new(|| json!({"status": "ok", "enabled": autopatch::is_enabled()})),
        ),
        (
            "model_observation".into(),
            Box::new(|| serde_json::to_value(crate::model_status::snapshot()).unwrap()),
        ),
        (
            "system_network".into(),
            Box::new(move || platform::network(&route_ips)),
        ),
        ("os_version".into(), Box::new(platform::os_version)),
        (
            "configuration".into(),
            Box::new(|| match net::config::load() {
                Ok(config) => config_summary(&config),
                Err(_) => unavailable("unreadable_or_invalid"),
            }),
        ),
    ];
    for host in net::health::AGENT_HOSTS {
        jobs.push((
            format!("connection:{host}"),
            Box::new(move || connection(net::health::probe_host(host))),
        ));
    }
    let checks = bounded_jobs(jobs, Duration::from_secs(20));
    json!({
        "schema_version": 1,
        "bypass_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "started_ms": started,
        "finished_ms": net::config::now_ms(),
        "model_access": "not_tested; verify with proxy checker or a real request in Antigravity",
        "privacy": "Local report; no account data, prompts, proxy passwords, raw logs, or user paths.",
        "recent_events": recent_events(&net::config::directory().join("network-events.log")),
        "previous_events": recent_events(&net::config::directory().join("network-events.previous.log")),
        "proxy": net::local_proxy::summary(),
        "checks": checks
    })
}

fn write_report(directory: &Path, report: &Value) -> Result<PathBuf, String> {
    let mut file = tempfile::Builder::new()
        .prefix("antigravity-diagnostics-")
        .suffix(".json")
        .tempfile_in(directory)
        .map_err(|e| format!("Не создать отчёт: {e}"))?;
    serde_json::to_writer_pretty(&mut file, report).map_err(|e| e.to_string())?;
    file.write_all(b"\n")
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        net::config::inherit_directory_owner(file.path())?;
    }
    let (_, path) = file.keep().map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn save(directory: Option<&Path>) -> Result<PathBuf, String> {
    let directory = if let Some(path) = directory {
        path.to_path_buf()
    } else {
        net::config::ensure_directory()?;
        net::config::directory()
    };
    if !directory.is_dir() {
        return Err("Каталог для отчёта не существует".into());
    }
    let directory = fs::canonicalize(directory).map_err(|e| e.to_string())?;
    write_report(&directory, &collect())
}

pub fn build_ai_prompt(report: &Value) -> String {
    let cfg = net::proxy_config::load().unwrap_or_default();
    let live_checks: Vec<Value> =
        net::local_proxy::check_all_products(cfg.upstream.as_ref(), cfg.vpn_policy)
            .into_iter()
            .map(|c| {
                json!({
                    "service": c.name,
                    "ok": c.ok,
                    "geo_blocked": c.geo_blocked,
                })
            })
            .collect();
    let payload = json!({
        "live_google_endpoints": live_checks,
        "diagnostics": report,
    });
    let pretty = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into());
    format!(
        "Помоги мне починить работу Google Antigravity / Gemini на моём компьютере.\n\
Я НЕ программист — пожалуйста, объясни простым человеческим языком на русском, что именно сейчас сломано и какой один пункт меню мне нажать.\n\n\
Контекст архитектуры утилиты GoogleAI-bypass-russia (v{}):\n\
1. Antigravity IDE/CLI: бинарники должны иметь `patch_state: \"Patched\"` и `proxy_env_ready: true` (`AG_LS_PROXY`).\n\
2. Локальный шлюз (`gateway.listener_alive: true`): принимает трафик на `127.0.0.1:<port>` и отправляет в зарубежный SOCKS5/HTTP прокси пользователя (`proxy.upstream_configured: true`).\n\
3. Gemini Desktop и Gemini Web: работают через системный PAC (`legacy_conflicts.system_pac_active: true`). Если `hosts_has_gate_overrides`, `resolver_has_gate_files`, `legacy_daemon_present` или `proxy_bypass_blocks_google` равны `true`, старый сторонний обходчик мешает трафику.\n\
4. Кнопка «Спросить Gemini» в Chrome: требует `chrome_glic_unlocked: true` (при закрытом Chrome) и личного аккаунта `@gmail.com`.\n\
5. Как запустить меню утилиты одной командой в Терминале macOS:\n\
   `curl -fsSL https://github.com/Robert6887/GoogleAI-bypass-russia/releases/latest/download/unlock_and_restore.sh | bash`\n\
   Пункты меню: `[1]` Настроить разблокировку и очистить конфликты, `[2]` Добавить/сменить прокси или переключить маршрут VPN, `[3]` Чекер прокси, `[4]` Полный откат к заводским настройкам.\n\n\
Обезличенный JSON-отчёт диагностики (пароли, IP прокси и личные пути удалены):\n\
```json\n\
{pretty}\n\
```\n",
        env!("CARGO_PKG_VERSION")
    )
}

pub fn copy_to_clipboard(text: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};
        let mut cmd = if unsafe { libc::geteuid() } == 0 {
            if let Ok(uid) = net::local_proxy::user_id() {
                let mut c = Command::new("/bin/launchctl");
                c.args(["asuser", &uid.to_string(), "/usr/bin/pbcopy"]);
                c
            } else {
                Command::new("/usr/bin/pbcopy")
            }
        } else {
            Command::new("/usr/bin/pbcopy")
        };
        if let Ok(mut child) = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            return child.wait().is_ok_and(|s| s.success());
        }
        false
    }
    #[cfg(target_os = "windows")]
    {
        use std::process::{Command, Stdio};
        if let Ok(mut child) = Command::new("clip.exe")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            return child.wait().is_ok_and(|s| s.success());
        }
        false
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = text;
        false
    }
}

pub fn save_ai_prompt(report: &Value) -> Result<(PathBuf, bool), String> {
    net::config::ensure_directory()?;
    let prompt_text = build_ai_prompt(report);
    let copied = copy_to_clipboard(&prompt_text);
    let path = net::config::directory().join("antigravity-ai-prompt.txt");
    system::fs_utils::robust_write_file(&path, prompt_text.as_bytes())?;
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        let _ = net::config::inherit_directory_owner(&path);
    }
    Ok((path, copied))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_architecture_is_read_without_executing_the_application() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("application");
        let mut data = vec![0u8; 128];
        data[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        data[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        fs::write(&file, &data).unwrap();
        assert_eq!(binary_architecture(&file), Some("aarch64"));
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&64u32.to_le_bytes());
        data[64..70].copy_from_slice(b"PE\0\0\x64\x86");
        fs::write(&file, &data).unwrap();
        assert_eq!(binary_architecture(&file), Some("x86_64"));
        fs::write(&file, b"#!/bin/sh\nSECRET").unwrap();
        assert_eq!(binary_architecture(&file), None);
    }

    #[test]
    fn report_omits_secrets_from_configuration_errors_and_logs() {
        let mut config = net::config::Config::default();
        config.log_roots = vec![PathBuf::from("/SECRET_USER/logs")];
        let report = json!({
            "config": config_summary(&config),
            "error": connection(net::health::ConnReport {
                host: net::health::AGENT_HOSTS[0].into(),
                error: Some("TLS: SECRET_TOKEN /SECRET_USER".into()),
                ..Default::default()
            }),
            "event": event_summary("[123] Региональный отказ: SECRET_TOKEN")
        });
        assert!(!report.to_string().contains("SECRET"));
        assert!(event_summary("[123] Proxy credentials: SECRET_TOKEN").is_none());
        assert_eq!(report["error"]["error_stage"], "tls_or_certificate");
        assert!(version_text("1.2.3\nSECRET").is_none());
        assert!(version_text("1.2.3").is_some());
    }

    #[test]
    fn stalled_check_preserves_completed_sections() {
        let (release, blocked) = mpsc::channel::<()>();
        let result = bounded_jobs(
            vec![
                ("fast".into(), Box::new(|| json!(42))),
                (
                    "stalled".into(),
                    Box::new(move || {
                        let _ = blocked.recv();
                        json!(1)
                    }),
                ),
            ],
            Duration::from_secs(2),
        );
        drop(release);
        assert_eq!(result["fast"], 42);
        assert_eq!(result["stalled"]["status"], "timeout");
    }
}
