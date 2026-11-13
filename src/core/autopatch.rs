//! Automatic re-patching of Antigravity IDE & CLI after Electron / ShipIt updates.
//!
//! Whenever Antigravity updates itself, its executables return to `Stock`.
//! The per-user background watcher detects the new stock files, archives their
//! exact clean bytes in `.ag-backups/<sha256>.bin` via `patcher::patch_target`,
//! re-applies the regional & `AG_LS_PROXY` patches, and clears V8 bytecode caches.
use crate::core::{
    detector::{self, TargetKind},
    patcher::{self, BinaryState, PatchOutcome},
    v8_cache,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const AUTOPATCH_FLAG: &str = "--auto-patch";
pub const AGENT_LABEL: &str = "com.antigravity.bypass.autopatch";
#[cfg(windows)]
const TASK_NAME: &str = "AntigravityBypassAutoPatch";

fn lock_file() -> Option<fs::File> {
    let _ = crate::net::config::ensure_directory();
    let path = crate::net::config::directory().join("autopatch.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .ok()?;
    file.try_lock().ok()?;
    Some(file)
}

#[cfg(target_os = "macos")]
fn updater_busy() -> bool {
    crate::system::command::output("ps", ["-axo", "comm="])
        .ok()
        .is_some_and(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|line| line.trim().ends_with("/ShipIt") || line.trim() == "ShipIt")
        })
}

#[cfg(not(target_os = "macos"))]
fn updater_busy() -> bool {
    false
}

/// Run a single idempotent check-and-patch pass across discovered Antigravity installations.
/// Never kills running IDE processes: if files are currently open, waits for the next pass.
pub fn run_once() -> Result<usize, String> {
    let Some(_guard) = lock_file() else {
        return Ok(0);
    };
    if let Ok(cfg) = crate::net::proxy_config::load() {
        if !cfg.products.autopatch || !cfg.products.antigravity {
            return Ok(0);
        }
    }
    if updater_busy() {
        return Ok(0);
    }

    let _ = detector::recover_installations();
    let installs = detector::find_installations();
    let mut changed = 0usize;
    for root in &installs {
        for target in detector::find_targets_in_path(root) {
            let state = patcher::check_target_state(&target);
            let env_missing = matches!(target.kind, TargetKind::LanguageServer | TargetKind::AgyCli)
                && state == BinaryState::Patched
                && !patcher::proxy_env_ready(&target);
            if !matches!(state, BinaryState::Stock | BinaryState::PartiallyPatched) && !env_missing
            {
                continue;
            }
            match patcher::patch_target(&target) {
                Ok(PatchOutcome::Changed(_)) => {
                    changed += 1;
                    crate::net::config::log_event(&format!(
                        "Автопатч: обновлён патч для {}",
                        target.name
                    ));
                }
                Ok(_) => {}
                Err(error) => {
                    crate::net::config::log_event(&format!(
                        "Автопатч отложен ({}): {error}",
                        target.name
                    ));
                }
            }
        }
    }
    if changed > 0 {
        let _ = v8_cache::clear_ide_v8_caches();
        #[cfg(target_os = "macos")]
        if let Some(port) = crate::net::local_proxy::saved_port() {
            let _ = crate::net::proxy_session::apply(&crate::net::local_proxy::url_at(port));
        }
    }
    Ok(changed)
}

#[cfg(target_os = "macos")]
fn agent_path() -> PathBuf {
    crate::system::env::expand_env_vars("~/Library/LaunchAgents")
        .join(format!("{AGENT_LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn agent_plist(executable: &Path) -> String {
    use crate::net::local_proxy::xml_escape;
    let log = crate::net::config::directory().join("autopatch.log");
    let user_app = crate::system::env::expand_env_vars("~/Applications/Antigravity.app/Contents");
    let watch_paths = [
        PathBuf::from("/Applications/Antigravity.app/Contents/Info.plist"),
        PathBuf::from("/Applications/Antigravity.app/Contents/Resources/bin"),
        PathBuf::from("/Applications/Antigravity.app/Contents/Resources/app.asar"),
        user_app.join("Info.plist"),
    ];
    let mut watch_xml = String::new();
    for path in &watch_paths {
        watch_xml.push_str(&format!(
            "<string>{}</string>",
            xml_escape(&path.to_string_lossy())
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{AGENT_LABEL}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>{AUTOPATCH_FLAG}</string></array>\n<key>RunAtLoad</key><true/>\n<key>StartInterval</key><integer>120</integer>\n<key>ThrottleInterval</key><integer>15</integer>\n<key>WatchPaths</key><array>{watch_xml}</array>\n<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
        xml_escape(&executable.to_string_lossy()),
        xml_escape(&log.to_string_lossy()),
        xml_escape(&log.to_string_lossy())
    )
}

pub fn is_enabled() -> bool {
    #[cfg(target_os = "macos")]
    {
        agent_path().is_file()
    }
    #[cfg(windows)]
    {
        crate::system::command::output("schtasks", ["/Query", "/TN", TASK_NAME])
            .is_ok_and(|o| o.status.success())
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        false
    }
}

pub fn enable() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let exe = crate::net::local_proxy::ensure_installed_exe()?;
        let plist = agent_path();
        if let Some(parent) = plist.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let before = match fs::read(&plist) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        let after = agent_plist(&exe).into_bytes();
        crate::system::journal::apply(&plist, before.as_deref(), &after, "autopatch-agent-v1")?;
        crate::net::config::inherit_directory_owner(&plist)?;
        let uid = crate::net::local_proxy::user_id()?;
        let _ = crate::net::local_proxy::launchctl([
            "bootout".to_string(),
            format!("gui/{uid}/{AGENT_LABEL}"),
        ]);
        let out = crate::net::local_proxy::launchctl([
            "bootstrap".to_string(),
            format!("gui/{uid}"),
            plist.to_string_lossy().into_owned(),
        ])?;
        if !out.status.success() {
            let loaded = crate::net::local_proxy::launchctl([
                "print".to_string(),
                format!("gui/{uid}/{AGENT_LABEL}"),
            ])
            .is_ok_and(|o| o.status.success());
            if !loaded {
                return Err(format!(
                    "Не удалось включить автопатч: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let exe = crate::net::local_proxy::ensure_installed_exe()?;
        let action = format!("\"{}\" {}", exe.display(), AUTOPATCH_FLAG);
        let out = crate::system::command::output(
            "schtasks",
            [
                "/Create",
                "/TN",
                TASK_NAME,
                "/SC",
                "MINUTE",
                "/MO",
                "2",
                "/TR",
                &action,
                "/F",
            ],
        )
        .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "Не удалось создать задачу автопатча: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Err("Автопатч поддерживается на macOS и Windows".into())
    }
}

pub fn disable() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let plist = agent_path();
        if let Ok(uid) = crate::net::local_proxy::user_id() {
            let _ = crate::net::local_proxy::launchctl([
                "bootout".to_string(),
                format!("gui/{uid}/{AGENT_LABEL}"),
            ]);
        }
        if plist.exists() {
            if crate::system::journal::has_record(&plist) {
                crate::system::journal::restore(&plist)?;
            } else {
                fs::remove_file(&plist).map_err(|e| e.to_string())?;
            }
        }
        let exe = crate::net::local_proxy::installed_exe();
        if !crate::net::local_proxy::listener_alive()
            && std::env::current_exe().ok().as_ref() != Some(&exe)
            && exe.exists()
        {
            let _ = fs::remove_file(exe);
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if is_enabled() {
            let _ = crate::system::command::output("schtasks", ["/Delete", "/TN", TASK_NAME, "/F"]);
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn autopatch_plist_embeds_flag_and_watch_paths() {
        let xml = agent_plist(Path::new("/Users/test/ag_proxy"));
        assert!(xml.contains(AGENT_LABEL));
        assert!(xml.contains(AUTOPATCH_FLAG));
        assert!(xml.contains("<key>WatchPaths</key>"));
        assert!(xml.contains("/Applications/Antigravity.app/Contents/Info.plist"));
    }
}
