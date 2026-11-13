//! User-owned state directory, event log, and language-server log settings.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub watch_region_errors: bool,
    pub log_roots: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            watch_region_errors: true,
            log_roots: user_log_roots(),
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn user_root() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::system::env::expand_env_vars("%USERPROFILE%"));
    #[cfg(not(windows))]
    let base = crate::system::env::expand_env_vars("~").join(if cfg!(target_os = "macos") {
        "Library/Application Support"
    } else {
        ".config"
    });
    base.join("AntigravityBypass").join("network")
}

pub fn user_log_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = Some(
        crate::system::env::expand_env_vars("~").join(if cfg!(target_os = "macos") {
            "Library/Application Support"
        } else {
            ".config"
        }),
    );
    base.into_iter()
        .flat_map(|base| {
            ["Antigravity", "Antigravity IDE", "Google Antigravity"]
                .map(|product| base.join(product).join("logs"))
        })
        .collect()
}

pub fn directory() -> PathBuf {
    user_root()
}

pub fn path() -> PathBuf {
    directory().join("network.json")
}

pub fn ensure_directory() -> Result<(), String> {
    let dir = directory();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        // An elevated launch must not leave the user's network state owned by root.
        if let Some(owner) = dir
            .ancestors()
            .skip(1)
            .filter_map(|p| fs::metadata(p).ok())
            .find(|m| m.uid() != 0)
        {
            for path in [dir.parent().unwrap(), &dir] {
                let file = fs::File::open(path).map_err(|e| e.to_string())?;
                let meta = file.metadata().map_err(|e| e.to_string())?;
                if (meta.uid(), meta.gid()) != (owner.uid(), owner.gid())
                    && unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0
                {
                    return Err(std::io::Error::last_os_error().to_string());
                }
            }
        }
    }
    Ok(())
}

pub fn inherit_directory_owner(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let owner = fs::metadata(path.parent().ok_or("Нет каталога состояния")?)
            .map_err(|e| e.to_string())?;
        let file = fs::File::open(path).map_err(|e| e.to_string())?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if (meta.uid(), meta.gid()) != (owner.uid(), owner.gid())
            && unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn validate(config: &Config) -> Result<(), String> {
    if config.log_roots.len() > 16 {
        return Err("Слишком много каталогов журналов в network.json".into());
    }
    if config.log_roots.iter().any(|p| !p.is_absolute()) {
        return Err("Каталоги журналов должны быть абсолютными".into());
    }
    Ok(())
}

pub fn load() -> Result<Config, String> {
    let config: Config = match fs::read(path()) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("network.json: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(e) => return Err(format!("network.json: {e}")),
    };
    validate(&config)?;
    Ok(config)
}

pub fn log_event(message: &str) {
    if ensure_directory().is_err() {
        return;
    }
    let current = directory().join("network-events.log");
    if fs::metadata(&current)
        .ok()
        .is_some_and(|meta| meta.len() > 512 * 1024)
    {
        let previous = directory().join("network-events.previous.log");
        let _ = fs::rename(&current, previous);
    }
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&current)
    {
        let clean = message.replace(['\r', '\n'], " ");
        let _ = writeln!(file, "[{}] {clean}", now_ms());
        let _ = inherit_directory_owner(&current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_network_json_with_old_dns_fields_loads_cleanly() {
        let legacy: Config = serde_json::from_value(serde_json::json!({
            "doh": [{"name": "legacy", "url": "https://example.test/dns-query"}],
            "provider_order": ["legacy"],
            "watch_region_errors": false
        }))
        .unwrap();
        assert!(!legacy.watch_region_errors);
        assert!(validate(&legacy).is_ok());
    }

    #[test]
    fn config_rejects_relative_log_roots() {
        let mut c = Config::default();
        assert!(validate(&c).is_ok());
        c.log_roots = vec!["relative".into()];
        assert!(validate(&c).is_err());
    }
}
