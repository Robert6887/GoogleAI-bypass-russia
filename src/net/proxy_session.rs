//! Own AG_LS_PROXY and isolated gRPC proxy variables (for native Gemini.app)
//! in the macOS GUI session and restore their exact prior values.
//! HTTPS_PROXY and global curl/git/npm proxy variables remain untouched.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf};

const ENV_NAME: &str = "AG_LS_PROXY";
const GRPC_PROXY_ENV: &str = "grpc_proxy";
const NO_GRPC_PROXY_ENV: &str = "no_grpc_proxy";
const GRPC_DNS_ENV: &str = "GRPC_DNS_RESOLVER";
const NO_GRPC_PROXY_VAL: &str = "localhost,127.0.0.1,::1";
const GRPC_DNS_VAL: &str = "native";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Backup {
    schema: u32,
    original: Option<String>,
    modified: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    extra_originals: BTreeMap<String, Option<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    extra_modified: BTreeMap<String, String>,
}

fn backup_path() -> PathBuf {
    super::config::directory().join("proxy-session.json")
}

fn is_local_url(value: &str) -> bool {
    let Some(port) = value
        .strip_prefix("http://127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
    else {
        return false;
    };
    port != 0
}

fn validate_backup(backup: &Backup) -> Result<(), String> {
    if backup.schema != 1 || !is_local_url(&backup.modified) {
        return Err("Повреждена копия окружения локального прокси".into());
    }
    Ok(())
}

fn load() -> Result<Option<Backup>, String> {
    match fs::read(backup_path()) {
        Ok(bytes) => {
            let backup: Backup = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            validate_backup(&backup)?;
            Ok(Some(backup))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn user_id() -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let uid = fs::metadata(crate::system::env::expand_env_vars("~"))
        .map_err(|e| e.to_string())?
        .uid();
    if uid == 0 {
        return Err("Не найден пользователь GUI для AG_LS_PROXY".into());
    }
    Ok(uid.to_string())
}

#[cfg(target_os = "macos")]
fn command(args: &[&str]) -> Result<std::process::Output, String> {
    let uid = user_id()?;
    if unsafe { libc::geteuid() } != 0 {
        return crate::system::command::output("launchctl", args).map_err(|e| e.to_string());
    }
    let mut arguments = vec!["asuser", &uid, "/bin/launchctl"];
    arguments.extend_from_slice(args);
    crate::system::command::output("launchctl", arguments).map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
fn read_var(name: &str) -> Result<Option<String>, String> {
    let output = command(&["getenv", name])?;
    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Ok((!value.is_empty()).then_some(value));
    }
    if output.status.code() == Some(1) && output.stdout.is_empty() {
        return Ok(None);
    }
    Err(format!("Не удалось прочитать {name} из GUI-сессии"))
}

#[cfg(not(target_os = "macos"))]
fn read_var(name: &str) -> Result<Option<String>, String> {
    Err(format!("{name} в GUI-сессии поддерживается только на macOS"))
}

fn read() -> Result<Option<String>, String> {
    read_var(ENV_NAME)
}

#[cfg(target_os = "macos")]
fn write_var(name: &str, value: Option<&str>) -> Result<(), String> {
    let output = match value {
        Some(value) => command(&["setenv", name, value]),
        None => command(&["unsetenv", name]),
    }?;
    if !output.status.success() || read_var(name)?.as_deref() != value {
        return Err(format!("Не удалось проверить запись {name}"));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn write_var(name: &str, _value: Option<&str>) -> Result<(), String> {
    Err(format!("{name} в GUI-сессии поддерживается только на macOS"))
}

fn next_backup(
    existing: Option<Backup>,
    current: Option<String>,
    url: &str,
) -> Result<Backup, String> {
    if !is_local_url(url) {
        return Err("AG_LS_PROXY должен указывать на локальный HTTP-прокси".into());
    }
    if let Some(mut backup) = existing {
        validate_backup(&backup)?;
        if current.as_ref().is_some_and(|value| {
            Some(value) != backup.original.as_ref()
                && value != &backup.modified
                && !is_local_url(value)
        }) {
            return Err("AG_LS_PROXY изменён пользователем; значение сохранено".into());
        }
        backup.modified = url.into();
        Ok(backup)
    } else {
        Ok(Backup {
            schema: 1,
            original: current,
            modified: url.into(),
            extra_originals: BTreeMap::new(),
            extra_modified: BTreeMap::new(),
        })
    }
}

pub fn apply(url: &str) -> Result<(), String> {
    super::config::ensure_directory()?;
    let current = read()?;
    let mut backup = next_backup(load()?, current.clone(), url)?;
    let desired_extras = [
        (GRPC_PROXY_ENV, url),
        (NO_GRPC_PROXY_ENV, NO_GRPC_PROXY_VAL),
        (GRPC_DNS_ENV, GRPC_DNS_VAL),
    ];
    let mut pending_writes: Vec<(&str, &str)> = Vec::new();
    for (name, desired) in desired_extras {
        let cur = read_var(name)?;
        let foreign = cur.as_ref().is_some_and(|val| {
            backup
                .extra_originals
                .get(name)
                .is_some_and(|orig| orig.as_ref() != Some(val))
                && backup.extra_modified.get(name) != Some(val)
                && !(name == GRPC_PROXY_ENV && is_local_url(val))
        });
        let foreign_untracked = !backup.extra_originals.contains_key(name)
            && name == GRPC_PROXY_ENV
            && cur.as_deref().is_some_and(|val| !is_local_url(val));
        if foreign || foreign_untracked {
            continue;
        }
        backup.extra_originals.entry(name.into()).or_insert(cur.clone());
        backup.extra_modified.insert(name.into(), desired.into());
        if cur.as_deref() != Some(desired) {
            pending_writes.push((name, desired));
        }
    }
    let path = backup_path();
    crate::system::fs_utils::robust_write_file(
        &path,
        &serde_json::to_vec_pretty(&backup).map_err(|e| e.to_string())?,
    )?;
    super::config::inherit_directory_owner(&path)?;
    if current.as_deref() != Some(url) {
        if read()? != current {
            return Err("AG_LS_PROXY изменился во время подготовки отката".into());
        }
        write_var(ENV_NAME, Some(url))?;
    }
    for (name, desired) in pending_writes {
        write_var(name, Some(desired))?;
    }
    Ok(())
}

pub fn restore() -> Result<(), String> {
    let Some(backup) = load()? else {
        return Ok(());
    };
    let current = read()?;
    if current.as_ref().is_some_and(|value| {
        Some(value) != backup.original.as_ref() && value != &backup.modified && !is_local_url(value)
    }) {
        return Err("AG_LS_PROXY изменён пользователем; копия и значение сохранены".into());
    }
    if current != backup.original {
        write_var(ENV_NAME, backup.original.as_deref())?;
    }
    for (name, orig) in &backup.extra_originals {
        if let Ok(cur) = read_var(name) {
            let managed = backup.extra_modified.get(name) == cur.as_ref()
                || (name == GRPC_PROXY_ENV && cur.as_deref().is_some_and(is_local_url));
            if managed && &cur != orig {
                write_var(name, orig.as_deref())?;
            }
        }
    }
    match fs::remove_file(backup_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_absence_and_value_survive_port_changes() {
        for original in [None, Some("http://user-proxy.example:3128".into())] {
            let backup = next_backup(None, original.clone(), "http://127.0.0.1:53129").unwrap();
            assert_eq!(backup.original, original);
            let moved = next_backup(
                Some(backup),
                Some("http://127.0.0.1:53129".into()),
                "http://127.0.0.1:43129",
            )
            .unwrap();
            assert_eq!(moved.original, original);
            assert_eq!(moved.modified, "http://127.0.0.1:43129");
        }
    }

    #[test]
    fn foreign_change_blocks_restore_and_only_loopback_urls_are_managed() {
        let backup = next_backup(None, None, "http://127.0.0.1:53129").unwrap();
        assert!(next_backup(
            Some(backup),
            Some("http://foreign.example:3128".into()),
            "http://127.0.0.1:43129"
        )
        .is_err());
        for invalid in [
            "http://localhost:53129",
            "https://127.0.0.1:53129",
            "http://127.0.0.1:0",
            "http://127.0.0.1:53129/path",
        ] {
            assert!(next_backup(None, None, invalid).is_err());
        }
    }
}
