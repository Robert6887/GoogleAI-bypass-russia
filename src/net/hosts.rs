//! Cleanup of legacy `/etc/hosts` blocks and third-party Google AI blackhole lines.
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const START_MARK: &str = "# BEGIN ANTIGRAVITY-BYPASS-RUSSIA";
const END_MARK: &str = "# END ANTIGRAVITY-BYPASS-RUSSIA";

pub fn hosts_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

pub fn remove_entries() -> Result<bool, String> {
    let p = hosts_path();
    if !p.exists() {
        return Ok(false);
    }
    let original = fs::read_to_string(&p).map_err(|e| format!("Чтение hosts: {e}"))?;
    let stripped = strip_legacy_entries(&original)?;
    if stripped == original {
        return Ok(false);
    }
    if crate::net::config::ensure_directory().is_ok() {
        let archive = crate::net::config::directory().join("hosts.legacy-archive");
        if !archive.exists() {
            let _ = crate::system::fs_utils::robust_write_file(&archive, original.as_bytes());
            let _ = crate::net::config::inherit_directory_owner(&archive);
        }
    }
    safe_write_hosts(&p, original.as_bytes(), stripped.as_bytes())?;
    Ok(true)
}

pub fn has_gate_overrides() -> bool {
    let p = hosts_path();
    let Ok(text) = fs::read_to_string(p) else {
        return false;
    };
    strip_legacy_entries(&text).is_ok_and(|stripped| stripped != text)
}

pub(crate) fn is_legacy_or_gate_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    super::local_proxy::is_gate_host(&h)
        || matches!(
            h.as_str(),
            "makersuite.google.com"
                | "bard.google.com"
                | "jules.google.com"
                | "deepmind.google"
                | "notebooklm-pa.googleapis.com"
                | "aisandbox-pa.googleapis.com"
        )
}

pub fn strip_legacy_entries(text: &str) -> Result<String, String> {
    let without_block = strip_block(text)?;
    let mut result = String::with_capacity(without_block.len());
    for line in without_block.split_inclusive('\n') {
        let trimmed = line.trim();
        if is_legacy_bypass_comment(trimmed) || is_gate_host_override(trimmed) {
            continue;
        }
        result.push_str(line);
    }
    Ok(result)
}

fn is_legacy_bypass_comment(trimmed: &str) -> bool {
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("# ag-bypass")
        || lower.starts_with("# antigravity-bypass")
        || lower.starts_with("# confeden")
}

fn is_gate_host_override(trimmed: &str) -> bool {
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    let body = trimmed.split('#').next().unwrap_or("").trim();
    let mut fields = body.split_whitespace();
    let Some(ip_str) = fields.next() else {
        return false;
    };
    if ip_str.parse::<IpAddr>().is_err() {
        return false;
    }
    let hosts: Vec<&str> = fields.collect();
    !hosts.is_empty() && hosts.iter().all(|h| is_legacy_or_gate_host(h))
}

fn strip_block(text: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut in_block = false;
    for line in text.split_inclusive('\n') {
        match line.trim() {
            START_MARK if !in_block => in_block = true,
            END_MARK if in_block => in_block = false,
            START_MARK | END_MARK => {
                return Err("Повреждены границы блока hosts; файл сохранён".into())
            }
            _ if !in_block => result.push_str(line),
            _ => {}
        }
    }
    if in_block {
        return Err("Нет конца блока hosts; файл сохранён".into());
    }
    Ok(result)
}

fn safe_write_hosts(path: &Path, expected: &[u8], data: &[u8]) -> Result<(), String> {
    let current = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && expected.is_empty() => vec![],
        Err(e) => return Err(e.to_string()),
    };
    if current != expected {
        return Err("hosts изменён другой программой; повторите операцию".into());
    }
    let result = crate::system::fs_utils::robust_write_file(path, data);
    #[cfg(windows)]
    if let Err(atomic_error) = result {
        return write_hosts_in_place(path, expected, data)
            .map_err(|e| format!("{atomic_error}. Обновление hosts на месте: {e}"));
    }
    result
}

#[cfg(windows)]
fn write_hosts_in_place(path: &Path, expected: &[u8], data: &[u8]) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(1)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut original = Vec::new();
    file.read_to_end(&mut original).map_err(|e| e.to_string())?;
    if original != expected {
        return Err("hosts изменён другой программой; повторите операцию".into());
    }
    let mut backup = tempfile::Builder::new()
        .prefix("hosts.antigravity-recovery-")
        .tempfile_in(path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|e| e.to_string())?;
    backup.write_all(&original).map_err(|e| e.to_string())?;
    backup.as_file().sync_all().map_err(|e| e.to_string())?;
    let (backup_file, backup_path) = backup.keep().map_err(|e| e.to_string())?;
    drop(backup_file);

    let mut replace = |bytes: &[u8]| -> std::io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()
    };
    if let Err(error) = replace(data) {
        let restored = replace(&original);
        return Err(format!(
            "{error}; восстановление исходного файла: {}; резервная копия: {}",
            match restored {
                Ok(()) => "выполнено".to_string(),
                Err(e) => e.to_string(),
            },
            backup_path.display()
        ));
    }
    let _ = fs::remove_file(backup_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_legacy_block_and_gate_ipv6_blackholes_while_keeping_user_hosts() {
        let original = "127.0.0.1 localhost\n::1 localhost\n10.0.0.5 internal.corp\n";
        let polluted = format!(
            "{START_MARK}\n83.220.169.155 cloudcode-pa.googleapis.com\n{END_MARK}\n{original}# AG-BYPASS-HAP: блок IPv6\n::1 daily-cloudcode-pa.googleapis.com\n::1 cloudcode-pa.googleapis.com\n::1 aicode.googleapis.com\n45.155.204.190 gemini.google.com robinfrontend-pa.googleapis.com\n193.233.112.67 makersuite.google.com\n"
        );
        assert_eq!(strip_legacy_entries(&polluted).unwrap(), original);
        assert!(strip_block(&format!("{START_MARK}\nunterminated")).is_err());
    }
}
