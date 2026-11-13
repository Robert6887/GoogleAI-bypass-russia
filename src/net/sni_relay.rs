//! Loopback-only TLS SNI passthrough gateway for native macOS `Gemini.app`.
//!
//! `Gemini.app` (`GRPC2ClientProviderImpl` / `GRPCNIOTransportHTTP2Posix`) opens raw
//! POSIX BSD sockets directly to `robinfrontend-pa.googleapis.com:443`, bypassing
//! macOS `.pac` and environment proxy variables. When `gemini_desktop` is enabled in
//! `OwnProxy` mode, this relay listens exclusively on dedicated `lo0` aliases
//! (`127.0.0.2:443` and `[fd00:6765:6d69::2]:443`, leaving `127.0.0.1:443` untouched),
//! drops root privileges immediately after binding port 443, inspects only the
//! cleartext TLS `ClientHello` SNI hostname, and tunnels the untouched end-to-end TLS
//! stream through the user's configured SOCKS5 or HTTP proxy.
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

pub const SNI_PROXY_FLAG: &str = "--sni-proxy";
pub const DAEMON_LABEL: &str = "com.antigravity.bypass.sni";
const MAX_TLS_RECORD: usize = 16 * 1024;
const HELLO_BUDGET: Duration = Duration::from_secs(5);

pub const GEMINI_DESKTOP_SNI_HOSTS: &[&str] = &[
    "robinfrontend-pa.googleapis.com",
    "robinfrontend-pa.mtls.googleapis.com",
    "webchannel-robinfrontend-pa.googleapis.com",
    "webchannel-robinfrontend-pa.mtls.googleapis.com",
    "preprod-robinfrontend-pa.googleapis.com",
    "accountlinking-pa.googleapis.com",
    "notifications-pa.googleapis.com",
    "notifications-ueeshp-pa.googleapis.com",
    "signaler-pa.googleapis.com",
    "speechs3proto2-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "geller-pa.googleapis.com",
    "feedback-pa.googleapis.com",
    "feedback-pa.mtls.googleapis.com",
    "directpath-pa.googleapis.com",
];

/// Extract the RFC 6066 `server_name` (`host_name`) from a complete TLS `ClientHello` record.
pub fn extract_tls_sni(record: &[u8]) -> Option<String> {
    if record.len() < 5 || record[0] != 0x16 || record[1] != 0x03 {
        return None;
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let body = record.get(5..5 + record_len)?;
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
    let hello = body.get(4..4 + hs_len)?;
    // client_version (2) + random (32)
    let mut pos = 34usize;
    let sid_len = *hello.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;
    let cs_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?;
    let comp_len = *hello.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(comp_len)?;
    let ext_total = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    let mut exts = hello.get(pos..pos + ext_total)?;
    while exts.len() >= 4 {
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let ext_len = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        let ext_data = exts.get(4..4 + ext_len)?;
        exts = &exts[4 + ext_len..];
        if ext_type != 0x0000 || ext_data.len() < 2 {
            continue;
        }
        let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
        let mut names = ext_data.get(2..2 + list_len)?;
        while names.len() >= 3 {
            let name_type = names[0];
            let name_len = u16::from_be_bytes([names[1], names[2]]) as usize;
            let raw_name = names.get(3..3 + name_len)?;
            names = &names[3 + name_len..];
            if name_type == 0x00 {
                let host = std::str::from_utf8(raw_name).ok()?.trim();
                if !host.is_empty()
                    && host.len() <= 253
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                {
                    return Some(host.to_ascii_lowercase());
                }
                return None;
            }
        }
    }
    None
}

pub fn read_client_hello(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    let mut read_hdr = 0usize;
    while read_hdr < 5 {
        let remain = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TLS header timeout"))?;
        stream.set_read_timeout(Some(remain))?;
        match stream.read(&mut header[read_hdr..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF before TLS header",
                ))
            }
            Ok(n) => read_hdr += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if header[0] != 0x16 || header[1] != 0x03 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Not a TLS Handshake record",
        ));
    }
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if body_len == 0 || body_len > MAX_TLS_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid TLS record length",
        ));
    }
    let total = 5 + body_len;
    let mut record = vec![0u8; total];
    record[..5].copy_from_slice(&header);
    let mut offset = 5usize;
    while offset < total {
        let remain = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TLS body timeout"))?;
        stream.set_read_timeout(Some(remain))?;
        match stream.read(&mut record[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF inside TLS ClientHello",
                ))
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(record)
}

pub fn handle_sni_client(mut client: TcpStream, config_path: &Path) {
    let Ok(hello) = read_client_hello(&mut client, Instant::now() + HELLO_BUDGET) else {
        return;
    };
    let Some(sni) = extract_tls_sni(&hello) else {
        return;
    };
    if !super::local_proxy::is_gate_host(&sni) {
        return;
    }
    let Ok(config) = super::proxy_config::load_from_path(config_path) else {
        return;
    };
    let Ok(mut remote) = super::local_proxy::open_upstream_gate(&sni, 443, &config) else {
        return;
    };
    if remote.write_all(&hello).is_ok() {
        super::local_proxy::tunnel(client, remote);
    }
}

fn sni_loopback_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 443)
}

pub fn listener_alive() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = sni_loopback_v4();
        false
    }
    #[cfg(target_os = "macos")]
    {
        TcpStream::connect_timeout(&sni_loopback_v4(), Duration::from_millis(150)).is_ok()
    }
}

fn serve_listener(listener: TcpListener, config_path: PathBuf) {
    let _ = super::socket::configure_tcp_listener(&listener);
    for incoming in listener.incoming() {
        if let Ok(client) = incoming {
            let path = config_path.clone();
            thread::spawn(move || handle_sni_client(client, &path));
        }
    }
}

#[cfg(target_os = "macos")]
fn configure_lo0_aliases(enable: bool) {
    if enable {
        let _ = crate::system::command::output(
            "/sbin/ifconfig",
            [
                "lo0",
                "inet",
                super::hosts::SNI_LOOPBACK_IPV4,
                "netmask",
                "255.255.255.255",
                "alias",
            ],
        );
        let _ = crate::system::command::output(
            "/sbin/ifconfig",
            [
                "lo0",
                "inet6",
                super::hosts::SNI_LOOPBACK_IPV6,
                "prefixlen",
                "128",
                "alias",
            ],
        );
    } else {
        let _ = crate::system::command::output(
            "/sbin/ifconfig",
            ["lo0", "-alias", super::hosts::SNI_LOOPBACK_IPV4],
        );
        let _ = crate::system::command::output(
            "/sbin/ifconfig",
            ["lo0", "inet6", super::hosts::SNI_LOOPBACK_IPV6, "-alias"],
        );
    }
}

#[cfg(target_os = "macos")]
fn drop_privileges(uid: u32, gid: u32) -> Result<(), String> {
    if uid == 0 {
        return Err("Целевой UID для сброса привилегий SNI-шлюза не может быть 0".into());
    }
    unsafe {
        if libc::geteuid() == 0 {
            let _ = libc::setgroups(0, std::ptr::null());
            if libc::setgid(gid) != 0 {
                return Err("Не удалось сбросить GID в SNI-шлюзе".into());
            }
            if libc::setuid(uid) != 0 {
                return Err("Не удалось сбросить UID в SNI-шлюзе".into());
            }
        }
        if libc::geteuid() != uid || libc::getuid() != uid {
            return Err("Проверка сброса привилегий SNI-шлюза не прошла".into());
        }
    }
    Ok(())
}

pub fn run_from_args(args: &[String]) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (args, serve_listener as fn(TcpListener, PathBuf));
        Err("SNI-шлюз Gemini.app используется только на macOS".into())
    }
    #[cfg(target_os = "macos")]
    {
        if args.len() != 3 {
            return Err("Использование: --sni-proxy <uid> <gid> <proxy.json>".into());
        }
        let uid: u32 = args[0]
            .parse()
            .map_err(|_| "Некорректный UID для SNI-шлюза".to_string())?;
        let gid: u32 = args[1]
            .parse()
            .map_err(|_| "Некорректный GID для SNI-шлюза".to_string())?;
        let config_path = PathBuf::from(&args[2]);

        configure_lo0_aliases(true);
        let v4_listener = TcpListener::bind(sni_loopback_v4())
            .map_err(|e| format!("Не удалось занять 127.0.0.2:443 для Gemini Desktop: {e}"))?;
        let v6_addr: Option<SocketAddr> = format!("[{}]:443", super::hosts::SNI_LOOPBACK_IPV6)
            .parse()
            .ok();
        let v6_listener = v6_addr.and_then(|addr| TcpListener::bind(addr).ok());

        drop_privileges(uid, gid)?;

        if let Some(v6) = v6_listener {
            let cfg_v6 = config_path.clone();
            thread::spawn(move || serve_listener(v6, cfg_v6));
        }
        serve_listener(v4_listener, config_path);
        Err("Цикл SNI-шлюза завершился".into())
    }
}

#[cfg(target_os = "macos")]
fn daemon_exe_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/AntigravityBypass/ag_sni_relay")
}

#[cfg(target_os = "macos")]
fn daemon_plist_path() -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{DAEMON_LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn daemon_plist_xml(exe: &Path, uid: u32, gid: u32, config_path: &Path) -> String {
    use super::local_proxy::xml_escape;
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{DAEMON_LABEL}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>{SNI_PROXY_FLAG}</string><string>{uid}</string><string>{gid}</string><string>{}</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>5</integer>\n</dict></plist>\n",
        xml_escape(&exe.to_string_lossy()),
        xml_escape(&config_path.to_string_lossy()),
    )
}

pub fn enable() -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::{
            fs,
            os::unix::fs::{MetadataExt, PermissionsExt},
        };
        if unsafe { libc::geteuid() } != 0 {
            if listener_alive() {
                return Ok(());
            }
            return Err("Для настройки SNI-шлюза Gemini.app запустите пункт [1]".into());
        }
        let home_meta = fs::metadata(crate::system::env::expand_env_vars("~"))
            .map_err(|e| format!("Не удалось определить пользователя GUI: {e}"))?;
        let uid = home_meta.uid();
        let gid = home_meta.gid();
        if uid == 0 {
            return Err("Не найден непривилегированный пользователь GUI для SNI-шлюза".into());
        }

        let source = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe = daemon_exe_path();
        if let Some(parent) = exe.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
            let _ = std::os::unix::fs::chown(parent, Some(0), Some(0));
        }
        let bytes = fs::read(&source).map_err(|e| format!("Чтение бинарника SNI-шлюза: {e}"))?;
        let _ = fs::remove_file(&exe);
        crate::system::fs_utils::robust_write_file(&exe, &bytes)?;
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        crate::system::fs_utils::post_write_hook(&exe)?;
        let _ = std::os::unix::fs::chown(&exe, Some(0), Some(0));

        let plist = daemon_plist_path();
        let config_path = super::proxy_config::path();
        let xml = daemon_plist_xml(&exe, uid, gid, &config_path);
        crate::system::fs_utils::robust_write_file(&plist, xml.as_bytes())?;
        fs::set_permissions(&plist, fs::Permissions::from_mode(0o644))
            .map_err(|e| e.to_string())?;
        let _ = std::os::unix::fs::chown(&plist, Some(0), Some(0));

        let _ = crate::system::command::output(
            "launchctl",
            ["bootout", &format!("system/{DAEMON_LABEL}")],
        );
        let out = crate::system::command::output(
            "launchctl",
            ["bootstrap", "system", &plist.to_string_lossy()],
        )
        .map_err(|e| e.to_string())?;
        if !out.status.success() {
            let loaded = crate::system::command::output(
                "launchctl",
                ["print", &format!("system/{DAEMON_LABEL}")],
            )
            .is_ok_and(|o| o.status.success());
            if !loaded {
                return Err(format!(
                    "LaunchDaemon SNI-шлюза не загружен: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }

        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            if listener_alive() {
                super::hosts::apply_gemini_sni_hosts(GEMINI_DESKTOP_SNI_HOSTS)?;
                let _ = super::flush_dns_cache();
                return Ok(());
            }
            thread::sleep(Duration::from_millis(80));
        }
        Err("SNI-шлюз Gemini.app (127.0.0.2:443) не подтвердил готовность за 6 секунд".into())
    }
}

pub fn disable() -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use std::fs;
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        let mut errors = Vec::new();
        match super::hosts::remove_gemini_sni_hosts() {
            Ok(true) => {
                let _ = super::flush_dns_cache();
            }
            Ok(false) => {}
            Err(e) => errors.push(e),
        }
        let _ = crate::system::command::output(
            "launchctl",
            ["bootout", &format!("system/{DAEMON_LABEL}")],
        );
        let plist = daemon_plist_path();
        if plist.exists() {
            if let Err(e) = fs::remove_file(&plist) {
                errors.push(e.to_string());
            }
        }
        let exe = daemon_exe_path();
        if std::env::current_exe().ok().as_ref() != Some(&exe) && exe.exists() {
            let _ = fs::remove_file(&exe);
        }
        if let Some(parent) = exe.parent() {
            let _ = fs::remove_dir(parent);
        }
        configure_lo0_aliases(false);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(sni: Option<&str>, pad_len: usize) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(host) = sni {
            let hb = host.as_bytes();
            let list_len = (3 + hb.len()) as u16;
            let ext_len = 2 + list_len;
            exts.extend_from_slice(&0x0000u16.to_be_bytes());
            exts.extend_from_slice(&ext_len.to_be_bytes());
            exts.extend_from_slice(&list_len.to_be_bytes());
            exts.push(0x00);
            exts.extend_from_slice(&(hb.len() as u16).to_be_bytes());
            exts.extend_from_slice(hb);
        }
        if pad_len > 0 {
            // Simulate large TLS 1.3 key_share (e.g., X25519MLKEM768 ~1.2 KB) before/after SNI.
            let mut ks = Vec::new();
            ks.extend_from_slice(&0x0033u16.to_be_bytes());
            ks.extend_from_slice(&(pad_len as u16).to_be_bytes());
            ks.resize(4 + pad_len, 0xAB);
            ks.extend_from_slice(&exts);
            exts = ks;
        }
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        hs.extend_from_slice(&[0x11; 32]); // random
        hs.push(32); // session_id len
        hs.extend_from_slice(&[0x22; 32]);
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1); // compression_methods len
        hs.push(0x00);
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        let hs_len = hs.len();
        let mut body = vec![
            0x01,
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ];
        body.extend_from_slice(&hs);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    #[test]
    fn extracts_sni_from_standard_and_post_quantum_fragmented_client_hello() {
        let hello = build_client_hello(Some("RobinFrontend-PA.googleapis.com"), 1500);
        assert_eq!(
            extract_tls_sni(&hello).as_deref(),
            Some("robinfrontend-pa.googleapis.com")
        );
        assert_eq!(extract_tls_sni(&build_client_hello(None, 64)), None);
        assert_eq!(extract_tls_sni(b"GET / HTTP/1.1\r\n\r\n"), None);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = hello.clone();
        let writer = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&payload[..3]).unwrap();
            thread::sleep(Duration::from_millis(15));
            s.write_all(&payload[3..700]).unwrap();
            thread::sleep(Duration::from_millis(15));
            s.write_all(&payload[700..]).unwrap();
        });
        let (mut accepted, _) = listener.accept().unwrap();
        let read_back = read_client_hello(&mut accepted, Instant::now() + Duration::from_secs(2)).unwrap();
        writer.join().unwrap();
        assert_eq!(read_back, hello);
    }
}
