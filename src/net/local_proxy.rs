//! Loopback CONNECT gateway and PAC server for Antigravity, Gemini Web, AI Studio,
//! native macOS Gemini.app, and Chrome built-in Gemini (GLIC).
//!
//! Accepts local HTTP CONNECT from apps/OS and forwards Google AI / Gemini gate hosts
//! through the user's SOCKS5 (remote DNS `socks5h`) or HTTP CONNECT proxy with end-to-end TLS.
use super::proxy_config::{Mode, Products, ProxyConfig, ProxyProtocol, Upstream, VpnPolicy};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub const LOCAL_PROXY_FLAG: &str = "--local-proxy";
pub const DEFAULT_PORT: u16 = 53129;
pub const FALLBACK_PORTS: [u16; 6] = [43129, 44129, 45129, 46129, 47129, 48129];
pub const AGENT_LABEL: &str = "com.antigravity.bypass.local-proxy";
const MAX_HEAD: usize = 8 * 1024;
const CONNECT_BUDGET: Duration = Duration::from_secs(8);
const TEST_BUDGET: Duration = Duration::from_secs(12);

pub const ANTIGRAVITY_DOMAINS: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "autopush-cloudcode-pa.sandbox.googleapis.com",
    "aicode.googleapis.com",
];

pub const GEMINI_SHARED_AUTH_DOMAINS: &[&str] = &[
    "gemini.google.com",
    "gemini.gstatic.com",
    "gemini.app.google",
    "ogs.google.com",
    "geminiweb-pa.clients6.google.com",
    "push.clients6.google.com",
    "ogads-pa.clients6.google.com",
    "ogads-pa.googleapis.com",
    "signaler-pa.clients6.google.com",
    "signaler-pa.googleapis.com",
    "scone-pa.clients6.google.com",
    "scone-pa.googleapis.com",
    "waa-pa.clients6.google.com",
    "waa-pa.googleapis.com",
    "proactivebackend-pa.clients6.google.com",
    "peoplestack-pa.clients6.google.com",
];

pub const GEMINI_WEB_DOMAINS: &[&str] = &[
    "generativelanguage.googleapis.com",
    "aistudio.google.com",
    "ai.google.dev",
    "makersuite.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
    "webchannel-alkalimakersuite-pa.clients6.google.com",
    "gemini.google.com",
    "gemini.gstatic.com",
    "gemini.app.google",
    "geminiweb-pa.clients6.google.com",
    "push.clients6.google.com",
    "ogads-pa.clients6.google.com",
    "signaler-pa.clients6.google.com",
    "bard.google.com",
    "notebooklm.google.com",
    "notebooklm.google",
    "notebooklm-pa.googleapis.com",
    "notebooklm-pa.clients6.google.com",
    "jules.google.com",
    "labs.google",
    "aisandbox-pa.googleapis.com",
    "deepmind.google",
    "ogs.google.com",
    "scone-pa.clients6.google.com",
    "waa-pa.clients6.google.com",
    "content.googleapis.com",
];

pub const GEMINI_DESKTOP_DOMAINS: &[&str] = &[
    "robinfrontend-pa.googleapis.com",
    "robinfrontend-pa.mtls.googleapis.com",
    "webchannel-robinfrontend-pa.googleapis.com",
    "webchannel-robinfrontend-pa.mtls.googleapis.com",
    "preprod-robinfrontend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "geller-pa.googleapis.com",
    "signaler-pa.googleapis.com",
    "speechs3proto2-pa.googleapis.com",
    "accountlinking-pa.googleapis.com",
    "notifications-pa.googleapis.com",
    "notifications-ueeshp-pa.googleapis.com",
    "feedback-pa.googleapis.com",
    "feedback-pa.mtls.googleapis.com",
    "directpath-pa.googleapis.com",
    "photospicker.googleapis.com",
    "push.clients6.google.com",
];

pub const CHROME_GEMINI_DOMAINS: &[&str] = &[
    "geminiweb-pa.clients6.google.com",
    "geminiweb-pa.googleapis.com",
    "aratea-pa.googleapis.com",
    "aratea-pa.clients6.google.com",
    "optimizationguide-pa.googleapis.com",
    "optimizationguide-pa.clients6.google.com",
    "accountcapabilities-pa.googleapis.com",
    "clientservices.googleapis.com",
    "lensfrontend-pa.googleapis.com",
    "lensfrontend-pa.clients6.google.com",
    "push.clients6.google.com",
    "signaler-pa.clients6.google.com",
];

/// Complete union of Google AI / Gemini gate hosts eligible for proxying.
pub const GATE_DOMAINS: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "autopush-cloudcode-pa.sandbox.googleapis.com",
    "aicode.googleapis.com",
    "generativelanguage.googleapis.com",
    "aistudio.google.com",
    "ai.google.dev",
    "makersuite.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
    "webchannel-alkalimakersuite-pa.clients6.google.com",
    "gemini.google.com",
    "gemini.gstatic.com",
    "gemini.app.google",
    "geminiweb-pa.clients6.google.com",
    "push.clients6.google.com",
    "ogads-pa.clients6.google.com",
    "ogads-pa.googleapis.com",
    "signaler-pa.clients6.google.com",
    "bard.google.com",
    "notebooklm.google.com",
    "notebooklm.google",
    "notebooklm-pa.googleapis.com",
    "notebooklm-pa.clients6.google.com",
    "jules.google.com",
    "labs.google",
    "aisandbox-pa.googleapis.com",
    "deepmind.google",
    "ogs.google.com",
    "scone-pa.clients6.google.com",
    "scone-pa.googleapis.com",
    "waa-pa.clients6.google.com",
    "waa-pa.googleapis.com",
    "proactivebackend-pa.clients6.google.com",
    "peoplestack-pa.clients6.google.com",
    "content.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    "robinfrontend-pa.mtls.googleapis.com",
    "webchannel-robinfrontend-pa.googleapis.com",
    "webchannel-robinfrontend-pa.mtls.googleapis.com",
    "preprod-robinfrontend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "geller-pa.googleapis.com",
    "signaler-pa.googleapis.com",
    "speechs3proto2-pa.googleapis.com",
    "accountlinking-pa.googleapis.com",
    "notifications-pa.googleapis.com",
    "notifications-ueeshp-pa.googleapis.com",
    "feedback-pa.googleapis.com",
    "feedback-pa.mtls.googleapis.com",
    "directpath-pa.googleapis.com",
    "photospicker.googleapis.com",
    "geminiweb-pa.googleapis.com",
    "aratea-pa.googleapis.com",
    "aratea-pa.clients6.google.com",
    "optimizationguide-pa.googleapis.com",
    "optimizationguide-pa.clients6.google.com",
    "accountcapabilities-pa.googleapis.com",
    "clientservices.googleapis.com",
    "lensfrontend-pa.googleapis.com",
    "lensfrontend-pa.clients6.google.com",
];

pub fn is_gate_host(host: &str) -> bool {
    let trimmed = host.trim().trim_end_matches('.');
    let lower = trimmed.to_ascii_lowercase();
    GATE_DOMAINS.iter().any(|domain| {
        lower == *domain
            || (lower.len() > domain.len()
                && lower.ends_with(domain)
                && lower.as_bytes()[lower.len() - domain.len() - 1] == b'.')
    })
}

fn active_pac_domains(products: &Products) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut push_unique = |slice: &[&'static str]| {
        for &domain in slice {
            if !out.contains(&domain) {
                out.push(domain);
            }
        }
    };
    if products.antigravity {
        push_unique(ANTIGRAVITY_DOMAINS);
    }
    if products.needs_system_pac() {
        push_unique(GEMINI_SHARED_AUTH_DOMAINS);
    }
    if products.gemini_web {
        push_unique(GEMINI_WEB_DOMAINS);
    }
    if products.gemini_desktop {
        push_unique(GEMINI_DESKTOP_DOMAINS);
    }
    if products.chrome_gemini {
        push_unique(CHROME_GEMINI_DOMAINS);
    }
    out
}

fn parse_pac_request(head: &[u8]) -> Option<bool> {
    let line = std::str::from_utf8(head).ok()?.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return None;
    }
    let is_head = if method.eq_ignore_ascii_case("GET") {
        false
    } else if method.eq_ignore_ascii_case("HEAD") {
        true
    } else {
        return None;
    };
    let path = if let Some(rest) = target.strip_prefix("http://") {
        rest.find('/').map_or("/", |idx| &rest[idx..])
    } else {
        target
    };
    let clean = path.split('?').next().unwrap_or(path);
    (clean == "/proxy.pac").then_some(is_head)
}

pub fn pac_script_for_products(port: u16, products: &Products) -> String {
    let domains = active_pac_domains(products);
    if domains.is_empty() {
        return "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n".into();
    }
    let mut list = String::new();
    for (idx, domain) in domains.iter().enumerate() {
        if idx > 0 {
            list.push_str(",\n    ");
        }
        list.push('"');
        list.push_str(domain);
        list.push('"');
    }
    format!(
        "function FindProxyForURL(url, host) {{\n  host = host.toLowerCase();\n  var colon = host.indexOf(':');\n  if (colon !== -1 && host.charAt(0) !== '[') host = host.substring(0, colon);\n  if (host.charAt(host.length - 1) === '.') host = host.substring(0, host.length - 1);\n  var domains = [\n    {list}\n  ];\n  for (var i = 0; i < domains.length; i++) {{\n    var d = domains[i];\n    if (host === d) return \"PROXY 127.0.0.1:{port}\";\n    var suffix = \".\" + d;\n    if (host.length > suffix.length && host.substring(host.length - suffix.length) === suffix) {{\n      return \"PROXY 127.0.0.1:{port}\";\n    }}\n  }}\n  return \"DIRECT\";\n}}\n"
    )
}

fn parse_connect(head: &[u8]) -> Result<(String, u16), u16> {
    let text = std::str::from_utf8(head).map_err(|_| 400u16)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or(400u16)?;
    let mut parts = request.split_whitespace();
    let method = parts.next().ok_or(400u16)?;
    let authority = parts.next().ok_or(400u16)?;
    let version = parts.next().ok_or(400u16)?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(400);
    }
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(405);
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(400u16)?;
        (host, tail.strip_prefix(':').ok_or(400u16)?)
    } else {
        authority.rsplit_once(':').ok_or(400u16)?
    };
    if host.is_empty()
        || host.len() > 253
        || host.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(400);
    }
    let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or(400u16)?;
    Ok((host.to_string(), port))
}

fn read_head(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT header is too large or slow",
            ));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before CONNECT headers",
                ))
            }
            Ok(_) => head.push(byte[0]),
            Err(error) => return Err(error),
        }
    }
    Ok(head)
}

fn status_code(head: &[u8]) -> Option<u16> {
    std::str::from_utf8(head)
        .ok()?
        .split("\r\n")
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn basic_auth(username: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{username}:{password}");
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.as_bytes().chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        for index in 0..4 {
            if index <= chunk.len() {
                output.push(ALPHABET[((value >> (18 - 6 * index)) & 63) as usize] as char);
            } else {
                output.push('=');
            }
        }
    }
    output
}

fn resolve_within(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, String> {
    let host = host.to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (host.as_str(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>())
            .map_err(|e| e.to_string());
        let _ = tx.send(result);
    });
    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(addresses)) if !addresses.is_empty() => Ok(addresses),
        Ok(Ok(_)) => Err("DNS не вернул адресов".into()),
        Ok(Err(_)) => Err("Не удалось разрешить адрес прокси или сервера".into()),
        Err(_) => Err("Превышено время DNS-запроса".into()),
    }
}

#[cfg(target_os = "macos")]
fn physical_interface() -> Option<u32> {
    super::egress::detect_physical().map(|(index, _)| index)
}

#[cfg(not(target_os = "macos"))]
fn physical_interface() -> Option<u32> {
    None
}

#[cfg(target_os = "macos")]
fn connect_bound(address: SocketAddr, timeout: Duration, if_index: u32) -> io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, RawFd};
    struct Fd(RawFd);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = Fd(unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) });
    if fd.0 < 0 {
        return Err(io::Error::last_os_error());
    }
    let option = if address.is_ipv4() { 25 } else { 125 }; // IP_BOUND_IF / IPV6_BOUND_IF
    let level = if address.is_ipv4() {
        libc::IPPROTO_IP
    } else {
        libc::IPPROTO_IPV6
    };
    let index = if_index as libc::c_int;
    if unsafe {
        libc::setsockopt(
            fd.0,
            level,
            option,
            &index as *const _ as *const libc::c_void,
            std::mem::size_of_val(&index) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(fd.0, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd.0, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (storage, length) = socket_address(address);
    let connected =
        unsafe { libc::connect(fd.0, &storage as *const _ as *const libc::sockaddr, length) };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let mut poll = libc::pollfd {
            fd: fd.0,
            events: libc::POLLOUT,
            revents: 0,
        };
        let millis = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
        }
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut socket_error: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.0,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut socket_error as *mut _ as *mut libc::c_void,
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(io::Error::from_raw_os_error(socket_error));
        }
    }
    if unsafe { libc::fcntl(fd.0, libc::F_SETFL, flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = fd.0;
    std::mem::forget(fd);
    Ok(unsafe { TcpStream::from_raw_fd(raw) })
}

#[cfg(target_os = "macos")]
fn socket_address(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    unsafe {
        match address {
            SocketAddr::V4(address) => {
                let mut raw: libc::sockaddr_in = std::mem::zeroed();
                raw.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                raw.sin_family = libc::AF_INET as libc::sa_family_t;
                raw.sin_port = address.port().to_be();
                raw.sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                };
                let mut storage: libc::sockaddr_storage = std::mem::zeroed();
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, raw);
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            SocketAddr::V6(address) => {
                let mut raw: libc::sockaddr_in6 = std::mem::zeroed();
                raw.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                raw.sin6_port = address.port().to_be();
                raw.sin6_addr = libc::in6_addr {
                    s6_addr: address.ip().octets(),
                };
                raw.sin6_flowinfo = address.flowinfo();
                raw.sin6_scope_id = address.scope_id();
                let mut storage: libc::sockaddr_storage = std::mem::zeroed();
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, raw);
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    }
}

fn connect_addresses(
    host: &str,
    port: u16,
    deadline: Instant,
    policy: VpnPolicy,
) -> Result<TcpStream, String> {
    let interface = if policy == VpnPolicy::Bypass {
        physical_interface()
    } else {
        None
    };
    let addresses = resolve_within(host, port, deadline)?;
    // Pass 1: when physical-first (`Bypass`) is enabled, try binding directly to
    // the hardware NIC (`en*`) for non-loopback targets so active L3 `utun` tunnels
    // cannot hijack or double-encapsulate proxy traffic. Loopback (`127.0.0.1` / `::1`,
    // e.g. a local SOCKS5/HTTP core on this machine) skips hardware binding immediately.
    if let Some(if_index) = interface {
        for address in &addresses {
            if address.ip().is_loopback() {
                continue;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let bound_budget = left.min(Duration::from_millis(2500));
            #[cfg(target_os = "macos")]
            if let Ok(stream) = connect_bound(*address, bound_budget, if_index) {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (address, bound_budget, if_index);
        }
    }
    // Pass 2: standard OS-routed connect (used directly for loopback upstreams,
    // `VpnPolicy::Use`, or as automatic zero-config fallback when an active tunnel
    // enables a kernel kill-switch such as `includeAllNetworks` / WFP that blocks `en0`).
    for address in addresses {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        if let Ok(stream) = TcpStream::connect_timeout(&address, left) {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
    }
    Err("TCP-соединение не установлено в отведённое время".into())
}

fn read_exact_until(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("Превышено время ожидания ответа от прокси".into());
    }
    stream
        .set_read_timeout(Some(left))
        .map_err(|_| "Ошибка таймаута чтения сокета".to_string())?;
    stream
        .read_exact(buf)
        .map_err(|_| "Прокси закрыл соединение или не ответил вовремя".to_string())
}

fn open_socks5(
    upstream: &Upstream,
    host: &str,
    port: u16,
    policy: VpnPolicy,
    budget: Duration,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + budget;
    let mut stream = connect_addresses(&upstream.host, upstream.port, deadline, policy)?;
    stream
        .set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .ok();
    let greeting: &[u8] = if upstream.credentials.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream
        .write_all(greeting)
        .map_err(|_| "Не отправить приветствие SOCKS5".to_string())?;

    let mut method_reply = [0u8; 2];
    read_exact_until(&mut stream, &mut method_reply, deadline)?;
    if method_reply[0] != 0x05 {
        return Err("Сервер не является SOCKS5-прокси".into());
    }
    match method_reply[1] {
        0x00 => {}
        0x02 => {
            let creds = upstream
                .credentials
                .as_ref()
                .ok_or("SOCKS5-прокси требует логин и пароль")?;
            let ubytes = creds.username.as_bytes();
            let pbytes = creds.password.as_bytes();
            if ubytes.len() > 255 || pbytes.len() > 255 {
                return Err("Логин или пароль длиннее 255 байт (ограничение SOCKS5)".into());
            }
            let mut auth = Vec::with_capacity(3 + ubytes.len() + pbytes.len());
            auth.push(0x01);
            auth.push(ubytes.len() as u8);
            auth.extend_from_slice(ubytes);
            auth.push(pbytes.len() as u8);
            auth.extend_from_slice(pbytes);
            stream
                .write_all(&auth)
                .map_err(|_| "Не отправить авторизацию SOCKS5".to_string())?;
            let mut auth_reply = [0u8; 2];
            read_exact_until(&mut stream, &mut auth_reply, deadline)?;
            if auth_reply[1] != 0x00 {
                return Err("SOCKS5-прокси отклонил логин или пароль".into());
            }
        }
        0xFF => return Err("SOCKS5-прокси отклонил метод авторизации (проверьте логин/пароль)".into()),
        other => return Err(format!("Неподдерживаемый метод авторизации SOCKS5 (0x{other:02x})")),
    }

    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let mut req = Vec::with_capacity(7 + clean_host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(v4) = clean_host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = clean_host.parse::<Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let domain = clean_host.as_bytes();
        if domain.is_empty() || domain.len() > 255 {
            return Err("Некорректное доменное имя для SOCKS5".into());
        }
        req.push(0x03);
        req.push(domain.len() as u8);
        req.extend_from_slice(domain);
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .map_err(|_| "Не отправить запрос подключения SOCKS5".to_string())?;

    let mut head = [0u8; 4];
    read_exact_until(&mut stream, &mut head, deadline)?;
    if head[0] != 0x05 {
        return Err("Некорректный ответ SOCKS5-прокси".into());
    }
    match head[1] {
        0x00 => {}
        0x02 => return Err("SOCKS5-прокси запретил подключение правилами (0x02)".into()),
        0x03 | 0x04 => return Err("Целевой сервер недоступен с внешнего SOCKS5-прокси".into()),
        0x05 => return Err("Целевой сервер отклонил соединение через SOCKS5 (0x05)".into()),
        code => return Err(format!("SOCKS5-прокси вернул ошибку соединения (0x{code:02x})")),
    }
    match head[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            read_exact_until(&mut stream, &mut tail, deadline)?;
        }
        0x04 => {
            let mut tail = [0u8; 18];
            read_exact_until(&mut stream, &mut tail, deadline)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_until(&mut stream, &mut len, deadline)?;
            let mut tail = vec![0u8; (len[0] as usize) + 2];
            read_exact_until(&mut stream, &mut tail, deadline)?;
        }
        _ => return Err("Неизвестный тип адреса в ответе SOCKS5".into()),
    }
    stream.set_read_timeout(None).ok();
    stream.set_write_timeout(None).ok();
    Ok(stream)
}

fn open_http_connect(
    upstream: &Upstream,
    host: &str,
    port: u16,
    policy: VpnPolicy,
    budget: Duration,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + budget;
    let mut stream = connect_addresses(&upstream.host, upstream.port, deadline, policy)?;
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n");
    if let Some(credentials) = &upstream.credentials {
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            basic_auth(&credentials.username, &credentials.password)
        ));
    }
    request.push_str("\r\n");
    stream
        .set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .ok();
    stream
        .write_all(request.as_bytes())
        .map_err(|_| "Не отправить CONNECT внешнему прокси".to_string())?;
    let head = read_head(&mut stream, deadline)
        .map_err(|_| "Внешний HTTP-прокси не ответил на CONNECT вовремя".to_string())?;
    match status_code(&head) {
        Some(200) => {
            stream.set_read_timeout(None).ok();
            stream.set_write_timeout(None).ok();
            Ok(stream)
        }
        Some(407) => Err("HTTP-прокси отклонил логин или пароль (407)".into()),
        Some(403) => Err("HTTP-прокси запретил CONNECT к этому хосту (403)".into()),
        Some(code) => Err(format!("HTTP-прокси ответил HTTP {code} на CONNECT")),
        None => Err("Сервер не является HTTP CONNECT-прокси".into()),
    }
}

pub fn open_upstream(
    upstream: &Upstream,
    host: &str,
    port: u16,
    policy: VpnPolicy,
    budget: Duration,
) -> Result<TcpStream, String> {
    match upstream.protocol {
        ProxyProtocol::Socks5 => open_socks5(upstream, host, port, policy, budget),
        ProxyProtocol::Http => open_http_connect(upstream, host, port, policy, budget),
    }
}

pub fn detect_protocol_against(
    upstream: &mut Upstream,
    protocol_explicit: bool,
    policy: VpnPolicy,
    probe_host: &str,
    probe_port: u16,
) -> Result<ProxyProtocol, String> {
    let budget = Duration::from_secs(7);
    if protocol_explicit {
        open_upstream(upstream, probe_host, probe_port, policy, budget)?;
        return Ok(upstream.protocol);
    }
    let order = if matches!(upstream.port, 80 | 3128 | 8000 | 8080 | 8888) {
        [ProxyProtocol::Http, ProxyProtocol::Socks5]
    } else {
        [ProxyProtocol::Socks5, ProxyProtocol::Http]
    };
    let mut auth_error = None;
    let mut last_error = String::new();
    for candidate in order {
        let mut trial = upstream.clone();
        trial.protocol = candidate;
        match open_upstream(&trial, probe_host, probe_port, policy, budget) {
            Ok(_) => {
                upstream.protocol = candidate;
                return Ok(candidate);
            }
            Err(error) => {
                if error.contains("логин") || error.contains("пароль") || error.contains("407") {
                    auth_error = Some(error);
                } else {
                    last_error = error;
                }
            }
        }
    }
    Err(auth_error.unwrap_or(last_error))
}

pub fn detect_protocol(
    upstream: &mut Upstream,
    protocol_explicit: bool,
    policy: VpnPolicy,
) -> Result<ProxyProtocol, String> {
    detect_protocol_against(
        upstream,
        protocol_explicit,
        policy,
        "daily-cloudcode-pa.googleapis.com",
        443,
    )
}

pub(crate) fn open_upstream_gate(
    host: &str,
    port: u16,
    config: &ProxyConfig,
) -> Result<TcpStream, String> {
    if !is_gate_host(host) {
        return Err("Целевой домен не входит в список Google AI".into());
    }
    let upstream = config
        .upstream
        .as_ref()
        .ok_or_else(|| "Не указан внешний прокси для SNI-шлюза".to_string())?;
    open_upstream(upstream, host, port, config.vpn_policy, CONNECT_BUDGET)
}

fn open_route(host: &str, port: u16, config: &ProxyConfig) -> Result<TcpStream, String> {
    if !is_gate_host(host) || config.mode == Mode::Vpn {
        // Non-gate destinations and explicit system-VPN mode must honour the OS routing
        // table (including split-tunnel corporate routes) rather than binding to en*.
        return connect_addresses(
            host,
            port,
            Instant::now() + CONNECT_BUDGET,
            VpnPolicy::Use,
        );
    }
    match (&config.mode, &config.upstream) {
        (Mode::OwnProxy, Some(upstream)) => {
            open_upstream(upstream, host, port, config.vpn_policy, CONNECT_BUDGET)
        }
        (Mode::OwnProxy, None) => {
            Err("Режим своего прокси включён, но прокси не указан".into())
        }
        (Mode::Auto, Some(upstream)) => {
            match open_upstream(upstream, host, port, config.vpn_policy, CONNECT_BUDGET) {
                Ok(stream) => Ok(stream),
                Err(_) => connect_addresses(
                    host,
                    port,
                    Instant::now() + CONNECT_BUDGET,
                    config.vpn_policy,
                ),
            }
        }
        (Mode::Auto, None) => connect_addresses(
            host,
            port,
            Instant::now() + CONNECT_BUDGET,
            config.vpn_policy,
        ),
        (Mode::Vpn, _) => unreachable!(),
    }
}

fn pump(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}

pub(crate) fn tunnel(client: TcpStream, upstream: TcpStream) {
    let _ = super::socket::configure_tcp_stream(&client);
    let _ = super::socket::configure_tcp_stream(&upstream);
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let _ = upstream.set_write_timeout(None);
    if let (Ok(client_read), Ok(upstream_read)) = (client.try_clone(), upstream.try_clone()) {
        let writer = thread::spawn(move || pump(upstream_read, client));
        pump(client_read, upstream);
        let _ = writer.join();
    }
}

fn reject(client: &mut TcpStream, code: u16) {
    let (status, text) = match code {
        405 => ("405 Method Not Allowed", "Only CONNECT is supported"),
        502 => ("502 Bad Gateway", "Upstream route unavailable"),
        _ => ("400 Bad Request", "Invalid CONNECT request"),
    };
    let _ = client.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        )
        .as_bytes(),
    );
}

fn handle_client(mut client: TcpStream, config: &ProxyConfig, local_port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let head = match read_head(&mut client, deadline) {
        Ok(head) => head,
        Err(_) => {
            reject(&mut client, 400);
            return;
        }
    };
    if let Some(is_head) = parse_pac_request(&head) {
        let body = pac_script_for_products(local_port, &config.products);
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = client.write_all(headers.as_bytes());
        if !is_head {
            let _ = client.write_all(body.as_bytes());
        }
        return;
    }
    let (host, port) = match parse_connect(&head) {
        Ok(request) => request,
        Err(code) => {
            reject(&mut client, code);
            return;
        }
    };
    if local_port != 0
        && port == local_port
        && (host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost"))
    {
        reject(&mut client, 400);
        return;
    }
    match open_route(&host, port, config) {
        Ok(upstream) => {
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_ok()
            {
                tunnel(client, upstream);
            }
        }
        Err(_) => reject(&mut client, 502),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ListenerState {
    schema: u32,
    port: u16,
    pid: u32,
}

fn state_path() -> PathBuf {
    super::config::directory().join("local-proxy.json")
}

pub fn saved_port() -> Option<u16> {
    let state: ListenerState = serde_json::from_slice(&fs::read(state_path()).ok()?).ok()?;
    (state.schema == 1 && state.port != 0).then_some(state.port)
}

pub fn listener_alive() -> bool {
    saved_port().is_some_and(|port| {
        TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            Duration::from_millis(250),
        )
        .is_ok()
    })
}

pub fn url_at(port: u16) -> String {
    format!("http://{}:{port}", Ipv4Addr::LOCALHOST)
}

pub fn pac_url_at(port: u16) -> String {
    format!(
        "http://{}:{port}/proxy.pac?v={}",
        Ipv4Addr::LOCALHOST,
        super::config::now_ms()
    )
}

fn save_port(port: u16) -> Result<(), String> {
    super::config::ensure_directory()?;
    let state = ListenerState {
        schema: 1,
        port,
        pid: std::process::id(),
    };
    crate::system::fs_utils::robust_write_file(
        &state_path(),
        &serde_json::to_vec(&state).map_err(|e| e.to_string())?,
    )
}

pub fn run() -> Result<(), String> {
    let mut last_error = None;
    let mut listener = None;
    for port in std::iter::once(DEFAULT_PORT).chain(FALLBACK_PORTS) {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(bound) => {
                listener = Some((bound, port));
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let (listener, port) = listener.ok_or_else(|| {
        format!(
            "Не удалось занять локальные порты прокси: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "неизвестная ошибка".into())
        )
    })?;
    let _ = super::socket::configure_tcp_listener(&listener);
    save_port(port)?;
    #[cfg(target_os = "macos")]
    if super::proxy_config::load()
        .map(|c| c.products.antigravity)
        .unwrap_or(true)
    {
        super::proxy_session::apply(&url_at(port))?;
    }
    eprintln!("Локальный шлюз Antigravity / Gemini: {}", url_at(port));
    for connection in listener.incoming() {
        match connection {
            Ok(client) => {
                let config = super::proxy_config::load().unwrap_or_else(|_| ProxyConfig {
                    mode: Mode::OwnProxy,
                    ..ProxyConfig::default()
                });
                thread::spawn(move || handle_client(client, &config, port));
            }
            Err(error) => eprintln!("Ошибка accept локального прокси: {error}"),
        }
    }
    Err("Цикл локального прокси завершился".into())
}

#[derive(Clone, Debug, Serialize)]
pub struct ProductCheck {
    pub name: &'static str,
    pub host: &'static str,
    pub ok: bool,
    pub geo_blocked: bool,
    pub latency_ms: u128,
    pub http_status: Option<u16>,
    pub detail: String,
}

pub(crate) fn is_geo_blocked_response(raw_text: &str) -> bool {
    let lower = raw_text.to_ascii_lowercase();
    let header_end = lower.find("\r\n\r\n").unwrap_or(lower.len());
    let headers = &lower[..header_end];
    for line in headers.lines() {
        if let Some(loc) = line.strip_prefix("location:") {
            let loc = loc.trim();
            if loc.contains("/faq")
                || loc.contains("unsupported")
                || loc.contains("available-regions")
                || loc.contains("region_not_supported")
                || loc.contains("unavailable")
            {
                return true;
            }
        }
    }
    raw_text.contains("не поддерживается в вашей стране")
        || lower.contains("isn't currently supported in your country")
        || lower.contains("gemini isn't currently supported")
        || lower.contains("available regions for google ai studio")
}

fn probe_single_product(
    name: &'static str,
    host: &'static str,
    path: &'static str,
    check_geo: bool,
    upstream: Option<&Upstream>,
    policy: VpnPolicy,
) -> ProductCheck {
    let start = Instant::now();
    let stream_res = match upstream {
        Some(proxy) => open_upstream(proxy, host, 443, policy, TEST_BUDGET),
        None => connect_addresses(host, 443, start + TEST_BUDGET, policy),
    };
    let stream = match stream_res {
        Ok(stream) => stream,
        Err(error) => {
            return ProductCheck {
                name,
                host,
                ok: false,
                geo_blocked: false,
                latency_ms: start.elapsed().as_millis(),
                http_status: None,
                detail: error,
            };
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(8))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(8))).ok();
    let mut tls = match native_tls::TlsConnector::new()
        .map_err(|_| "Ошибка системного TLS".to_string())
        .and_then(|c| {
            c.connect(host, stream)
                .map_err(|_| "Прокси открыл туннель, но TLS с Google не установлен".to_string())
        }) {
        Ok(tls) => tls,
        Err(error) => {
            return ProductCheck {
                name,
                host,
                ok: false,
                geo_blocked: false,
                latency_ms: start.elapsed().as_millis(),
                http_status: None,
                detail: error,
            };
        }
    };
    let method = if check_geo { "GET" } else { "HEAD" };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n"
    );
    if tls.write_all(req.as_bytes()).is_err() {
        return ProductCheck {
            name,
            host,
            ok: false,
            geo_blocked: false,
            latency_ms: start.elapsed().as_millis(),
            http_status: None,
            detail: "TLS открыт, но HTTP-запрос не отправлен".into(),
        };
    }
    let mut response = Vec::new();
    let limit = if check_geo { 24 * 1024 } else { 8 * 1024 };
    let _ = tls.take(limit).read_to_end(&mut response);
    let latency_ms = start.elapsed().as_millis().max(1);
    let Some(code) = status_code(&response) else {
        return ProductCheck {
            name,
            host,
            ok: false,
            geo_blocked: false,
            latency_ms,
            http_status: None,
            detail: "Google не вернул корректный HTTP-ответ".into(),
        };
    };
    let text = String::from_utf8_lossy(&response);
    if check_geo && is_geo_blocked_response(&text) {
        return ProductCheck {
            name,
            host,
            ok: false,
            geo_blocked: true,
            latency_ms,
            http_status: Some(code),
            detail: "Регион заблокирован Google (IP прокси определяется как РФ / неподдерживаемая страна)".into(),
        };
    }
    let ok = code < 500;
    let detail = if ok {
        format!("Доступ открыт (HTTP {code}, {latency_ms} мс)")
    } else {
        format!("Сервер Google вернул ошибку HTTP {code}")
    };
    ProductCheck {
        name,
        host,
        ok,
        geo_blocked: false,
        latency_ms,
        http_status: Some(code),
        detail,
    }
}

pub fn check_all_products(upstream: Option<&Upstream>, policy: VpnPolicy) -> Vec<ProductCheck> {
    const TARGETS: &[(&str, &str, &str, bool)] = &[
        ("Antigravity IDE (основной)", "daily-cloudcode-pa.googleapis.com", "/", false),
        ("Antigravity IDE (резервный)", "cloudcode-pa.googleapis.com", "/", false),
        ("Gemini в браузере", "gemini.google.com", "/app", true),
        ("Google AI Studio", "aistudio.google.com", "/", true),
        ("Gemini Desktop", "robinfrontend-pa.googleapis.com", "/", false),
        ("«Спросить Gemini» в Chrome", "geminiweb-pa.clients6.google.com", "/", false),
    ];
    thread::scope(|scope| {
        let handles: Vec<_> = TARGETS
            .iter()
            .map(|&(name, host, path, check_geo)| {
                scope.spawn(move || probe_single_product(name, host, path, check_geo, upstream, policy))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or(ProductCheck {
                    name: "Проверка",
                    host: "",
                    ok: false,
                    geo_blocked: false,
                    latency_ms: 0,
                    http_status: None,
                    detail: "Поток проверки прерван".into(),
                })
            })
            .collect()
    })
}

pub fn test_upstream() -> Result<String, String> {
    let config = super::proxy_config::load()?;
    let upstream = config
        .upstream
        .as_ref()
        .ok_or("Сначала укажите прокси (SOCKS5 или HTTP)")?;
    let checks = check_all_products(Some(upstream), config.vpn_policy);
    let ok_count = checks.iter().filter(|c| c.ok).count();
    let geo_blocked = checks.iter().any(|c| c.geo_blocked);
    if ok_count == 0 {
        let first_err = checks
            .first()
            .map(|c| c.detail.clone())
            .unwrap_or_else(|| "нет ответа".into());
        return Err(format!("Прокси не прошёл проверку: {first_err}"));
    }
    if geo_blocked {
        return Err(format!(
            "{} работает ({ok_count}/{} сервисов), но Google отклоняет регион этого IP для Gemini / AI Studio — выберите зарубежный прокси (США / Европа)",
            upstream.protocol.label(),
            checks.len()
        ));
    }
    let avg_ms = checks.iter().filter(|c| c.ok).map(|c| c.latency_ms).sum::<u128>()
        / (ok_count as u128);
    Ok(format!(
        "{} проверен: доступ открыт ко всем сервисам ({ok_count}/{}), средний отклик ~{avg_ms} мс",
        upstream.protocol.label(),
        checks.len()
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn user_id() -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let uid = fs::metadata(crate::system::env::expand_env_vars("~"))
        .map_err(|e| e.to_string())?
        .uid();
    if uid == 0 {
        return Err("Не найден пользователь GUI для фонового агента".into());
    }
    Ok(uid.to_string())
}

#[cfg(target_os = "macos")]
pub(crate) fn launchctl<I, S>(args: I) -> Result<std::process::Output, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let uid = user_id()?;
    if unsafe { libc::geteuid() } != 0 {
        return crate::system::command::output("launchctl", args).map_err(|e| e.to_string());
    }
    let args: Vec<std::ffi::OsString> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect();
    crate::system::command::output(
        "launchctl",
        std::iter::once(std::ffi::OsString::from("asuser"))
            .chain([std::ffi::OsString::from(uid), "/bin/launchctl".into()])
            .chain(args),
    )
    .map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
fn agent_path() -> PathBuf {
    crate::system::env::expand_env_vars("~/Library/LaunchAgents")
        .join(format!("{AGENT_LABEL}.plist"))
}

pub(crate) fn installed_exe() -> PathBuf {
    #[cfg(windows)]
    {
        super::config::directory().join("ag_proxy.exe")
    }
    #[cfg(not(windows))]
    {
        super::config::directory().join("ag_proxy")
    }
}

pub(crate) fn ensure_installed_exe() -> Result<PathBuf, String> {
    super::config::ensure_directory()?;
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    let destination = installed_exe();
    if source != destination {
        let bytes = fs::read(&source).map_err(|e| format!("Чтение исполняемого файла: {e}"))?;
        let _ = fs::remove_file(&destination);
        crate::system::fs_utils::robust_write_file(&destination, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        crate::system::fs_utils::post_write_hook(&destination)?;
        super::config::inherit_directory_owner(&destination)?;
    }
    #[cfg(target_os = "macos")]
    install_cli_shortcut(&destination);
    Ok(destination)
}

#[cfg(target_os = "macos")]
const CLI_SHORTCUT: &str = "/usr/local/bin/ag-bypass";

#[cfg(target_os = "macos")]
fn install_cli_shortcut(executable: &Path) {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let shortcut = Path::new(CLI_SHORTCUT);
    if let Some(parent) = shortcut.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::symlink_metadata(shortcut) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if fs::read_link(shortcut).ok().as_deref() == Some(executable) {
                return;
            }
        }
        Ok(_) => return,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let _ = std::os::unix::fs::symlink(executable, shortcut);
        }
        Err(_) => return,
    }
}

#[cfg(target_os = "macos")]
fn remove_cli_shortcut(executable: &Path) {
    let shortcut = Path::new(CLI_SHORTCUT);
    if fs::read_link(shortcut).ok().as_deref() == Some(executable) {
        let _ = fs::remove_file(shortcut);
    }
}

pub fn cli_shortcut_ready() -> bool {
    #[cfg(target_os = "macos")]
    {
        fs::read_link(CLI_SHORTCUT).ok().as_deref() == Some(installed_exe().as_path())
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn agent_plist(executable: &Path) -> String {
    let log = super::config::directory().join("local-proxy.log");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{AGENT_LABEL}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>{LOCAL_PROXY_FLAG}</string></array>\n<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer>\n<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
        xml_escape(&executable.to_string_lossy()),
        xml_escape(&log.to_string_lossy()),
        xml_escape(&log.to_string_lossy())
    )
}

#[cfg(target_os = "macos")]
fn loaded() -> bool {
    user_id().ok().is_some_and(|uid| {
        launchctl(["print".to_string(), format!("gui/{uid}/{AGENT_LABEL}")])
            .is_ok_and(|out| out.status.success())
    })
}

#[cfg(target_os = "macos")]
fn bootout() {
    if let Ok(uid) = user_id() {
        let _ = launchctl(["bootout".to_string(), format!("gui/{uid}/{AGENT_LABEL}")]);
    }
}

pub fn enable() -> Result<u16, String> {
    #[cfg(not(target_os = "macos"))]
    return Err("Автозапуск локального шлюза сейчас поддерживается на macOS".into());
    #[cfg(target_os = "macos")]
    {
        let config = super::proxy_config::load()?;
        let destination = ensure_installed_exe()?;
        let plist = agent_path();
        if let Some(parent) = plist.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let before = match fs::read(&plist) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        let after = agent_plist(&destination).into_bytes();
        crate::system::journal::apply(&plist, before.as_deref(), &after, "local-proxy-agent-v1")?;
        super::config::inherit_directory_owner(&plist)?;
        let _ = fs::remove_file(state_path());
        bootout();
        let uid = user_id()?;
        let output = launchctl([
            "bootstrap".to_string(),
            format!("gui/{uid}"),
            plist.to_string_lossy().into_owned(),
        ])
        .map_err(|e| e.to_string())?;
        if !output.status.success() && !loaded() {
            return Err(format!(
                "LaunchAgent локального прокси не загружен: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if let Some(port) = saved_port() {
                if TcpStream::connect_timeout(
                    &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    Duration::from_millis(250),
                )
                .is_ok()
                {
                    if config.products.antigravity {
                        super::proxy_session::apply(&url_at(port))?;
                    } else {
                        let _ = super::proxy_session::restore();
                    }
                    if config.products.needs_system_pac() {
                        super::gemini_apps::enable_system_pac(&pac_url_at(port))?;
                    } else {
                        let _ = super::gemini_apps::disable_system_pac();
                    }
                    if config.products.gemini_desktop && config.mode != Mode::Vpn {
                        super::sni_relay::enable()?;
                    } else {
                        let _ = super::sni_relay::disable();
                    }
                    return Ok(port);
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err("Локальный прокси не подтвердил готовность за 8 секунд".into())
    }
}

pub fn disable() -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = super::gemini_apps::restore_chrome_glic();
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let mut errors = Vec::new();
        if let Err(error) = super::sni_relay::disable() {
            errors.push(error);
        }
        let plist = agent_path();
        if plist.exists() && !crate::system::journal::has_record(&plist) {
            errors.push(format!(
                "{} не имеет журнала этой установки; чужой LaunchAgent сохранён",
                plist.display()
            ));
        } else {
            bootout();
            if plist.exists() {
                if let Err(error) = crate::system::journal::restore(&plist) {
                    errors.push(error);
                }
            }
        }
        if let Err(error) = super::gemini_apps::disable_system_pac() {
            errors.push(error);
        }
        if let Err(error) = super::gemini_apps::restore_chrome_glic() {
            errors.push(error);
        }
        if let Err(error) = super::proxy_session::restore() {
            errors.push(error);
        }
        match fs::remove_file(state_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => errors.push(e.to_string()),
        }
        let executable = installed_exe();
        remove_cli_shortcut(&executable);
        if !crate::core::autopatch::is_enabled()
            && std::env::current_exe().ok().as_ref() != Some(&executable)
            && executable.exists()
        {
            if let Err(error) = fs::remove_file(executable) {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

pub fn summary() -> serde_json::Value {
    let config = super::proxy_config::load();
    serde_json::json!({
        "configured": config.as_ref().ok().and_then(|c| c.upstream.as_ref()).is_some(),
        "protocol": config.as_ref().ok().and_then(|c| c.upstream.as_ref()).map(|u| u.protocol.to_string()),
        "mode": config.as_ref().ok().map(|c| c.mode.to_string()),
        "vpn_policy": config.as_ref().ok().map(|c| c.vpn_policy.to_string()),
        "products": config.as_ref().ok().map(|c| c.products),
        "local_port": saved_port(),
        "listener": listener_alive(),
        "sni_relay": super::sni_relay::listener_alive(),
        "pac_enabled": super::gemini_apps::pac_active(),
        "credentials": "omitted",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::proxy_config::Credentials;

    #[test]
    fn gate_policy_covers_antigravity_gemini_ai_studio_and_excludes_general_google() {
        for host in GATE_DOMAINS {
            assert!(is_gate_host(host), "{host}");
            assert!(is_gate_host(&host.to_uppercase()), "{host}");
        }
        for sub in [
            "sub.gemini.google.com",
            "ws.aistudio.google.com",
            "gemini.google.com.",
        ] {
            assert!(is_gate_host(sub), "{sub}");
        }
        for host in [
            "oauth2.googleapis.com",
            "www.google.com",
            "mail.google.com",
            "youtube.com",
            "evil-cloudcode-pa.googleapis.com.example",
            "cloudcode-pa.googleapis.com.evil.test",
            "notgemini.google.com",
        ] {
            assert!(!is_gate_host(host), "{host}");
        }
    }

    #[test]
    fn connect_parser_rejects_non_connect_and_malformed_targets() {
        assert_eq!(
            parse_connect(
                b"CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            Ok(("daily-cloudcode-pa.googleapis.com".into(), 443))
        );
        assert_eq!(
            parse_connect(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n"),
            Ok(("2001:db8::1".into(), 443))
        );
        assert_eq!(parse_connect(b"GET / HTTP/1.1\r\n\r\n"), Err(405));
        assert_eq!(parse_connect(b"CONNECT host HTTP/1.1\r\n\r\n"), Err(400));
    }

    #[test]
    fn basic_auth_matches_the_standard_vector() {
        assert_eq!(
            basic_auth("Aladdin", "open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn local_connect_uses_mock_http_upstream_and_tunnels_bytes() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let head = read_head(&mut stream, Instant::now() + Duration::from_secs(2)).unwrap();
            let text = String::from_utf8(head).unwrap();
            assert!(text.starts_with("CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\n"));
            assert!(text.contains("Proxy-Authorization: Basic dXNlcjpTRUNSRVRfVE9LRU4=\r\n"));
            stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            stream.write_all(&byte).unwrap();
        });
        let config = ProxyConfig {
            schema: 1,
            mode: Mode::OwnProxy,
            vpn_policy: VpnPolicy::Use,
            upstream: Some(
                Upstream::endpoint(
                    "127.0.0.1".into(),
                    upstream_port,
                    Some(Credentials {
                        username: "user".into(),
                        password: "SECRET_TOKEN".into(),
                    }),
                )
                .unwrap(),
            ),
            products: Products::default(),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            handle_client(client, &config, address.port());
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com\r\n\r\n")
            .unwrap();
        let response = read_head(&mut client, Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(status_code(&response), Some(200));
        client.write_all(b"Z").unwrap();
        let mut echoed = [0u8; 1];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"Z");
        drop(client);
        server.join().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn local_connect_uses_mock_socks5_upstream_with_rfc1929_auth_and_domain_atyp() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for round in 0..2 {
                let (mut stream, _) = upstream_listener.accept().unwrap();
                let mut greet = [0u8; 4];
                stream.read_exact(&mut greet).unwrap();
                assert_eq!(&greet, &[0x05, 0x02, 0x00, 0x02]);
                stream.write_all(&[0x05, 0x02]).unwrap();

                let mut auth_head = [0u8; 2];
                stream.read_exact(&mut auth_head).unwrap();
                assert_eq!(auth_head[0], 0x01);
                let mut u = vec![0u8; auth_head[1] as usize];
                stream.read_exact(&mut u).unwrap();
                let mut plen = [0u8; 1];
                stream.read_exact(&mut plen).unwrap();
                let mut p = vec![0u8; plen[0] as usize];
                stream.read_exact(&mut p).unwrap();
                assert_eq!(u, b"user");
                assert_eq!(p, b"secret");
                stream.write_all(&[0x01, 0x00]).unwrap();

                let mut req_head = [0u8; 5];
                stream.read_exact(&mut req_head).unwrap();
                assert_eq!(&req_head[..4], &[0x05, 0x01, 0x00, 0x03]); // ATYP=0x03 remote DNS!
                let dlen = req_head[4] as usize;
                let mut domain = vec![0u8; dlen];
                stream.read_exact(&mut domain).unwrap();
                assert_eq!(domain, b"gemini.google.com");
                let mut port_bytes = [0u8; 2];
                stream.read_exact(&mut port_bytes).unwrap();
                assert_eq!(u16::from_be_bytes(port_bytes), 443);

                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB])
                    .unwrap();
                if round == 1 {
                    let mut byte = [0u8; 1];
                    stream.read_exact(&mut byte).unwrap();
                    stream.write_all(&byte).unwrap();
                }
            }
        });

        let mut upstream = Upstream::with_protocol(
            ProxyProtocol::Http,
            "127.0.0.1".into(),
            upstream_port,
            Some(Credentials {
                username: "user".into(),
                password: "secret".into(),
            }),
        )
        .unwrap();
        let detected =
            detect_protocol_against(&mut upstream, false, VpnPolicy::Use, "gemini.google.com", 443)
                .unwrap();
        assert_eq!(detected, ProxyProtocol::Socks5);
        assert_eq!(upstream.protocol, ProxyProtocol::Socks5);

        let config = ProxyConfig {
            schema: 1,
            mode: Mode::OwnProxy,
            vpn_policy: VpnPolicy::Use,
            upstream: Some(upstream),
            products: Products::default(),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            handle_client(client, &config, address.port());
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"CONNECT gemini.google.com:443 HTTP/1.1\r\nHost: gemini.google.com\r\n\r\n")
            .unwrap();
        let response = read_head(&mut client, Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(status_code(&response), Some(200));
        client.write_all(b"Z").unwrap();
        let mut echoed = [0u8; 1];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"Z");
        drop(client);
        server.join().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn local_listener_serves_pac_file_with_selected_product_domains() {
        let mut config = ProxyConfig::default();
        config.products.chrome_gemini = false;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let port = address.port();
        let worker = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            handle_client(client, &config, port);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut full = Vec::new();
        client.read_to_end(&mut full).unwrap();
        let text = String::from_utf8(full).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("\"gemini.google.com\""));
        assert!(text.contains("\"robinfrontend-pa.googleapis.com\""));
        assert!(!text.contains("\"geminiweb-pa.googleapis.com\""));
        worker.join().unwrap();
    }

    #[test]
    fn geo_blocked_redirect_and_body_markers_are_detected() {
        assert!(is_geo_blocked_response(
            "HTTP/1.1 302 Found\r\nLocation: https://gemini.google.com/faq\r\n\r\n"
        ));
        assert!(is_geo_blocked_response(
            "HTTP/1.1 302 Found\r\nLocation: https://ai.google.dev/gemini-api/docs/available-regions\r\n\r\n"
        ));
        assert!(is_geo_blocked_response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nGemini пока не поддерживается в вашей стране"
        ));
        assert!(!is_geo_blocked_response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Gemini Chat</html>"
        ));
    }

    #[test]
    fn own_proxy_without_an_upstream_fails_closed() {
        let config = ProxyConfig {
            schema: 1,
            mode: Mode::OwnProxy,
            vpn_policy: VpnPolicy::Use,
            upstream: None,
            products: Products::default(),
        };
        assert!(open_route("daily-cloudcode-pa.googleapis.com", 443, &config).is_err());
    }
}
