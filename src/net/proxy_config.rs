//! Per-user settings for the private local SOCKS5 / HTTP CONNECT gateway and selected products.
//!
//! Passwords never appear in command-line arguments, diagnostic reports, or Debug output.
use serde::{Deserialize, Serialize};
use std::{fmt, fs, io::Write, path::PathBuf, str::FromStr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    #[default]
    Http,
    #[serde(alias = "socks", alias = "socks5h")]
    Socks5,
}

impl ProxyProtocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Socks5 => "SOCKS5",
        }
    }
}

impl FromStr for ProxyProtocol {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "http" | "http-connect" => Ok(Self::Http),
            "socks5" | "socks5h" | "socks" => Ok(Self::Socks5),
            _ => Err("Протокол прокси: socks5 или http".into()),
        }
    }
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    OwnProxy,
    Vpn,
    #[serde(alias = "sni-direct")]
    Auto,
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "own-proxy" => Ok(Self::OwnProxy),
            "vpn" => Ok(Self::Vpn),
            "auto" => Ok(Self::Auto),
            _ => Err("Режим: own-proxy, vpn или auto".into()),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OwnProxy => "own-proxy",
            Self::Vpn => "vpn",
            Self::Auto => "auto",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpnPolicy {
    Use,
    #[default]
    Bypass,
}

impl FromStr for VpnPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "use" | "use-vpn" => Ok(Self::Use),
            "bypass" | "bypass-vpn" => Ok(Self::Bypass),
            _ => Err("Политика VPN: use или bypass".into()),
        }
    }
}

impl fmt::Display for VpnPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Use => "use-vpn",
            Self::Bypass => "bypass-vpn",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Products {
    pub antigravity: bool,
    pub autopatch: bool,
    pub gemini_desktop: bool,
    pub gemini_web: bool,
    pub chrome_gemini: bool,
}

impl Default for Products {
    fn default() -> Self {
        Self {
            antigravity: true,
            autopatch: true,
            gemini_desktop: true,
            gemini_web: true,
            chrome_gemini: true,
        }
    }
}

impl Products {
    pub fn needs_system_pac(&self) -> bool {
        self.gemini_desktop || self.gemini_web || self.chrome_gemini
    }

    pub fn needs_local_gateway(&self) -> bool {
        self.antigravity || self.needs_system_pac()
    }

    pub fn any_selected(&self) -> bool {
        self.antigravity
            || self.autopatch
            || self.gemini_desktop
            || self.gemini_web
            || self.chrome_gemini
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"[скрыт]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default)]
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Credentials>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedUpstream {
    pub upstream: Upstream,
    pub protocol_explicit: bool,
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upstream")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "[скрыты]"),
            )
            .finish()
    }
}

impl Upstream {
    fn looks_like_host(host: &str) -> bool {
        host.contains('.') || host.contains(':') || host.eq_ignore_ascii_case("localhost")
    }

    fn strip_wrapping_quotes(raw: &str) -> &str {
        let trimmed = raw.trim();
        if trimmed.len() >= 2
            && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
        {
            trimmed[1..trimmed.len() - 1].trim()
        } else {
            trimmed
        }
    }

    fn extract_scheme(raw: &str) -> Result<(ProxyProtocol, bool, &str), String> {
        if let Some((scheme, rest)) = raw.split_once("://") {
            match scheme.to_ascii_lowercase().as_str() {
                "http" => Ok((ProxyProtocol::Http, true, rest)),
                "socks5" | "socks5h" | "socks" => Ok((ProxyProtocol::Socks5, true, rest)),
                _ => Err(
                    "Поддерживаются SOCKS5 (socks5://...) и HTTP (http://...), либо просто ip:port:login:password"
                        .into(),
                ),
            }
        } else {
            Ok((ProxyProtocol::Http, false, raw))
        }
    }

    fn split_credentials(userinfo: &str) -> Result<Credentials, String> {
        let (username, password) = userinfo.split_once(':').ok_or(
            "Формат: socks5://login:pass@ip:port, login:pass@ip:port, ip:port:login:pass или ip:port",
        )?;
        Ok(Credentials {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Parse popular SOCKS5 / HTTP proxy formats and remember whether the scheme was explicit:
    /// - `socks5://login:password@host:port` / `http://login:password@host:port`
    /// - `login:password@host:port`
    /// - `host:port:login:password` (including `[ipv6]:port:login:password`)
    /// - `host:port@login:password`
    /// - `host:port` without authentication
    pub fn parse_with_hint(input: &str) -> Result<ParsedUpstream, String> {
        let raw = Self::strip_wrapping_quotes(input);
        if raw.is_empty() {
            return Err("Укажите адрес прокси (например ip:port:login:password)".into());
        }
        let (protocol, protocol_explicit, raw) = Self::extract_scheme(raw)?;
        if raw.is_empty() {
            return Err("После схемы укажите адрес прокси (например ip:port)".into());
        }
        let (credentials, address) = if raw.contains('@') {
            let (left, right) = raw.rsplit_once('@').unwrap();
            let first_is_endpoint = raw
                .split_once('@')
                .is_some_and(|(first, _)| Self::parse_endpoint(first).is_ok());
            if let Ok((host, _)) = Self::parse_endpoint(right) {
                if Self::looks_like_host(&host) || !first_is_endpoint {
                    (Some(Self::split_credentials(left)?), right.to_string())
                } else {
                    let (endpoint, userinfo) = raw.split_once('@').unwrap();
                    (Some(Self::split_credentials(userinfo)?), endpoint.to_string())
                }
            } else if let Some((endpoint, userinfo)) = raw.split_once('@') {
                if Self::parse_endpoint(endpoint).is_ok() {
                    (Some(Self::split_credentials(userinfo)?), endpoint.to_string())
                } else {
                    return Err(
                        "Формат: login:password@ip:port, ip:port:login:password или ip:port".into(),
                    );
                }
            } else {
                return Err(
                    "Формат: login:password@ip:port, ip:port:login:password или ip:port".into(),
                );
            }
        } else if let Some(bracketed) = raw.strip_prefix('[') {
            let (ipv6_host, tail) = bracketed
                .split_once(']')
                .ok_or("Нет закрывающей скобки IPv6-адреса")?;
            let after = tail
                .strip_prefix(':')
                .ok_or("После IPv6-адреса нужен :порт")?;
            match after.split_once(':') {
                None => (None, raw.to_string()),
                Some((port_str, userinfo)) => (
                    Some(Self::split_credentials(userinfo)?),
                    format!("[{ipv6_host}]:{port_str}"),
                ),
            }
        } else {
            let parts: Vec<&str> = raw.splitn(4, ':').collect();
            match parts.as_slice() {
                [_, _] => (None, raw.to_string()),
                [host, port, username, password] => (
                    Some(Credentials {
                        username: (*username).to_string(),
                        password: (*password).to_string(),
                    }),
                    format!("{host}:{port}"),
                ),
                _ => {
                    return Err(
                        "Формат: login:password@ip:port, ip:port:login:password или ip:port".into(),
                    )
                }
            }
        };
        let (host, port) = Self::parse_endpoint(&address)?;
        let upstream = Self::with_protocol(protocol, host, port, credentials)?;
        Ok(ParsedUpstream {
            upstream,
            protocol_explicit,
        })
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        Ok(Self::parse_with_hint(input)?.upstream)
    }

    /// Parse only the endpoint (optionally prefixed with `socks5://` or `http://`).
    /// Credentials are deliberately kept out of argv.
    pub fn parse_endpoint_with_protocol(
        input: &str,
    ) -> Result<(ProxyProtocol, bool, String, u16), String> {
        let raw = input.trim();
        if raw.is_empty() || raw.len() > 2048 || raw.chars().any(char::is_control) {
            return Err("Укажите адрес в формате хост:порт".into());
        }
        if raw.contains('@') {
            return Err("Не передавайте логин и пароль в аргументах: они сохранятся в истории shell. Укажите только хост:порт; пароль будет запрошен отдельно".into());
        }
        let (protocol, explicit, rest) = Self::extract_scheme(raw)?;
        let hostport = rest.strip_suffix('/').unwrap_or(rest);
        if hostport.is_empty()
            || hostport.contains(['/', '?', '#'])
            || hostport.chars().any(char::is_whitespace)
        {
            return Err("Некорректный адрес прокси".into());
        }
        let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or("Нет закрывающей скобки IPv6-адреса")?;
            let port = tail
                .strip_prefix(':')
                .ok_or("После IPv6-адреса нужен :порт")?;
            (host, port)
        } else {
            hostport
                .rsplit_once(':')
                .ok_or("Не указан порт; формат: хост:порт")?
        };
        if host.is_empty()
            || host.len() > 253
            || host.contains(['[', ']'])
            || (host.parse::<std::net::Ipv6Addr>().is_err()
                && !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')))
        {
            return Err("Некорректное имя или IP-адрес прокси".into());
        }
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or("Порт должен быть числом от 1 до 65535")?;
        Ok((protocol, explicit, host.to_string(), port))
    }

    pub fn parse_endpoint(input: &str) -> Result<(String, u16), String> {
        let (_, _, host, port) = Self::parse_endpoint_with_protocol(input)?;
        Ok((host, port))
    }

    #[cfg(test)]
    pub fn endpoint(
        host: String,
        port: u16,
        credentials: Option<Credentials>,
    ) -> Result<Self, String> {
        Self::with_protocol(ProxyProtocol::Http, host, port, credentials)
    }

    pub fn with_protocol(
        protocol: ProxyProtocol,
        host: String,
        port: u16,
        credentials: Option<Credentials>,
    ) -> Result<Self, String> {
        let (valid_host, valid_port) = Self::parse_endpoint(&if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        })?;
        if let Some(credentials) = &credentials {
            if credentials.username.is_empty()
                || credentials.username.len() > 1024
                || credentials.password.len() > 4096
                || credentials
                    .username
                    .chars()
                    .chain(credentials.password.chars())
                    .any(char::is_control)
            {
                return Err("Некорректные логин или пароль прокси".into());
            }
        }
        Ok(Self {
            protocol,
            host: valid_host,
            port: valid_port,
            credentials,
        })
    }

    pub fn safe_display(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.credentials {
            Some(credentials) => format!(
                "{} {}:***@{}:{}",
                self.protocol.label(),
                credentials.username,
                host,
                self.port
            ),
            None => format!("{} {host}:{}", self.protocol.label(), self.port),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub schema: u32,
    pub mode: Mode,
    pub vpn_policy: VpnPolicy,
    pub upstream: Option<Upstream>,
    pub products: Products,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema > 2 {
            return Err("Неподдерживаемая версия настроек прокси".into());
        }
        if let Some(upstream) = &self.upstream {
            Upstream::with_protocol(
                upstream.protocol,
                upstream.host.clone(),
                upstream.port,
                upstream.credentials.clone(),
            )?;
        }
        Ok(())
    }

    pub fn normalized(mut self) -> Self {
        self.schema = 1;
        self
    }
}

pub fn path() -> PathBuf {
    super::config::directory().join("proxy.json")
}

pub fn load_from_path(file: &std::path::Path) -> Result<ProxyConfig, String> {
    match fs::read(file) {
        Ok(bytes) => {
            let config: ProxyConfig = serde_json::from_slice(&bytes).map_err(|_| {
                "Файл настроек прокси повреждён; пароль в отчёт не включается".to_string()
            })?;
            config.validate()?;
            Ok(config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ProxyConfig::default()),
        Err(error) => Err(format!("Не прочитать настройки прокси: {error}")),
    }
}

pub fn load() -> Result<ProxyConfig, String> {
    load_from_path(&path())
}

pub fn save(config: &ProxyConfig) -> Result<(), String> {
    config.validate()?;
    super::config::ensure_directory()?;
    let path = path();
    let bytes =
        serde_json::to_vec_pretty(&config.clone().normalized()).map_err(|e| e.to_string())?;
    crate::system::fs_utils::robust_write_file(&path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Права на файл с паролем: {e}"))?;
    }
    super::config::inherit_directory_owner(&path)?;
    Ok(())
}

pub fn save_upstream(upstream: Upstream) -> Result<(), String> {
    let mut config = load()?;
    config.upstream = Some(upstream);
    config.mode = Mode::OwnProxy;
    save(&config)
}

pub fn clear_upstream() -> Result<(), String> {
    let mut config = load()?;
    config.upstream = None;
    if config.mode == Mode::OwnProxy {
        config.mode = Mode::Auto;
    }
    save(&config)
}

pub fn set_mode(mode: Mode) -> Result<(), String> {
    let mut config = load()?;
    config.mode = mode;
    save(&config)
}

pub fn set_vpn_policy(policy: VpnPolicy) -> Result<(), String> {
    let mut config = load()?;
    config.vpn_policy = policy;
    save(&config)
}

pub fn read_hidden(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        let disabled = std::process::Command::new("/bin/stty")
            .arg("-echo")
            .status()
            .map_err(|e| format!("Не отключить отображение пароля: {e}"))?
            .success();
        let mut value = String::new();
        let read = std::io::stdin().read_line(&mut value);
        if disabled {
            let _ = std::process::Command::new("/bin/stty").arg("echo").status();
            println!();
        }
        read.map_err(|e| format!("Не прочитать пароль: {e}"))?;
        Ok(value.trim_end_matches(['\r', '\n']).to_string())
    }
    #[cfg(not(unix))]
    {
        let mut value = String::new();
        std::io::stdin()
            .read_line(&mut value)
            .map_err(|e| format!("Не прочитать пароль: {e}"))?;
        Ok(value.trim_end_matches(['\r', '\n']).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parser_supports_socks5_and_http_and_keeps_credentials_out_of_arguments() {
        assert_eq!(
            Upstream::parse_endpoint_with_protocol("http://proxy.example:3128").unwrap(),
            (ProxyProtocol::Http, true, "proxy.example".into(), 3128)
        );
        assert_eq!(
            Upstream::parse_endpoint_with_protocol("socks5://proxy.example:1080").unwrap(),
            (ProxyProtocol::Socks5, true, "proxy.example".into(), 1080)
        );
        assert_eq!(
            Upstream::parse_endpoint_with_protocol("socks5h://[2001:db8::1]:1080").unwrap(),
            (ProxyProtocol::Socks5, true, "2001:db8::1".into(), 1080)
        );
        assert_eq!(
            Upstream::parse_endpoint_with_protocol("proxy.example:1080").unwrap(),
            (ProxyProtocol::Http, false, "proxy.example".into(), 1080)
        );
        for invalid in [
            "",
            "proxy.example",
            "https://proxy.example:443",
            "socks4://proxy.example:1080",
            "user:secret@proxy.example:3128",
            "proxy.example:0",
            "proxy.example:3128/path",
            "bad host:3128",
        ] {
            assert!(Upstream::parse_endpoint(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn combined_proxy_input_supports_socks5_http_and_schemeless_formats() {
        let parsed = Upstream::parse_with_hint("socks5://ivan:p@ss:word@proxy.example:1080").unwrap();
        assert!(parsed.protocol_explicit);
        assert_eq!(parsed.upstream.protocol, ProxyProtocol::Socks5);
        assert_eq!(parsed.upstream.host, "proxy.example");
        assert_eq!(parsed.upstream.port, 1080);
        assert_eq!(parsed.upstream.credentials.unwrap().password, "p@ss:word");

        let colon_fmt = Upstream::parse_with_hint("185.10.20.30:1080:user1:p:a:s:s").unwrap();
        assert!(!colon_fmt.protocol_explicit);
        assert_eq!(colon_fmt.upstream.host, "185.10.20.30");
        assert_eq!(colon_fmt.upstream.port, 1080);
        assert_eq!(colon_fmt.upstream.credentials.unwrap().password, "p:a:s:s");

        let socks_colon = Upstream::parse_with_hint("socks://185.10.20.30:1080:user1:secret").unwrap();
        assert!(socks_colon.protocol_explicit);
        assert_eq!(socks_colon.upstream.protocol, ProxyProtocol::Socks5);

        let rev_at = Upstream::parse("\"http://185.10.20.30:8000@ivan:12345\"").unwrap();
        assert_eq!(rev_at.protocol, ProxyProtocol::Http);
        assert_eq!(rev_at.host, "185.10.20.30");
        assert_eq!(rev_at.credentials.unwrap().username, "ivan");

        for invalid in [
            "",
            "ivan@proxy.example:3128",
            ":secret@proxy.example:3128",
            "185.10.20.30:8000:onlyuser",
            "https://185.10.20.30:443",
        ] {
            assert!(Upstream::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn debug_display_and_legacy_config_migration_work_cleanly() {
        let upstream = Upstream::with_protocol(
            ProxyProtocol::Socks5,
            "proxy.example".into(),
            1080,
            Some(Credentials {
                username: "ivan".into(),
                password: "SECRET_TOKEN".into(),
            }),
        )
        .unwrap();
        assert!(!format!("{upstream:?}").contains("SECRET_TOKEN"));
        assert!(!upstream.safe_display().contains("SECRET_TOKEN"));
        assert!(upstream.safe_display().starts_with("SOCKS5 "));

        // Old schema-1 configs with sni-direct or without `products` / `protocol` migrate cleanly.
        let legacy = br#"{"schema":1,"mode":"sni-direct","vpn_policy":"bypass","upstream":{"host":"1.2.3.4","port":8080}}"#;
        let parsed: ProxyConfig = serde_json::from_slice(legacy).unwrap();
        assert_eq!(parsed.mode, Mode::Auto);
        assert_eq!(parsed.upstream.unwrap().protocol, ProxyProtocol::Http);
        assert!(parsed.products.antigravity && parsed.products.autopatch);
        assert!(
            serde_json::from_slice::<ProxyConfig>(br#"{"schema":1,"unexpected":true}"#).is_err()
        );
    }
}
