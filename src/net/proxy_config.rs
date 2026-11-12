//! Per-user settings for the private Antigravity CONNECT route.
//!
//! The password never appears in a command-line argument, report or Debug output.
use serde::{Deserialize, Serialize};
use std::{fmt, fs, io::Write, path::PathBuf, str::FromStr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    OwnProxy,
    Vpn,
    SniDirect,
    Auto,
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "own-proxy" => Ok(Self::OwnProxy),
            "vpn" => Ok(Self::Vpn),
            "sni-direct" => Ok(Self::SniDirect),
            "auto" => Ok(Self::Auto),
            _ => Err("Режим: own-proxy, vpn, sni-direct или auto".into()),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OwnProxy => "own-proxy",
            Self::Vpn => "vpn",
            Self::SniDirect => "sni-direct",
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
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Credentials>,
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upstream")
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

    fn split_credentials(userinfo: &str) -> Result<Credentials, String> {
        let (username, password) = userinfo.split_once(':').ok_or(
            "Формат: login:password@ip:port, ip:port:login:password или ip:port",
        )?;
        Ok(Credentials {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Parse popular proxy formats:
    /// - `login:password@host:port` (or `http://...`)
    /// - `host:port:login:password` (including `[ipv6]:port:login:password`)
    /// - `host:port@login:password`
    /// - `host:port` without authentication
    pub fn parse(input: &str) -> Result<Self, String> {
        let raw = Self::strip_wrapping_quotes(input);
        if raw.is_empty() {
            return Err("Укажите адрес прокси (например login:password@ip:port)".into());
        }
        let raw = if raw.len() >= 7 && raw[..7].eq_ignore_ascii_case("http://") {
            &raw[7..]
        } else {
            raw
        };
        if raw.contains("://") {
            return Err("Нужен обычный HTTP CONNECT-прокси, не SOCKS и не HTTPS-прокси".into());
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
                        "Формат: login:password@ip:port, ip:port:login:password или ip:port"
                            .into(),
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
                        "Формат: login:password@ip:port, ip:port:login:password или ip:port"
                            .into(),
                    )
                }
            }
        };
        let (host, port) = Self::parse_endpoint(&address)?;
        Self::endpoint(host, port, credentials)
    }

    /// Parse only the endpoint. Credentials are deliberately kept out of argv.
    pub fn parse_endpoint(input: &str) -> Result<(String, u16), String> {
        let raw = input.trim();
        if raw.is_empty() || raw.len() > 2048 || raw.chars().any(char::is_control) {
            return Err("Укажите адрес в формате хост:порт".into());
        }
        if raw.contains('@') {
            return Err("Не передавайте логин и пароль в аргументах: они сохранятся в истории shell. Укажите только хост:порт; пароль будет запрошен отдельно".into());
        }
        let rest = raw.strip_prefix("http://").unwrap_or(raw);
        if rest.contains("://") {
            return Err("Нужен обычный HTTP CONNECT-прокси, не SOCKS и не HTTPS-прокси".into());
        }
        let hostport = rest.strip_suffix('/').unwrap_or(rest);
        if hostport.is_empty()
            || hostport.contains(['/', '?', '#'])
            || hostport.chars().any(char::is_whitespace)
        {
            return Err("Некорректный адрес HTTP-прокси".into());
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
        Ok((host.to_string(), port))
    }

    pub fn endpoint(
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
            Some(credentials) => format!("{}:***@{}:{}", credentials.username, host, self.port),
            None => format!("{host}:{}", self.port),
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
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema > 1 {
            return Err("Неподдерживаемая версия настроек прокси".into());
        }
        if let Some(upstream) = &self.upstream {
            Upstream::endpoint(
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

pub fn load() -> Result<ProxyConfig, String> {
    match fs::read(path()) {
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
    fn endpoint_parser_is_strict_and_credentials_stay_out_of_arguments() {
        assert_eq!(
            Upstream::parse_endpoint("http://proxy.example:3128").unwrap(),
            ("proxy.example".into(), 3128)
        );
        assert_eq!(
            Upstream::parse_endpoint("[2001:db8::1]:8080").unwrap(),
            ("2001:db8::1".into(), 8080)
        );
        for invalid in [
            "",
            "proxy.example",
            "https://proxy.example:443",
            "socks5://proxy.example:1080",
            "user:secret@proxy.example:3128",
            "proxy.example:0",
            "proxy.example:3128/path",
            "bad host:3128",
        ] {
            assert!(Upstream::parse_endpoint(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn combined_proxy_input_supports_credentials_and_special_password_chars() {
        let upstream = Upstream::parse("ivan:p@ss:word@proxy.example:3128").unwrap();
        assert_eq!(upstream.host, "proxy.example");
        assert_eq!(upstream.port, 3128);
        let credentials = upstream.credentials.unwrap();
        assert_eq!(credentials.username, "ivan");
        assert_eq!(credentials.password, "p@ss:word");

        let upstream = Upstream::parse("http://ivan:secret@[2001:db8::1]:8080").unwrap();
        assert_eq!(upstream.host, "2001:db8::1");
        assert_eq!(upstream.port, 8080);

        let upstream = Upstream::parse("proxy.example:3128").unwrap();
        assert!(upstream.credentials.is_none());

        let colon_fmt = Upstream::parse("185.10.20.30:8000:user1:p:a:s:s").unwrap();
        assert_eq!(colon_fmt.host, "185.10.20.30");
        assert_eq!(colon_fmt.port, 8000);
        assert_eq!(
            colon_fmt.credentials.unwrap(),
            Credentials {
                username: "user1".into(),
                password: "p:a:s:s".into(),
            }
        );

        let ipv6_colon = Upstream::parse("[2001:db8::1]:8080:ivan:secret:1").unwrap();
        assert_eq!(ipv6_colon.host, "2001:db8::1");
        assert_eq!(ipv6_colon.port, 8080);
        assert_eq!(ipv6_colon.credentials.unwrap().password, "secret:1");

        let rev_at = Upstream::parse("\"http://185.10.20.30:8000@ivan:12345\"").unwrap();
        assert_eq!(rev_at.host, "185.10.20.30");
        assert_eq!(rev_at.port, 8000);
        assert_eq!(rev_at.credentials.unwrap().username, "ivan");

        let rev_at_special = Upstream::parse("185.10.20.30:8000@ivan:p@ss").unwrap();
        assert_eq!(rev_at_special.host, "185.10.20.30");
        assert_eq!(rev_at_special.credentials.unwrap().password, "p@ss");

        for invalid in [
            "",
            "ivan@proxy.example:3128",
            ":secret@proxy.example:3128",
            "185.10.20.30:8000:onlyuser",
            "socks5://185.10.20.30:1080",
        ] {
            assert!(Upstream::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn debug_and_display_never_reveal_the_password() {
        let upstream = Upstream::endpoint(
            "proxy.example".into(),
            3128,
            Some(Credentials {
                username: "ivan".into(),
                password: "SECRET_TOKEN".into(),
            }),
        )
        .unwrap();
        assert!(!format!("{upstream:?}").contains("SECRET_TOKEN"));
        assert!(!upstream.safe_display().contains("SECRET_TOKEN"));
        let serialized = serde_json::to_string(&upstream).unwrap();
        // JSON storage necessarily contains it; logs and Debug necessarily do not.
        assert!(serialized.contains("SECRET_TOKEN"));
    }

    #[test]
    fn config_roundtrip_and_unknown_fields_are_checked() {
        let config = ProxyConfig {
            schema: 1,
            mode: Mode::OwnProxy,
            vpn_policy: VpnPolicy::Bypass,
            upstream: None,
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        assert_eq!(
            serde_json::from_slice::<ProxyConfig>(&bytes).unwrap().mode,
            Mode::OwnProxy
        );
        assert!(
            serde_json::from_slice::<ProxyConfig>(br#"{"schema":1,"unexpected":true}"#).is_err()
        );
    }
}
