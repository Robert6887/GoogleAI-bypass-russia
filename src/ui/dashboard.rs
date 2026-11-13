use crate::core::autopatch;
use crate::core::detector::get_quick_status;
use crate::core::patcher::BinaryState;
use crate::net::{gemini_apps, local_proxy, proxy_config};

pub fn banner() {
    println!(
        "\x1b[96m=====================================================================\x1b[0m"
    );
    println!(
        "\x1b[96m{:^69}\x1b[0m",
        format!("ANTIGRAVITY & GEMINI BYPASS (v{})", env!("CARGO_PKG_VERSION"))
    );
    println!(
        "\x1b[96m=====================================================================\x1b[0m"
    );
    println!(" Разблокировка сервисов Google AI через SOCKS5 / HTTP-прокси и автопатч\n");
}

pub fn print_dashboard() {
    let status = get_quick_status();
    let cfg = proxy_config::load().unwrap_or_default();
    let proxy = local_proxy::summary();
    let listener_on = proxy["listener"] == true;
    let pac_on = proxy["pac_enabled"] == true;
    let local_port = proxy["local_port"].as_u64().unwrap_or(0);

    let title = " ТЕКУЩИЙ СТАТУС ";
    let left = (67 - title.chars().count()) / 2;
    let right = 67 - title.chars().count() - left;
    println!(
        "\x1b[90m╭{}\x1b[96m{}\x1b[90m{}╮\x1b[0m",
        "─".repeat(left),
        title,
        "─".repeat(right)
    );
    println!("\x1b[90m│{}│\x1b[0m", " ".repeat(67));

    let vpn_tag = match cfg.vpn_policy {
        proxy_config::VpnPolicy::Bypass => "обход корп. VPN",
        proxy_config::VpnPolicy::Use => "через VPN",
    };
    let proxy_status = match &cfg.upstream {
        Some(upstream) if listener_on => {
            format!("\x1b[92m{} ({vpn_tag})\x1b[0m", upstream.safe_display())
        }
        Some(upstream) => format!("\x1b[93m{} (шлюз выкл.)\x1b[0m", upstream.safe_display()),
        None if cfg.mode == proxy_config::Mode::Vpn && listener_on => {
            "\x1b[92mсистемный VPN (без отдельного прокси)\x1b[0m".into()
        }
        None if cfg.mode == proxy_config::Mode::Vpn => {
            "\x1b[93mрежим VPN (шлюз не запущен)\x1b[0m".into()
        }
        None => "\x1b[90mне задан — выберите пункт [1] или [2]\x1b[0m".into(),
    };
    status_row("Свой прокси:", &proxy_status);

    let ag_status = if !status.incomplete_ide_installations.is_empty() {
        "\x1b[93mПереустановите Antigravity IDE\x1b[0m".into()
    } else {
        match status.core_status {
            Some(BinaryState::Patched) if listener_on => {
                format!("\x1b[92mРазблокирована (шлюз :{local_port})\x1b[0m")
            }
            Some(BinaryState::Patched) => "\x1b[93mПропатчена (шлюз выключен)\x1b[0m".into(),
            Some(BinaryState::Stock) => "\x1b[93mНе пропатчена — выберите [1]\x1b[0m".into(),
            Some(BinaryState::PartiallyPatched | BinaryState::Unknown) => {
                "\x1b[93mНужна проверка в пункте [1]\x1b[0m".into()
            }
            None => "\x1b[90mНе найдена\x1b[0m".into(),
        }
    };
    status_row("Antigravity IDE:", &ag_status);

    let autopatch_status = if autopatch::is_enabled() {
        "\x1b[92mВключён (обновляет патч сам)\x1b[0m"
    } else {
        "\x1b[90mВыключен\x1b[0m"
    };
    status_row("Автопатч IDE:", autopatch_status);

    let desktop_installed = std::path::Path::new("/Applications/Gemini.app").exists();
    let sni_on = proxy["sni_relay"] == true;
    let desktop_ready = listener_on
        && pac_on
        && cfg.products.gemini_desktop
        && (sni_on || cfg.mode == proxy_config::Mode::Vpn);
    let desktop_status = if desktop_ready {
        "\x1b[92mРазблокирован (SNI-шлюз + PAC)\x1b[0m"
    } else if listener_on && cfg.products.gemini_desktop {
        "\x1b[93mНужно обновить шлюз в пункте [1]\x1b[0m"
    } else if desktop_installed {
        "\x1b[93mУстановлен (не включён в [1])\x1b[0m"
    } else {
        "\x1b[90mВыключен\x1b[0m"
    };
    status_row("Gemini Desktop:", desktop_status);

    let web_status = if listener_on && pac_on && cfg.products.gemini_web {
        "\x1b[92mРазблокирован (Gemini + AI Studio)\x1b[0m"
    } else {
        "\x1b[90mВыключен\x1b[0m"
    };
    status_row("Gemini Браузер:", web_status);

    let chrome_status = if !gemini_apps::chrome_installed() {
        "\x1b[90mGoogle Chrome не найден\x1b[0m"
    } else if !gemini_apps::chrome_glic_needs_unlock() && listener_on && pac_on && cfg.products.chrome_gemini {
        "\x1b[92mРазблокирован («Спросить Gemini»)\x1b[0m"
    } else if !gemini_apps::chrome_glic_needs_unlock() {
        "\x1b[93mФлаг включён (нужен шлюз в [1])\x1b[0m"
    } else {
        "\x1b[90mНе разблокирован\x1b[0m"
    };
    status_row("Gemini в Chrome:", chrome_status);

    println!("\x1b[90m│{}│\x1b[0m", " ".repeat(67));
    println!("\x1b[90m╰{}╯\x1b[0m\n", "─".repeat(67));
}

// Pad the visible text, not ANSI colour sequences, to keep the right border straight.
fn format_status_row(label: &str, status: &str) -> String {
    let (colour, icon) = if status.starts_with("\x1b[92m") {
        ("\x1b[92m", "✓")
    } else if status.starts_with("\x1b[93m") {
        ("\x1b[93m", "!")
    } else {
        ("\x1b[90m", "–")
    };
    let raw_text = status
        .strip_prefix(colour)
        .unwrap_or(status)
        .strip_suffix("\x1b[0m")
        .unwrap_or(status);
    let prefix = format!("  {label:<18} ");
    let max_text = 66usize.saturating_sub(prefix.chars().count() + 4);
    let text = if raw_text.chars().count() > max_text && max_text > 1 {
        let head: String = raw_text.chars().take(max_text - 1).collect();
        format!("{head}…")
    } else {
        raw_text.to_string()
    };
    let padding = 67usize.saturating_sub(prefix.chars().count() + 4 + text.chars().count());
    format!(
        "\x1b[90m│\x1b[0m{prefix}{colour}[{icon}] {text}\x1b[0m{}\x1b[90m│\x1b[0m",
        " ".repeat(padding)
    )
}

fn status_row(label: &str, status: &str) {
    println!("{}", format_status_row(label, status));
}

#[cfg(test)]
mod tests {
    use super::format_status_row;

    #[test]
    fn long_proxy_labels_truncate_cleanly_without_breaking_frame_width() {
        let long = "\x1b[92mSOCKS5 very_long_username_12345:***@subdomain.proxy-provider.example.com:65535 (обход корп. VPN)\x1b[0m";
        let rendered = format_status_row("Свой прокси:", long);
        let plain = regex::Regex::new(r"\x1b\[[0-9;]*m")
            .unwrap()
            .replace_all(&rendered, "");
        assert_eq!(plain.chars().count(), 69, "{plain}");
    }
}
