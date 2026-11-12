use crate::core::detector::get_quick_status;
use crate::core::patcher::BinaryState;

pub fn banner() {
    println!(
        "\x1b[96m=====================================================================\x1b[0m"
    );
    println!(
        "\x1b[96m{:^69}\x1b[0m",
        format!("ANTIGRAVITY-BYPASS-RUSSIA (v{})", env!("CARGO_PKG_VERSION"))
    );
    println!(
        "\x1b[96m=====================================================================\x1b[0m"
    );
    println!(" Открытая утилита обхода блокировок и чистого отката\n");
}

pub fn print_dashboard() {
    let (rules, _, _) = crate::net::nrpt::get_nrpt_status_info();
    let running = crate::system::service::running_state();
    let status = get_quick_status();
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
    let proxy = crate::net::local_proxy::summary();
    let listener_on = proxy["listener"] == true;
    let pac_on = proxy["pac_enabled"] == true;
    let local_port = proxy["local_port"].as_u64().unwrap_or(0);
    let network = if listener_on && pac_on {
        format!("\x1b[92mВключён (шлюз + PAC :{local_port})\x1b[0m")
    } else if listener_on {
        format!("\x1b[92mВключён (шлюз :{local_port})\x1b[0m")
    } else if running.is_err() {
        "\x1b[93mНе удалось проверить службу\x1b[0m".into()
    } else if rules > 0 && running == Ok(true) {
        "\x1b[92mВключён (DNS-маршрут)\x1b[0m".into()
    } else if rules > 0 {
        "\x1b[93mНужна проверка\x1b[0m".into()
    } else {
        "\x1b[90mВыключен\x1b[0m".into()
    };
    status_row("Обход:", &network);
    let proxy_status = match crate::net::proxy_config::load().ok() {
        Some(cfg) if cfg.upstream.is_some() => {
            let safe = cfg.upstream.as_ref().unwrap().safe_display();
            if listener_on {
                format!("\x1b[92m{safe} ({})\x1b[0m", cfg.vpn_policy)
            } else {
                format!("\x1b[93m{safe} (шлюз выкл.)\x1b[0m")
            }
        }
        Some(cfg) if cfg.mode == crate::net::proxy_config::Mode::Vpn => {
            if listener_on {
                "\x1b[92mрежим VPN (без прокси)\x1b[0m".into()
            } else {
                "\x1b[90mрежим VPN; шлюз выключен\x1b[0m".into()
            }
        }
        Some(cfg) if cfg.mode == crate::net::proxy_config::Mode::SniDirect => {
            "\x1b[90mпубличный DNS (без прокси)\x1b[0m".into()
        }
        _ => {
            if listener_on {
                "\x1b[93mне задан — выберите [2]\x1b[0m".into()
            } else {
                "\x1b[90mне задан — выберите [2]\x1b[0m".into()
            }
        }
    };
    status_row("Свой прокси:", &proxy_status);
    status_row("Antigravity:", component_status(status.core_status));
    let ide = if !status.incomplete_ide_installations.is_empty() {
        "\x1b[93mПереустановите Antigravity IDE\x1b[0m"
    } else if !status.ide_installations.is_empty() {
        "\x1b[92mУстановлена\x1b[0m"
    } else {
        "\x1b[90mНе найдена\x1b[0m"
    };
    status_row("Antigravity IDE:", ide);
    let cli = if status.cli_status.is_none() && !status.cli_launchers.is_empty() {
        "\x1b[93mНужна проверка\x1b[0m"
    } else {
        component_status(status.cli_status)
    };
    status_row("Antigravity CLI:", cli);
    let model = crate::model_status::snapshot();
    let colour = if model.warning() {
        "\x1b[93m"
    } else {
        "\x1b[90m"
    };
    status_row(
        "Модель (журнал):",
        &format!("{colour}{}\x1b[0m", model.label()),
    );
    println!("\x1b[90m│{}│\x1b[0m", " ".repeat(67));
    println!("\x1b[90m╰{}╯\x1b[0m\n", "─".repeat(67));
}

fn component_status(status: Option<BinaryState>) -> &'static str {
    match status {
        Some(BinaryState::Patched) => "\x1b[92mПропатчено\x1b[0m",
        Some(BinaryState::Stock) => "\x1b[93mНе пропатчено\x1b[0m",
        Some(BinaryState::PartiallyPatched | BinaryState::Unknown) => {
            "\x1b[93mНужна проверка\x1b[0m"
        }
        None => "\x1b[90mНе найдено\x1b[0m",
    }
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
        let long = "\x1b[92mvery_long_username_12345:***@subdomain.proxy-provider.example.com:65535 (bypass-vpn)\x1b[0m";
        let rendered = format_status_row("Свой прокси:", long);
        let plain = regex::Regex::new(r"\x1b\[[0-9;]*m")
            .unwrap()
            .replace_all(&rendered, "");
        assert_eq!(plain.chars().count(), 69, "{plain}");
    }
}
