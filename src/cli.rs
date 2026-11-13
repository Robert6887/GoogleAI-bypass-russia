//! Non-interactive command surface. Secrets are prompted interactively, never accepted in argv.
use crate::core::autopatch;
use crate::net::{local_proxy, proxy_config};
use std::str::FromStr;

pub fn proxy(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str) {
        Some("set") if args.len() == 2 => {
            let cfg = proxy_config::load().unwrap_or_default();
            let input = proxy_config::read_hidden(
                "SOCKS5 или HTTP прокси (ip:port:login:pass или login:pass@ip:port, ввод скрыт): ",
            )?;
            let upstream = match crate::ui::menu::parse_and_verify_proxy_input(&input, cfg.vpn_policy)
            {
                Ok(verified) => verified,
                Err(error) => {
                    eprintln!("! Автопроверка соединения не прошла ({error}); сохраняем по формату.");
                    proxy_config::Upstream::parse(&input)?
                }
            };
            proxy_config::save_upstream(upstream.clone())?;
            println!(
                "✓ Сохранено: {}. Режим: own-proxy.",
                upstream.safe_display()
            );
            println!("Проверяем доступ ко всем сервисам Google AI…");
            match local_proxy::test_upstream() {
                Ok(message) => println!("✓ {message}"),
                Err(error) => eprintln!("! Проверка предупреждает: {error}"),
            }
            if local_proxy::listener_alive() {
                println!("Локальный шлюз активен — новые запросы сразу идут через этот прокси.");
            } else {
                println!("Для наката патча и запуска шлюза выполните: sudo ag-bypass install");
            }
            Ok(())
        }
        Some("test" | "check") if args.len() == 2 => {
            let cfg = proxy_config::load()?;
            let upstream = cfg
                .upstream
                .as_ref()
                .ok_or("Сначала добавьте прокси командой: proxy set")?;
            println!(
                "Проверяем {} ко всем 6 сервисам Google AI (включая проверку региона)…",
                upstream.safe_display()
            );
            for c in local_proxy::check_all_products(Some(upstream), cfg.vpn_policy) {
                let mark = if c.ok { "✓" } else if c.geo_blocked { "!" } else { "✗" };
                println!("  {mark} {:<28} {}", c.name, c.detail);
            }
            println!("\n{}", local_proxy::test_upstream()?);
            Ok(())
        }
        Some("clear" | "delete" | "remove") if args.len() == 2 => {
            proxy_config::clear_upstream()?;
            println!("✓ Сохранённый адрес и пароль прокси полностью удалены.");
            Ok(())
        }
        Some("status") if args.len() == 2 => {
            let config = proxy_config::load()?;
            println!("Режим: {}", config.mode);
            println!("Работа с VPN: {}", config.vpn_policy);
            match config.upstream {
                Some(upstream) => println!("Прокси: {}", upstream.safe_display()),
                None => println!("Прокси: не задан"),
            }
            println!(
                "Автопатч IDE: {}",
                if autopatch::is_enabled() { "включён" } else { "выключен" }
            );
            println!(
                "Локальный шлюз: {}",
                local_proxy::saved_port()
                    .filter(|_| local_proxy::listener_alive())
                    .map(|port| format!("127.0.0.1:{port}"))
                    .unwrap_or_else(|| "выключен".into())
            );
            Ok(())
        }
        _ => Err(
            "Использование: proxy set | proxy test | proxy status | proxy clear".into(),
        ),
    }
}

pub fn mode(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("Использование: mode own-proxy|vpn|auto".into());
    }
    let mode = proxy_config::Mode::from_str(&args[1])?;
    proxy_config::set_mode(mode)?;
    println!("✓ Сохранён режим {mode}.");
    Ok(())
}

pub fn vpn(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("Использование: vpn bypass|use".into());
    }
    let policy = proxy_config::VpnPolicy::from_str(&args[1])?;
    proxy_config::set_vpn_policy(policy)?;
    println!("✓ Сохранена политика работы с VPN: {policy} (действует сразу на новые соединения).");
    Ok(())
}

pub fn autopatch_cmd(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str) {
        Some("on" | "enable") if args.len() == 2 => {
            let mut cfg = proxy_config::load()?;
            cfg.products.autopatch = true;
            cfg.products.antigravity = true;
            proxy_config::save(&cfg)?;
            autopatch::enable()?;
            println!("✓ Автопатч Antigravity включён.");
            Ok(())
        }
        Some("off" | "disable") if args.len() == 2 => {
            let mut cfg = proxy_config::load()?;
            cfg.products.autopatch = false;
            proxy_config::save(&cfg)?;
            autopatch::disable()?;
            println!("✓ Автопатч Antigravity выключен.");
            Ok(())
        }
        Some("run") if args.len() == 2 => {
            let count = autopatch::run_once()?;
            println!("✓ Проверка автопатча завершена (обновлено файлов: {count}).");
            Ok(())
        }
        Some("status") if args.len() == 2 => {
            println!(
                "Автопатч Antigravity: {}",
                if autopatch::is_enabled() { "включён" } else { "выключен" }
            );
            Ok(())
        }
        _ => Err("Использование: autopatch on | autopatch off | autopatch status | autopatch run".into()),
    }
}

pub fn chrome_gemini(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("Использование: chrome-gemini".into());
    }
    if crate::net::gemini_apps::chrome_running() {
        crate::net::gemini_apps::quit_chrome()?;
    }
    let count = crate::net::gemini_apps::unlock_chrome_glic()?;
    println!("✓ Разблокирована кнопка «Спросить Gemini» в Chrome (профилей: {count}).");
    Ok(())
}
