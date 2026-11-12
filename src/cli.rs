//! Non-interactive command surface. Secrets are prompted for, never accepted in argv.
use crate::net::{local_proxy, proxy_config};
use std::str::FromStr;

pub fn proxy(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str) {
        Some("set") if args.len() == 2 => {
            let input = proxy_config::read_hidden(
                "HTTP-прокси (login:pass@ip:port или ip:port:login:pass, ввод скрыт): ",
            )?;
            let upstream = proxy_config::Upstream::parse(&input)?;
            proxy_config::save_upstream(upstream.clone())?;
            println!(
                "✓ Сохранено: {}. Режим: own-proxy.",
                upstream.safe_display()
            );
            println!("Проверяем соединение до Google через прокси…");
            match local_proxy::test_upstream() {
                Ok(message) => println!("✓ {message}"),
                Err(error) => {
                    eprintln!("! Прокси сохранён, но проверка сейчас не прошла: {error}");
                }
            }
            if local_proxy::summary()["listener"] == true {
                println!("Локальный шлюз активен — новые запросы сразу пойдут через этот прокси.");
            } else {
                println!("Чтобы накатить патч и запустить шлюз, откройте меню или выполните: sudo … install");
            }
            Ok(())
        }
        Some("test") if args.len() == 2 => {
            println!("Проверяем HTTP CONNECT, TLS и HTTP через сохранённый прокси…");
            println!("{}", local_proxy::test_upstream()?);
            Ok(())
        }
        Some("clear") if args.len() == 2 => {
            proxy_config::clear_upstream()?;
            println!("Адрес и пароль прокси удалены из настроек; выбран режим auto.");
            Ok(())
        }
        Some("status") if args.len() == 2 => {
            let config = proxy_config::load()?;
            println!("Режим: {}", config.mode);
            println!("VPN: {}", config.vpn_policy);
            match config.upstream {
                Some(upstream) => println!("Прокси: {}", upstream.safe_display()),
                None => println!("Прокси: не настроен"),
            }
            println!(
                "Локальный порт: {}",
                local_proxy::saved_port()
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "не запущен".into())
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
        return Err("Использование: mode own-proxy|vpn|sni-direct|auto".into());
    }
    let mode = proxy_config::Mode::from_str(&args[1])?;
    proxy_config::set_mode(mode)?;
    println!("Сохранён режим {mode}. Применение: sudo … install");
    Ok(())
}

pub fn vpn(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("Использование: vpn use|bypass".into());
    }
    let policy = proxy_config::VpnPolicy::from_str(&args[1])?;
    proxy_config::set_vpn_policy(policy)?;
    println!("Сохранена политика {policy}. Действует на новые соединения локального прокси.");
    Ok(())
}

pub fn chrome_gemini(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("Использование: chrome-gemini".into());
    }
    if crate::net::gemini_apps::chrome_running() {
        crate::net::gemini_apps::quit_chrome()?;
    }
    let count = crate::net::gemini_apps::unlock_chrome_glic()?;
    println!("✓ Разблокирован встроенный Gemini в Chrome (профилей: {count}).");
    println!("Важно: для встроенной панели «Спросить Gemini» обычно нужен IP США и личный @gmail.com аккаунт.");
    Ok(())
}
