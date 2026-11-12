mod cli;
mod core;
mod diagnostics;
mod model_status;
mod net;
mod system;
mod ui;

use std::env;

fn print_help() {
    println!(
        "ANTIGRAVITY-BYPASS-RUSSIA (v{})\n\
        Использование: antigravity-bypass-russia [КОМАНДА] [ОПЦИИ]\n\n\
        Без аргументов запускается интерактивное меню [0-7].\n\n\
        Основные команды:\n\
          install / enable      Накатить патч и включить шлюз (Antigravity + Gemini)\n\
          proxy set             Вставить или сменить HTTP-прокси (ввод скрыт + автопроверка)\n\
          proxy test            Проверить CONNECT + TLS + HTTP через сохранённый прокси\n\
          proxy status          Показать режим и адрес прокси без пароля\n\
          proxy clear           Удалить сохранённый адрес и пароль прокси\n\
          chrome-gemini         Разблокировать «Спросить Gemini» в Chrome (Local State)\n\
          rollback / disable    Полный откат файлов, окружения и служб\n\
          doctor [--json]       Диагностика прокси и подключения\n\
          status                Показать сводку текущего статуса\n\n\
        Режимы и VPN:\n\
          mode own-proxy        Только собственный прокси для моделей, без прямого fallback\n\
          mode vpn              Прямой туннель через системный VPN\n\
          mode sni-direct       Резервный публичный DNS/SNI-режим\n\
          mode auto             Собственный прокси, при ошибке — прямое подключение\n\
          vpn bypass            Привязать новые TCP-соединения к физическому интерфейсу\n\
          vpn use               Использовать текущий маршрут ОС / VPN\n\n\
        Отдельные операции:\n\
          patch-files           Пропатчить поддерживаемые файлы [необязательный путь]\n\
          unlock                Резервный полный DNS/SNI-обход (файлы и DNS)\n\
          dns                   Настройка SmartDNS / NRPT обхода\n\
          tune                  Оптимизация сетевого стека TCP\n\
          diagnostics           Проверка подключения к серверам Google\n\
          report                Сохранить диагностику в JSON [необязательный каталог]\n\
          speed                 Показать режим прямого подключения\n\n\
        Опции:\n\
          -h, --help            Показать эту справку\n\
          -V, --version         Показать версию\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn result(action: Result<(), String>) -> ! {
    match action {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn doctor(json: bool) -> ! {
    if json {
        let mut report = diagnostics::collect();
        report["proxy"] = net::local_proxy::summary();
        if net::proxy_config::load()
            .ok()
            .and_then(|c| c.upstream)
            .is_some()
        {
            report["proxy"]["upstream_check"] = match net::local_proxy::test_upstream() {
                Ok(_) => serde_json::json!({"status": "connect_tls_http_ok"}),
                Err(_) => serde_json::json!({"status": "failed", "details": "omitted"}),
            };
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .unwrap_or_else(|_| "{\"error\":\"serialization\"}".into())
        );
        std::process::exit(0);
    }
    let ok = ui::menu::handle_diagnostics();
    std::process::exit(if ok { 0 } else { 1 });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    #[cfg(target_os = "macos")]
    if command == "--endpoint-session" {
        if let Err(error) = core::endpoint_session::restore() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if command == system::FORWARDER_FLAG {
        net::detach_console();
        if let Err(e) = net::run_dns_relay() {
            net::log_fatal(&e);
            std::process::exit(1);
        }
        return;
    }
    if command == net::local_proxy::LOCAL_PROXY_FLAG {
        if let Err(error) = net::local_proxy::run() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    ui::init_terminal();
    if matches!(command, "-h" | "--help" | "help") {
        print_help();
        return;
    }
    if matches!(command, "-V" | "--version" | "version") {
        println!("antigravity-bypass-russia v{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    match command {
        "proxy" => result(cli::proxy(&args[1..])),
        "mode" => result(cli::mode(&args[1..])),
        "vpn" => result(cli::vpn(&args[1..])),
        "chrome-gemini" => result(cli::chrome_gemini(&args[1..])),
        "doctor" if args.len() == 2 => doctor(false),
        "doctor" if args.len() == 3 && args[2] == "--json" => doctor(true),
        "doctor" => {
            eprintln!("Использование: doctor [--json]");
            std::process::exit(2);
        }
        _ => {}
    }

    if command == "status" && args.len() == 2 {
        ui::dashboard::print_dashboard();
        return;
    }
    if command == "speed" && args.len() == 2 {
        std::process::exit(if ui::speed::run() { 0 } else { 1 });
    }
    if command == "diagnostics" && args.len() == 2 {
        let ok = ui::menu::handle_diagnostics();
        std::process::exit(if ok { 0 } else { 1 });
    }
    if command == "report" && args.len() <= 3 {
        let directory = args.get(2).map(std::path::Path::new);
        let ok = ui::menu::handle_save_diagnostics(directory);
        std::process::exit(if ok { 0 } else { 1 });
    }

    let valid = matches!(
        command,
        "" | "install"
            | "enable"
            | "disable"
            | "unlock"
            | "patch-files"
            | "dns"
            | "rollback"
            | "restore"
            | "tune"
            | "--tune"
    );
    if !valid {
        eprintln!("Неизвестная команда или лишние аргументы: {command}. См. --help");
        std::process::exit(2);
    }
    if args.len()
        > if matches!(command, "patch-files" | "rollback" | "restore") {
            3
        } else if command.is_empty() {
            1
        } else {
            2
        }
    {
        eprintln!("Лишние аргументы. См. --help");
        std::process::exit(2);
    }
    system::ensure_admin();
    if !system::check_single_instance() {
        eprintln!("Уже выполняется другая операция обходчика");
        std::process::exit(1);
    }
    let ok = match command {
        "install" | "enable" => ui::menu::handle_proxy_enable(),
        "unlock" => ui::menu::handle_unlock_all(),
        "patch-files" => ui::menu::handle_patch_files_only(),
        "dns" => ui::menu::handle_dns_only(),
        "disable" | "rollback" | "restore" => ui::menu::handle_rollback(),
        "tune" | "--tune" => match net::socket::tune_os_network_stack() {
            Ok(logs) => {
                for log in logs {
                    println!("{log}");
                }
                println!("{}", net::socket::get_os_network_status());
                true
            }
            Err(e) => {
                eprintln!("{e}");
                false
            }
        },
        _ => {
            ui::run_app();
            true
        }
    };
    std::process::exit(if ok { 0 } else { 1 });
}
