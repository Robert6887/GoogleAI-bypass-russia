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
        "ANTIGRAVITY & GEMINI BYPASS (v{})\n\
        Использование: antigravity-bypass-russia [КОМАНДА] [ОПЦИИ]\n\n\
        Без аргументов запускается понятное пошаговое меню [0-5].\n\n\
        Основные команды:\n\
          install / enable      Настроить разблокировку продуктов (Antigravity, автопатч, Gemini)\n\
          proxy set             Вставить или заменить SOCKS5 / HTTP прокси (автоопределение протокола)\n\
          proxy test            Чекер прокси: пинг и проверка региона по всем 6 серверам Google\n\
          proxy clear           Удалить сохранённый прокси и пароль\n\
          proxy status          Показать текущий прокси, режим VPN и статус шлюза\n\
          autopatch on|off      Включить или выключить автопатч после обновлений Antigravity\n\
          chrome-gemini         Разблокировать кнопку «Спросить Gemini» в Google Chrome\n\
          rollback / disable    Полный откат к исходному состоянию и глубокая очистка следов\n\
          doctor [--json]       Проверка доступа и диагностика\n\
          status                Показать таблицу текущего статуса всех продуктов\n\n\
        Работа с туннелями и режимы:\n\
          vpn bypass            Прямой выход с физического адаптера с авто-резервом (по умолчанию)\n\
          vpn use               Выход через системную таблицу маршрутов / активный туннель\n\
          mode own-proxy        Работать строго через свой SOCKS5 / HTTP прокси\n\
          mode vpn              Работать через зарубежный системный VPN без отдельного прокси\n\
          mode auto             Свой прокси с автоматическим резервом\n\n\
        Сервисные команды:\n\
          patch-files           Пропатчить только бинарники Antigravity [необязательный путь]\n\
          tune                  Оптимизация буферов сетевого стека TCP\n\
          diagnostics           Запустить интерактивный чекер подключения\n\
          ai-help               Скопировать в буфер обмена готовый запрос для ИИ (OpenCode / Kimi / ChatGPT)\n\
          report                Сохранить обезличенный JSON-отчёт диагностики [каталог]\n\n\
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
    if command == core::autopatch::AUTOPATCH_FLAG {
        if let Err(error) = core::autopatch::run_once() {
            eprintln!("{error}");
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
    if command == net::sni_relay::SNI_PROXY_FLAG {
        if let Err(error) = net::sni_relay::run_from_args(&args[2..]) {
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
        "autopatch" => result(cli::autopatch_cmd(&args[1..])),
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
    if command == "diagnostics" && args.len() == 2 {
        let ok = ui::menu::handle_diagnostics();
        std::process::exit(if ok { 0 } else { 1 });
    }
    if command == "ai-help" && args.len() == 2 {
        let ok = ui::menu::handle_ai_help();
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
            | "unlock"
            | "disable"
            | "patch-files"
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
        "install" | "enable" | "unlock" => ui::menu::handle_proxy_enable(),
        "patch-files" => ui::menu::handle_patch_files_only(),
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
