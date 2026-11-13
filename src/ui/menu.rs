use crate::core::{
    autopatch,
    detector::{
        find_installations, find_targets_in_path, recover_installations, recover_targets_in_path,
        FoundTarget, TargetKind,
    },
    patcher::{check_target_state, patch_target, proxy_env_ready, restore_target, BinaryState},
    v8_cache::clear_ide_v8_caches,
};
use crate::net::{
    clean_legacy_network, gemini_apps, local_proxy,
    proxy_config::{self, Mode, ProxyConfig, Upstream, VpnPolicy},
};
use crate::system::env::{display_path, expand_env_vars, mask_path};
use crate::ui::dashboard::{banner, print_dashboard};
use crate::ui::terminal::{clear_screen, pause, prompt};
use std::io::IsTerminal;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSetupOutcome {
    Stopped,
    Completed(bool),
}

impl FileSetupOutcome {
    fn succeeded(self) -> bool {
        matches!(self, Self::Completed(true))
    }
}

fn continue_setup(outcome: FileSetupOutcome, next: impl FnOnce() -> bool) -> FileSetupOutcome {
    match outcome {
        FileSetupOutcome::Stopped => FileSetupOutcome::Stopped,
        FileSetupOutcome::Completed(ok) => FileSetupOutcome::Completed(next() && ok),
    }
}

fn is_interactive_session() -> bool {
    std::env::args().len() <= 1 && std::io::stdin().is_terminal()
}

fn print_error_details() {
    println!(
        "  Журнал событий: {}",
        crate::net::config::directory()
            .join("network-events.log")
            .display()
    );
}

fn operation_error(message: &str, detail: &str) {
    crate::net::config::log_event(&format!("{message}: {detail}"));
    eprintln!("  \x1b[91m✗\x1b[0m {message}");
    eprintln!("  {detail}");
}

const APP_MANAGEMENT_HINT: &[&str] = &[
    "macOS запретила изменять файлы внутри приложения (защита «Управление приложениями»).",
    "1. Закройте Antigravity.",
    "2. Системные настройки → Конфиденциальность и безопасность → Управление приложениями:",
    "   включите Терминал (или iTerm, из которого запускаете утилиту).",
    "3. Полностью закройте терминал (⌘Q), откройте его снова и повторите операцию.",
];

fn app_management_blocked(path: &Path, error: &str) -> bool {
    error.contains("(os error 1)")
        && path
            .ancestors()
            .any(|dir| dir.extension().is_some_and(|ext| ext == "app"))
}

fn print_patch_result(
    t: &FoundTarget,
    result: Result<crate::core::patcher::PatchOutcome, String>,
) -> bool {
    use crate::core::patcher::PatchOutcome;
    let label = match t.kind {
        TargetKind::LanguageServer => "Ядро Antigravity (language_server)",
        TargetKind::AgyCli => "Командная строка Antigravity (agy)",
        _ => "Интерфейс Antigravity (app.asar)",
    };
    match result {
        Ok(PatchOutcome::NotApplicable) => {
            println!("  \x1b[90m– {label}: без изменений\x1b[0m");
            true
        }
        Ok(outcome) => {
            let status = match outcome {
                PatchOutcome::Restored | PatchOutcome::AlreadyStock => "восстановлены оригиналы",
                _ => "разблокированы (чистый backup сохранён)",
            };
            println!("  \x1b[92m✓\x1b[0m {label}: {status}");
            true
        }
        Err(error) => {
            operation_error(
                &format!("{label}: не удалось завершить операцию"),
                &format!("{} ({}): {error}", t.name, t.path.display()),
            );
            if cfg!(target_os = "macos") && app_management_blocked(&t.path, &error) {
                for line in APP_MANAGEMENT_HINT {
                    eprintln!("  \x1b[93m{line}\x1b[0m");
                }
            }
            false
        }
    }
}

fn ensure_application_closed(paths: &[std::path::PathBuf], action: &str) -> bool {
    let running = crate::system::file_lock::running_applications(paths).and_then(|mut running| {
        running.extend(crate::system::file_lock::holders(paths)?);
        running.sort();
        running.dedup();
        Ok(running)
    });
    match running {
        Ok(holders) if !holders.is_empty() => {
            println!("  \x1b[93mНужно закрыть Antigravity перед изменением файлов\x1b[0m");
            println!("  Все ваши чаты, история и настройки полностью сохранятся.\n");
            if !is_interactive_session() {
                operation_error(
                    "Закройте Antigravity и повторите команду",
                    &holders.join(", "),
                );
                return false;
            }
            println!("  \x1b[1m[1]\x1b[0m  Мягко закрыть Antigravity и продолжить ({action})");
            println!("  \x1b[1m[0]\x1b[0m  Отмена — вернуться в меню\n");
            loop {
                match prompt("  Введите 1 или 0: ").as_str() {
                    "1" => break,
                    "0" => return false,
                    _ => println!("  Введите 1 для продолжения или 0 для отмены."),
                }
            }
            println!("\n  Закрываем процессы Antigravity…");
            if let Err(error) = crate::system::file_lock::close_application(paths) {
                operation_error("Не удалось закрыть Antigravity автоматически", &error);
                print_error_details();
                pause();
                return false;
            }
            println!("  \x1b[92m✓\x1b[0m Antigravity закрыта.\n");
        }
        Err(error) => {
            operation_error("Не удалось проверить запущенные процессы", &error);
            print_error_details();
            pause();
            return false;
        }
        _ => {}
    }
    true
}

fn patch_targets(targets: Vec<FoundTarget>) -> FileSetupOutcome {
    let paths: Vec<_> = targets.iter().map(|target| target.path.clone()).collect();
    if !ensure_application_closed(&paths, "настройка разблокировки") {
        return FileSetupOutcome::Stopped;
    }
    let mut ok = true;
    for t in targets {
        ok &= print_patch_result(&t, patch_target(&t));
    }
    if let Err(error) = clear_ide_v8_caches() {
        operation_error("Не удалось очистить V8-кэш IDE", &error);
        ok = false;
    }
    FileSetupOutcome::Completed(ok)
}

fn apply_files_side() -> bool {
    let mut ok = true;
    for note in crate::core::endpoint::apply_all() {
        match note {
            Ok(msg) => crate::net::config::log_event(&msg),
            Err(e) => {
                ok = false;
                operation_error("Не удалось обновить настройки IDE", &e);
            }
        }
    }
    ok
}

fn patch_installations() -> FileSetupOutcome {
    if let Err(error) = recover_installations() {
        operation_error("Не удалось восстановить прерванную запись", &error);
        return FileSetupOutcome::Stopped;
    }
    let installs = find_installations();
    if installs.is_empty() {
        eprintln!("  \x1b[91m✗\x1b[0m Установки Antigravity не найдены в стандартных папках.");
        return FileSetupOutcome::Stopped;
    }
    let targets: Vec<_> = installs
        .iter()
        .flat_map(|root| find_targets_in_path(root))
        .collect();
    if targets.is_empty() {
        eprintln!("  \x1b[91m✗\x1b[0m Поддерживаемые бинарники Antigravity не найдены.");
        return FileSetupOutcome::Stopped;
    }
    continue_setup(patch_targets(targets), apply_files_side)
}

fn patch_root(root: &Path) -> bool {
    if let Err(error) = recover_targets_in_path(root) {
        operation_error("Не удалось восстановить прерванную запись", &error);
        return false;
    }
    let targets = find_targets_in_path(root);
    if targets.is_empty() {
        eprintln!("  \x1b[91m✗\x1b[0m Нет поддерживаемых целей: {}", mask_path(root));
        return false;
    }
    patch_targets(targets).succeeded()
}

pub fn parse_and_verify_proxy_input(raw: &str, policy: VpnPolicy) -> Result<Upstream, String> {
    let parsed = Upstream::parse_with_hint(raw)?;
    let mut upstream = parsed.upstream;
    if parsed.protocol_explicit {
        println!(
            "  Проверяем соединение через {} прокси…",
            upstream.protocol.label()
        );
    } else {
        println!("  Автоматически определяем протокол прокси (SOCKS5 или HTTP)…");
    }
    let detected = local_proxy::detect_protocol(&mut upstream, parsed.protocol_explicit, policy)?;
    println!(
        "  \x1b[92m✓\x1b[0m Протокол подтверждён: \x1b[96m{}\x1b[0m ({})",
        detected.label(),
        upstream.safe_display()
    );
    Ok(upstream)
}

fn mark(enabled: bool) -> &'static str {
    if enabled {
        "\x1b[92m[✓]\x1b[0m"
    } else {
        "\x1b[90m[ ]\x1b[0m"
    }
}

fn interactive_setup_wizard(cfg: &mut ProxyConfig) -> bool {
    loop {
        clear_screen();
        banner();
        println!("  ШАГ 1 ИЗ 2 — ВЫБЕРИТЕ ПРОДУКТЫ ДЛЯ РАЗБЛОКИРОВКИ\n");
        println!(
            "  \x1b[1m1\x1b[0m {} Antigravity IDE и CLI (патч региона + локальный шлюз)",
            mark(cfg.products.antigravity)
        );
        println!(
            "  \x1b[1m2\x1b[0m {} Автопатч Antigravity (сам возвращает патч после обновлений IDE)",
            mark(cfg.products.autopatch && cfg.products.antigravity)
        );
        println!(
            "  \x1b[1m3\x1b[0m {} Gemini Desktop на macOS (приложение /Applications/Gemini.app)",
            mark(cfg.products.gemini_desktop)
        );
        println!(
            "  \x1b[1m4\x1b[0m {} Gemini в браузере и Google AI Studio (gemini.google.com, NotebookLM)",
            mark(cfg.products.gemini_web)
        );
        println!(
            "  \x1b[1m5\x1b[0m {} Кнопка «Спросить Gemini» в Google Chrome (встроенная панель ИИ)",
            mark(cfg.products.chrome_gemini)
        );
        println!("\n  \x1b[90m9  Указать нестандартную папку Antigravity вручную\x1b[0m");
        println!("  \x1b[90m0  Отмена — вернуться в меню\x1b[0m\n");
        println!("  • Нажмите \x1b[92mEnter\x1b[0m, чтобы разблокировать все отмеченные \x1b[92m[✓]\x1b[0m продукты");
        println!("  • Или введите номера (например \x1b[1m3\x1b[0m или \x1b[1m3 5\x1b[0m), чтобы переключить галочки\n");

        let input = prompt("  Ваш выбор [Enter = далее / 1-5 = переключить / 0 = отмена]: ");
        let trimmed = input.trim();
        if trimmed == "0" {
            return false;
        }
        if trimmed == "9" {
            handle_manual_path();
            continue;
        }
        if trimmed.is_empty() {
            if !cfg.products.any_selected() {
                println!("  \x1b[93mОтметьте хотя бы один продукт (для полного отката есть пункт [4]).\x1b[0m");
                pause();
                continue;
            }
            break;
        }
        let mut toggled = false;
        for token in trimmed.split(|c: char| c.is_whitespace() || c == ',') {
            match token {
                "1" => {
                    cfg.products.antigravity = !cfg.products.antigravity;
                    if !cfg.products.antigravity {
                        cfg.products.autopatch = false;
                    }
                    toggled = true;
                }
                "2" => {
                    cfg.products.autopatch = !cfg.products.autopatch;
                    if cfg.products.autopatch {
                        cfg.products.antigravity = true;
                    }
                    toggled = true;
                }
                "3" => {
                    cfg.products.gemini_desktop = !cfg.products.gemini_desktop;
                    toggled = true;
                }
                "4" => {
                    cfg.products.gemini_web = !cfg.products.gemini_web;
                    toggled = true;
                }
                "5" => {
                    cfg.products.chrome_gemini = !cfg.products.chrome_gemini;
                    toggled = true;
                }
                _ => {}
            }
        }
        if !toggled {
            println!("  \x1b[93mВведите номера от 1 до 5 или нажмите Enter.\x1b[0m");
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    clear_screen();
    banner();
    println!("  ШАГ 2 ИЗ 2 — ПРОКСИ (SOCKS5 ИЛИ HTTP)\n");
    println!("  Поддерживаются и \x1b[96mSOCKS5\x1b[0m, и \x1b[96mHTTP\x1b[0m прокси — протокол определяется автоматически!");
    println!("  Форматы: \x1b[1mip:port:login:pass\x1b[0m, \x1b[1mlogin:pass@ip:port\x1b[0m, \x1b[1msocks5://...\x1b[0m или \x1b[1mhttp://...\x1b[0m\n");
    if let Some(existing) = &cfg.upstream {
        println!(
            "  Сейчас сохранён прокси: \x1b[92m{}\x1b[0m",
            existing.safe_display()
        );
        println!("  • Нажмите \x1b[92mEnter\x1b[0m, чтобы использовать сохранённый прокси");
        println!("  • Вставьте новый прокси, чтобы заменить его");
        println!("  • Или введите \x1b[1mvpn\x1b[0m для работы через зарубежный системный VPN\n");
    } else if cfg.mode == Mode::Vpn {
        println!("  Сейчас выбран режим: \x1b[92mсистемный зарубежный VPN (без отдельного прокси)\x1b[0m");
        println!("  • Нажмите \x1b[92mEnter\x1b[0m, чтобы продолжить в режиме VPN, или вставьте прокси\n");
    } else {
        println!("  • Вставьте ваш прокси (SOCKS5 или HTTP), чтобы сразу проверить и подключить его");
        println!("  • Или введите \x1b[1mvpn\x1b[0m, если у вас включён зарубежный VPN на весь компьютер\n");
    }

    let raw = match proxy_config::read_hidden("  Прокси (ввод скрыт, Enter = оставить текущий): ")
    {
        Ok(val) => val,
        Err(error) => {
            operation_error("Не удалось прочитать ввод", &error);
            pause();
            return false;
        }
    };
    let trimmed = raw.trim();
    if trimmed == "0" {
        return false;
    }
    if trimmed.eq_ignore_ascii_case("vpn") {
        cfg.upstream = None;
        cfg.mode = Mode::Vpn;
        cfg.vpn_policy = VpnPolicy::Use;
        println!("  \x1b[92m✓\x1b[0m Выбран режим работы через системный зарубежный VPN.");
    } else if !trimmed.is_empty() {
        println!();
        match parse_and_verify_proxy_input(trimmed, cfg.vpn_policy) {
            Ok(upstream) => {
                cfg.upstream = Some(upstream);
                cfg.mode = Mode::OwnProxy;
            }
            Err(error) => {
                operation_error("Проверка прокси не прошла", &error);
                println!("  Проверьте адрес/логин/пароль или протестируйте прокси в пункте [3].");
                if prompt("\n  Всё равно сохранить этот прокси и продолжить? [1 = да / 0 = отмена]: ")
                    == "1"
                {
                    match Upstream::parse(trimmed) {
                        Ok(upstream) => {
                            cfg.upstream = Some(upstream);
                            cfg.mode = Mode::OwnProxy;
                        }
                        Err(parse_err) => {
                            operation_error("Некорректный формат прокси", &parse_err);
                            pause();
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
        }
    }
    true
}

pub fn handle_proxy_enable() -> bool {
    let mut config = match proxy_config::load() {
        Ok(c) => c,
        Err(error) => {
            operation_error("Не удалось прочитать настройки прокси", &error);
            pause();
            return false;
        }
    };
    if is_interactive_session() && !interactive_setup_wizard(&mut config) {
        return false;
    }
    if let Err(error) = proxy_config::save(&config) {
        operation_error("Не удалось сохранить выбранные настройки", &error);
        pause();
        return false;
    }

    clear_screen();
    banner();
    println!("  ПРИМЕНЕНИЕ РАЗБЛОКИРОВКИ ВЫБРАННЫХ ПРОДУКТОВ\n");
    let mut ok = true;

    if config.products.antigravity {
        ok &= patch_installations().succeeded();
        if ok {
            let unready: Vec<_> = find_installations()
                .iter()
                .flat_map(|root| find_targets_in_path(root))
                .filter(|t| {
                    matches!(t.kind, TargetKind::LanguageServer | TargetKind::AgyCli)
                        && !proxy_env_ready(t)
                })
                .collect();
            for target in unready {
                operation_error(
                    "В бинарнике не найдена переменная AG_LS_PROXY",
                    &target.path.display().to_string(),
                );
                ok = false;
            }
        }
    }

    if ok {
        if config.products.autopatch && config.products.antigravity {
            match autopatch::enable() {
                Ok(()) => println!(
                    "  \x1b[92m✓\x1b[0m Автопатч Antigravity включён (следит за обновлениями приложения)"
                ),
                Err(error) => {
                    operation_error("Не удалось включить автопатч", &error);
                    ok = false;
                }
            }
        } else if autopatch::is_enabled() {
            let _ = autopatch::disable();
            println!("  \x1b[90m– Автопатч Antigravity отключён по вашему выбору\x1b[0m");
        }
    }

    if ok {
        match clean_legacy_network(true) {
            Ok(notes) => {
                for note in notes {
                    println!("  \x1b[92m✓\x1b[0m Очистка конфликтующих следов: {note}");
                }
            }
            Err(error) => println!("  \x1b[93m!\x1b[0m Предупреждение очистки старых DNS: {error}"),
        }
    }

    #[cfg(target_os = "macos")]
    if ok {
        if config.products.needs_local_gateway() {
            match local_proxy::enable() {
                Ok(port) => {
                    println!(
                        "  \x1b[92m✓\x1b[0m Локальный шлюз активен: {}",
                        local_proxy::url_at(port)
                    );
                    if config.products.needs_system_pac() && gemini_apps::pac_active() {
                        println!(
                            "  \x1b[92m✓\x1b[0m Системный PAC настроен для выбранных сервисов Gemini"
                        );
                    }
                    if config.products.gemini_desktop && crate::net::sni_relay::listener_alive() {
                        println!(
                            "  \x1b[92m✓\x1b[0m Локальный SNI-шлюз Gemini.app активен (127.0.0.2:443)"
                        );
                    }
                    if config.products.gemini_desktop && gemini_apps::stop_gemini_desktop() {
                        println!(
                            "  \x1b[92m✓\x1b[0m Фоновые процессы Gemini.app перезапущены под новый маршрут"
                        );
                    }
                }
                Err(error) => {
                    operation_error("Не удалось запустить локальный шлюз", &error);
                    ok = false;
                }
            }
        } else {
            let _ = local_proxy::disable();
        }
    }

    if ok && gemini_apps::chrome_installed() {
        if config.products.chrome_gemini {
            if gemini_apps::chrome_glic_needs_unlock() {
                let can_unlock = if !gemini_apps::chrome_running() {
                    true
                } else if is_interactive_session() {
                    println!("\n  \x1b[96mКнопка «Спросить Gemini» в Google Chrome\x1b[0m");
                    println!("  Чтобы включить кнопку ИИ, нужно один раз мягко закрыть Chrome (все вкладки восстановятся).");
                    if prompt("  Закрыть Chrome сейчас и разблокировать? [1 = да / 0 = позже]: ")
                        == "1"
                    {
                        gemini_apps::quit_chrome()
                            .map(|()| true)
                            .unwrap_or_else(|e| {
                                println!("  \x1b[93m!\x1b[0m {e}");
                                false
                            })
                    } else {
                        false
                    }
                } else {
                    false
                };
                if can_unlock {
                    match gemini_apps::unlock_chrome_glic() {
                        Ok(count) => println!(
                            "  \x1b[92m✓\x1b[0m Кнопка «Спросить Gemini» в Chrome разблокирована (профилей: {count})"
                        ),
                        Err(error) => println!("  \x1b[93m!\x1b[0m Chrome GLIC: {error}"),
                    }
                }
            } else {
                println!("  \x1b[92m✓\x1b[0m Кнопка «Спросить Gemini» в Chrome уже активна");
            }
        } else {
            let _ = gemini_apps::restore_chrome_glic();
        }
    }

    if ok {
        if local_proxy::cli_shortcut_ready() {
            println!("  \x1b[92m✓\x1b[0m Быстрая команда в терминале: ag-bypass");
        }
        println!("\n  \x1b[92mГотово! Все выбранные продукты настроены.\x1b[0m");
        if config.upstream.is_none() && config.mode != Mode::Vpn {
            println!("  \x1b[93mНе забудьте добавить ваш SOCKS5 или HTTP прокси в пункте [2].\x1b[0m");
        } else {
            println!("  Перезапустите открытые приложения (⌘Q → открыть снова), чтобы изменения вступили в силу.");
        }
    } else {
        eprintln!("\n  Настройка завершена с предупреждениями. Подробности выше.");
        print_error_details();
    }
    pause();
    ok
}

pub fn handle_patch_files_only() -> bool {
    let ok = if let Some(path) = std::env::args().nth(2) {
        patch_root(&expand_env_vars(&path))
    } else {
        patch_installations().succeeded()
    };
    if ok {
        println!("\n  \x1b[92mФайлы Antigravity успешно пропатчены.\x1b[0m");
    }
    pause();
    ok
}

pub fn handle_manual_path() {
    let input = prompt("  Путь к папке или файлу Antigravity: ");
    if input.trim().is_empty() {
        return;
    }
    let root = expand_env_vars(input.trim().trim_matches('"'));
    let ok = patch_root(&root);
    if ok {
        println!("\n  \x1b[92mФайлы успешно пропатчены.\x1b[0m");
    }
    pause();
}

fn handle_proxy_and_vpn() {
    loop {
        clear_screen();
        banner();
        println!("  УПРАВЛЕНИЕ ПРОКСИ (SOCKS5 / HTTP) И РАБОТОЙ С VPN\n");
        let cfg = proxy_config::load().unwrap_or_default();
        match &cfg.upstream {
            Some(u) => println!("  Текущий прокси: \x1b[92m{}\x1b[0m", u.safe_display()),
            None if cfg.mode == Mode::Vpn => println!(
                "  Текущий режим:  \x1b[92mзарубежный системный VPN (без отдельного прокси)\x1b[0m"
            ),
            None => println!("  Текущий прокси: \x1b[90mне задан\x1b[0m"),
        }
        let vpn_desc = match cfg.vpn_policy {
            VpnPolicy::Bypass => {
                "Прямой выход с физического адаптера + авто-резерв (рекомендуется)"
            }
            VpnPolicy::Use => "Через системную таблицу маршрутов / активный туннель",
        };
        println!("  Маршрут сокета: \x1b[96m{vpn_desc}\x1b[0m\n");

        println!("  \x1b[90mКак работает выход к прокси при включённых VPN-клиентах:\x1b[0m");
        println!("  • Поддерживаются \x1b[1mSOCKS5\x1b[0m и \x1b[1mHTTP\x1b[0m прокси (в том числе локальные порты 127.0.0.1).");
        println!("  • По умолчанию шлюз привязывает сокет напрямую к физическому адаптеру (en*), мимо виртуальных");
        println!("    туннелей (utun), а при жёстком Kill-Switch автоматически переключается на системный маршрут.\n");

        println!("  \x1b[92m[1]\x1b[0m  Добавить или заменить прокси (SOCKS5 или HTTP)");
        println!("  \x1b[91m[2]\x1b[0m  Удалить сохранённый прокси");
        println!("  [3]  Работать через системный VPN-туннель (без отдельного прокси)");
        println!("  [4]  Переключить привязку сокета (Физический адаптер ↔ Системный маршрут)");
        println!("\n  [0]  Назад в главное меню\n");

        match prompt("  Выберите действие [0-4]: ").trim() {
            "0" | "" => return,
            "1" => {
                println!("\n  Форматы: ip:port:login:pass, login:pass@ip:port, socks5://... или http://...");
                let input = match proxy_config::read_hidden("  Вставьте прокси (ввод скрыт): ") {
                    Ok(v) => v,
                    Err(e) => {
                        operation_error("Ошибка чтения ввода", &e);
                        pause();
                        continue;
                    }
                };
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    continue;
                }
                println!();
                match parse_and_verify_proxy_input(trimmed, cfg.vpn_policy) {
                    Ok(upstream) => {
                        if let Err(e) = proxy_config::save_upstream(upstream) {
                            operation_error("Не удалось сохранить прокси", &e);
                        } else if local_proxy::listener_alive() {
                            println!("  \x1b[92m✓\x1b[0m Новый прокси сразу применён к работающему шлюзу!");
                        } else {
                            println!("  \x1b[93mТеперь запустите разблокировку в пункте [1] главного меню.\x1b[0m");
                        }
                    }
                    Err(error) => {
                        operation_error("Проверка прокси не прошла", &error);
                        if prompt("\n  Всё равно сохранить этот прокси? [1 = да / 0 = нет]: ") == "1"
                        {
                            match Upstream::parse(trimmed) {
                                Ok(u) => {
                                    let _ = proxy_config::save_upstream(u);
                                    println!("  \x1b[92m✓\x1b[0m Прокси сохранён.");
                                }
                                Err(pe) => operation_error("Некорректный формат", &pe),
                            }
                        }
                    }
                }
                pause();
            }
            "2" => {
                match proxy_config::clear_upstream() {
                    Ok(()) => println!("\n  \x1b[92m✓\x1b[0m Сохранённый адрес и пароль прокси полностью удалены."),
                    Err(e) => operation_error("Не удалось удалить прокси", &e),
                }
                pause();
            }
            "3" => {
                let mut next = cfg.clone();
                next.upstream = None;
                next.mode = Mode::Vpn;
                next.vpn_policy = VpnPolicy::Use;
                match proxy_config::save(&next) {
                    Ok(()) => println!("\n  \x1b[92m✓\x1b[0m Включён режим работы через системный зарубежный VPN."),
                    Err(e) => operation_error("Не удалось сохранить режим", &e),
                }
                pause();
            }
            "4" => {
                let next_policy = match cfg.vpn_policy {
                    VpnPolicy::Bypass => VpnPolicy::Use,
                    VpnPolicy::Use => VpnPolicy::Bypass,
                };
                match proxy_config::set_vpn_policy(next_policy) {
                    Ok(()) => println!(
                        "\n  \x1b[92m✓\x1b[0m Режим работы с VPN переключён на: {next_policy} (применяется сразу)."
                    ),
                    Err(e) => operation_error("Не удалось переключить политику VPN", &e),
                }
                pause();
            }
            _ => {}
        }
    }
}

fn render_product_checks(checks: &[local_proxy::ProductCheck]) -> bool {
    let mut all_ok = true;
    println!();
    for item in checks {
        if item.ok {
            println!(
                "  \x1b[92m✓\x1b[0m {:<28} \x1b[92m{}\x1b[0m",
                item.name, item.detail
            );
        } else if item.geo_blocked {
            all_ok = false;
            println!(
                "  \x1b[93m!\x1b[0m {:<28} \x1b[93m{}\x1b[0m",
                item.name, item.detail
            );
        } else {
            all_ok = false;
            println!(
                "  \x1b[91m✗\x1b[0m {:<28} \x1b[91m{}\x1b[0m",
                item.name, item.detail
            );
        }
    }
    all_ok
}

pub fn handle_diagnostics() -> bool {
    clear_screen();
    banner();
    println!("  ЧЕКЕР ПРОКСИ И ПРОВЕРКА ДОСТУПА КО ВСЕМ СЕРВИСАМ GOOGLE\n");
    let cfg = proxy_config::load().unwrap_or_default();
    let summary = local_proxy::summary();

    if summary["listener"] == true {
        println!(
            "  \x1b[92m✓\x1b[0m Локальный шлюз: активен (127.0.0.1:{})",
            summary["local_port"].as_u64().unwrap_or(0)
        );
    } else {
        println!("  \x1b[90m– Локальный шлюз: выключен\x1b[0m");
    }
    if autopatch::is_enabled() {
        println!("  \x1b[92m✓\x1b[0m Автопатч Antigravity: включён");
    }
    if gemini_apps::chrome_installed() {
        if gemini_apps::chrome_glic_needs_unlock() {
            println!("  \x1b[90m– Кнопка «Спросить Gemini» в Chrome: не разблокирована\x1b[0m");
        } else {
            println!("  \x1b[92m✓\x1b[0m Кнопка «Спросить Gemini» в Chrome: флаг региона US активен");
        }
    }

    let mut temp_proxy: Option<Upstream> = None;
    if is_interactive_session() {
        println!("\n  • Нажмите \x1b[92mEnter\x1b[0m, чтобы проверить ваш текущий сохранённый прокси / маршрут");
        println!("  • Или вставьте \x1b[96mлюбой новый купленный прокси\x1b[0m (SOCKS5 / HTTP), чтобы сразу проверить пинг и регион!\n");
        if let Ok(raw) =
            proxy_config::read_hidden("  Тестовый прокси (Enter = текущий, 0 = назад): ")
        {
            let trimmed = raw.trim();
            if trimmed == "0" {
                return true;
            }
            if !trimmed.is_empty() {
                println!();
                match parse_and_verify_proxy_input(trimmed, cfg.vpn_policy) {
                    Ok(u) => temp_proxy = Some(u),
                    Err(error) => {
                        operation_error("Прокси не отвечает или отклонён", &error);
                        pause();
                        return false;
                    }
                }
            }
        }
    }

    let target_upstream = temp_proxy.as_ref().or(cfg.upstream.as_ref());
    match target_upstream {
        Some(u) => println!(
            "\n  Проверяем все 6 серверов Google AI через {}…",
            u.safe_display()
        ),
        None => println!(
            "\n  Прокси не задан — проверяем прямое подключение / системный VPN…"
        ),
    }

    let checks = local_proxy::check_all_products(target_upstream, cfg.vpn_policy);
    let ok = render_product_checks(&checks);

    if let Some(tested) = temp_proxy {
        if ok && is_interactive_session() {
            if prompt("\n  Сохранить этот проверенный прокси как основной? [1 = да / Enter = нет]: ")
                .trim()
                == "1"
            {
                if proxy_config::save_upstream(tested).is_ok() {
                    println!("  \x1b[92m✓\x1b[0m Прокси сохранён как основной!");
                }
            }
        }
    }

    if !ok {
        println!("\n  \x1b[93mСовет:\x1b[0m если сервисы недоступны или регион заблокирован, используйте зарубежный SOCKS5/HTTP прокси (США/Европа).");
    } else {
        println!("\n  \x1b[92mОтлично! Прокси открывает все продукты Google AI без региональной блокировки.\x1b[0m");
    }
    let obs = crate::model_status::snapshot();
    let obs_color = if obs.warning() { "\x1b[93m" } else { "\x1b[90m" };
    println!("  {obs_color}Журнал IDE (за 15 мин): {}\x1b[0m", obs.label());
    pause();
    ok
}

pub fn handle_rollback() -> bool {
    let installs = if let Some(path) = std::env::args().nth(2) {
        let root = expand_env_vars(&path);
        if let Err(error) = recover_targets_in_path(&root) {
            operation_error("Не удалось восстановить прерванную запись", &error);
            return false;
        }
        vec![root]
    } else {
        if let Err(error) = recover_installations() {
            operation_error("Не удалось восстановить прерванную запись", &error);
            return false;
        }
        find_installations()
    };
    let paths: Vec<_> = installs
        .iter()
        .flat_map(|root| find_targets_in_path(root))
        .map(|t| t.path)
        .collect();
    clear_screen();
    banner();
    println!("  ПОЛНЫЙ ОТКАТ К ИСХОДНОМУ СОСТОЯНИЮ\n");
    println!("  Ваши чаты, воркспейсы, память агентов и вкладки Chrome полностью сохранятся.\n");
    if !ensure_application_closed(&paths, "полный откат") {
        return false;
    }

    let mut ok = true;
    if let Err(error) = autopatch::disable() {
        operation_error("Не удалось отключить автопатч", &error);
        ok = false;
    } else {
        println!("  \x1b[92m✓\x1b[0m Автопатч отключён");
    }

    let mut missing_third_party_backup = false;
    for root in installs {
        let targets = find_targets_in_path(&root);
        if targets.is_empty() && std::env::args().nth(2).is_some() {
            eprintln!("  \x1b[91m✗\x1b[0m Цели для отката не найдены: {}", root.display());
            ok = false;
        }
        for target in targets {
            match restore_target(&target) {
                Ok(outcome) => {
                    ok &= print_patch_result(&target, Ok(outcome));
                }
                Err(error) => {
                    // If Antigravity updated itself to a clean version that does not carry our patch,
                    // keep the new version untouched and proceed with full network/system cleanup!
                    if check_target_state(&target) == BinaryState::Unknown
                        && !proxy_env_ready(&target)
                    {
                        if let Ok(bytes) = std::fs::read(&target.path) {
                            let _ = crate::system::journal::retire(&target.path, Some(&bytes));
                        }
                        println!(
                            "  \x1b[92m✓\x1b[0m {}: обновлённая чистая версия сохранена без изменений",
                            target.name
                        );
                    } else {
                        if error.contains("Нет backup") {
                            missing_third_party_backup = true;
                        }
                        ok &= print_patch_result(&target, Err(error));
                    }
                }
            }
        }
    }

    if !paths.is_empty() {
        if let Err(error) = clear_ide_v8_caches() {
            operation_error("Не удалось очистить кэш V8", &error);
            ok = false;
        }
    }

    for e in crate::core::endpoint::remove_all() {
        operation_error("Не удалось восстановить settings.json", &e);
        ok = false;
    }

    if let Err(error) = local_proxy::disable() {
        operation_error("Не удалось остановить локальный шлюз / PAC", &error);
        ok = false;
    } else {
        println!("  \x1b[92m✓\x1b[0m Локальный шлюз, системный PAC и настройки Chrome возвращены к исходным");
    }
    if let Ok(true) = gemini_apps::reset_third_party_chrome_glic() {
        println!("  \x1b[92m✓\x1b[0m Сброшены сторонние флаги региона в Google Chrome");
    }

    match clean_legacy_network(true) {
        Ok(notes) => {
            for note in notes {
                println!("  \x1b[92m✓\x1b[0m Глубокая очистка: {note}");
            }
        }
        Err(error) => {
            operation_error("Предупреждение при очистке старых сетевых правил", &error);
            ok = false;
        }
    }

    if is_interactive_session()
        && proxy_config::load()
            .ok()
            .and_then(|c| c.upstream)
            .is_some()
    {
        if prompt(
            "\n  Удалить также сохранённый адрес и пароль прокси? [1 = удалить / Enter = оставить в памяти]: ",
        )
        .trim()
            == "1"
        {
            let _ = proxy_config::clear_upstream();
            println!("  \x1b[92m✓\x1b[0m Сохранённый прокси удалён.");
        }
    }

    if missing_third_party_backup {
        println!(
            "\n  \x1b[93mПодсказка:\x1b[0m все сетевые настройки, системный PAC, hosts и фоновые службы очищены.\n  Если сам файл Antigravity ранее изменялся сторонним патчером без сохранения резервной копии (.bak),\n  просто скачайте свежий Antigravity и перетащите поверх в Программы — ваши чаты и воркспейсы сохранятся."
        );
    }

    if ok {
        println!("\n  \x1b[92mПолный откат завершён. Система приведена в исходное состояние!\x1b[0m");
    } else {
        eprintln!("\n  Откат завершён с предупреждениями. Подробности выше.");
        print_error_details();
    }
    pause();
    ok
}

pub fn handle_ai_help() -> bool {
    println!("\n  Собираем полную диагностику для языковой модели (OpenCode / Kimi / ChatGPT / Claude)…");
    let report = crate::diagnostics::collect();
    match crate::diagnostics::save_ai_prompt(&report) {
        Ok((prompt_path, copied)) => {
            if copied {
                println!(
                    "\n  \x1b[92m✓\x1b[0m Готовый запрос для нейросети скопирован прямо в буфер обмена!"
                );
                println!(
                    "    Откройте \x1b[1mKimi, OpenCode, ChatGPT или Claude\x1b[0m и просто нажмите \x1b[96m⌘V (Ctrl+V)\x1b[0m."
                );
            }
            println!(
                "  \x1b[92m✓\x1b[0m Текстовый файл с запросом для ИИ сохранён:\n    {}",
                display_path(&prompt_path)
            );
            println!("    (Пароли прокси, IP-адреса прокси и личные пути полностью удалены.)");
            pause();
            true
        }
        Err(error) => {
            eprintln!("  Не удалось подготовить запрос для ИИ: {error}");
            pause();
            false
        }
    }
}

pub fn handle_save_diagnostics(directory: Option<&Path>) -> bool {
    println!("\n  Собираем отчёт диагностики (без паролей прокси и личных данных)…");
    let ok = match crate::diagnostics::save(directory) {
        Ok(path) => {
            println!("\n  Диагностика сохранена:\n  {}", display_path(&path));
            if directory.is_none() {
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(report) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Ok((prompt_path, copied)) =
                            crate::diagnostics::save_ai_prompt(&report)
                        {
                            if copied {
                                println!(
                                    "\n  \x1b[92m✓\x1b[0m Готовый запрос для ИИ скопирован в буфер обмена!"
                                );
                                println!(
                                    "    Просто откройте \x1b[1mKimi, OpenCode, ChatGPT или Claude\x1b[0m и нажмите \x1b[96m⌘V (Ctrl+V)\x1b[0m."
                                );
                            }
                            println!(
                                "  \x1b[90mТекст запроса также сохранён: {}\x1b[0m",
                                display_path(&prompt_path)
                            );
                        }
                    }
                }
            } else {
                println!("\n  Файл можно приложить к обращению или Issue.");
            }
            true
        }
        Err(error) => {
            eprintln!("  Не удалось сохранить диагностику: {error}");
            false
        }
    };
    pause();
    ok
}

pub fn run_app() {
    loop {
        clear_screen();
        banner();
        print_dashboard();

        println!("  \x1b[92m[1]\x1b[0m  Настроить разблокировку продуктов (выбор сервисов + прокси)");
        println!("  \x1b[96m[2]\x1b[0m  Прокси и работа с VPN (добавить SOCKS5/HTTP, сменить, удалить)");
        println!("  [3]  Чекер прокси и проверка доступа ко всем сервисам Google");
        println!("  \x1b[91m[4]\x1b[0m  Полный откат и глубокая очистка следов прошлых обходчиков");
        println!("  [5]  Диагностика для ИИ (OpenCode / Kimi / ChatGPT) и отчёт в файл");
        println!("\n  [0]  Выход\n");

        match prompt("Выберите действие [0-5]: ").trim() {
            "1" => {
                handle_proxy_enable();
            }
            "2" => {
                handle_proxy_and_vpn();
            }
            "3" => {
                handle_diagnostics();
            }
            "4" => {
                handle_rollback();
            }
            "5" => {
                handle_save_diagnostics(None);
            }
            "0" => {
                clear_screen();
                break;
            }
            _ => {
                println!("  \x1b[31mВведите номер пункта от 0 до 5.\x1b[0m");
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{app_management_blocked, continue_setup, FileSetupOutcome};
    use std::path::Path;

    #[test]
    fn cancelled_or_blocked_file_setup_skips_all_following_mutations() {
        let outcome = continue_setup(FileSetupOutcome::Stopped, || {
            panic!("Cancelled setup must not change endpoints")
        });
        assert_eq!(outcome, FileSetupOutcome::Stopped);
        assert!(!outcome.succeeded());
    }

    #[test]
    fn partial_setup_runs_remaining_stages_in_order_and_keeps_every_failure() {
        for files_ok in [false, true] {
            for side_ok in [false, true] {
                let mut stages = vec!["patch files"];
                let outcome = continue_setup(FileSetupOutcome::Completed(files_ok), || {
                    stages.push("configure endpoints");
                    side_ok
                });
                assert_eq!(stages, ["patch files", "configure endpoints"]);
                assert_eq!(outcome.succeeded(), files_ok && side_ok);
            }
        }
    }

    #[test]
    fn only_eperm_inside_an_app_bundle_explains_app_management() {
        let bundled =
            Path::new("/Applications/Antigravity.app/Contents/Resources/bin/language_server");
        let eperm = "Operation not permitted (os error 1)";
        assert!(app_management_blocked(bundled, eperm));
        assert!(!app_management_blocked(bundled, "Permission denied (os error 13)"));
        assert!(!app_management_blocked(Path::new("/usr/local/bin/agy"), eperm));
    }
}
