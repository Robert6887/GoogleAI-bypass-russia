use crate::core::detector::{
    find_installations, find_targets_in_path, recover_installations, recover_targets_in_path,
    FoundTarget,
};
use crate::core::patcher::{patch_target, restore_target};
use crate::core::v8_cache::clear_ide_v8_caches;
use crate::net::{apply_dns_rules, remove_dns_rules};
use crate::system::env::{display_path, expand_env_vars, mask_path};
use crate::ui::dashboard::{banner, print_dashboard};
use crate::ui::terminal::{clear_screen, pause, prompt};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSetupOutcome {
    // Cancellation, missing targets, or a failed application-close check.
    Stopped,
    // All targets were attempted; individual files may have failed.
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
        FileSetupOutcome::Completed(ok) => {
            // Run the next stage even after partial failure, preserving that failure.
            FileSetupOutcome::Completed(next() && ok)
        }
    }
}

#[cfg(test)]
mod setup_tests {
    use super::{continue_setup, FileSetupOutcome};

    #[test]
    fn cancelled_or_blocked_file_setup_skips_all_following_mutations() {
        let outcome = continue_setup(FileSetupOutcome::Stopped, || {
            panic!("Cancelled setup must not change endpoints")
        });
        let outcome = continue_setup(outcome, || {
            panic!("Cancelled setup must not configure DNS or install a service")
        });
        assert_eq!(outcome, FileSetupOutcome::Stopped);
        assert!(!outcome.succeeded());
    }

    #[test]
    fn partial_setup_runs_remaining_stages_in_order_and_keeps_every_failure() {
        for files_ok in [false, true] {
            for side_ok in [false, true] {
                for network_ok in [false, true] {
                    let mut stages = vec!["patch files and clear caches"];
                    let outcome = continue_setup(FileSetupOutcome::Completed(files_ok), || {
                        stages.push("configure endpoints");
                        side_ok
                    });
                    let outcome = continue_setup(outcome, || {
                        stages.push("configure DNS and refresh endpoints");
                        network_ok
                    });
                    assert_eq!(
                        stages,
                        [
                            "patch files and clear caches",
                            "configure endpoints",
                            "configure DNS and refresh endpoints"
                        ]
                    );
                    assert_eq!(outcome.succeeded(), files_ok && side_ok && network_ok);
                }
            }
        }
    }
}

fn print_error_details() {
    println!(
        "  Подробности для поддержки: {}",
        crate::net::config::directory()
            .join("network-events.log")
            .display()
    );
}

fn operation_error(message: &str, detail: &str) {
    crate::net::relay::log_event(&format!("{message}: {detail}"));
    eprintln!("  \x1b[91m✗\x1b[0m {message}");
    eprintln!("  {detail}");
}

fn print_patch_result(
    t: &FoundTarget,
    result: Result<crate::core::patcher::PatchOutcome, String>,
) -> bool {
    use crate::core::{detector::TargetKind, patcher::PatchOutcome};
    let label = match t.kind {
        TargetKind::LanguageServer => "Файлы Antigravity",
        TargetKind::AgyCli => "Командная строка Antigravity",
        _ => "Интерфейс приложения",
    };
    match result {
        Ok(PatchOutcome::NotApplicable) => {
            println!("  \x1b[90m– {label}: без изменений\x1b[0m");
            true
        }
        Ok(outcome) => {
            let status = match outcome {
                PatchOutcome::Restored | PatchOutcome::AlreadyStock => "восстановлены",
                _ => "настроены",
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

const APP_MANAGEMENT_HINT: &[&str] = &[
    "macOS запретила изменять файлы внутри приложения (защита «Управление приложениями»).",
    "1. Закройте Antigravity.",
    "2. Системные настройки → Конфиденциальность и безопасность → Управление приложениями:",
    "   включите Терминал (или iTerm, из которого запускаете утилиту).",
    "3. Полностью закройте терминал (⌘Q), откройте его снова и повторите операцию.",
];

/// App Management denies writes inside signed bundles with EPERM, even to root;
/// a missing Unix permission is EACCES (os error 13) and needs no such hint.
fn app_management_blocked(path: &Path, error: &str) -> bool {
    error.contains("(os error 1)")
        && path
            .ancestors()
            .any(|dir| dir.extension().is_some_and(|ext| ext == "app"))
}

#[cfg(test)]
mod app_management_tests {
    use super::app_management_blocked;
    use std::path::Path;

    #[test]
    fn only_eperm_inside_an_app_bundle_explains_app_management() {
        let bundled =
            Path::new("/Applications/Antigravity.app/Contents/Resources/bin/language_server");
        let eperm = "Operation not permitted (os error 1) at path \"/Applications/Antigravity.app/Contents/Resources/bin/.tmpvbl0fy\"";
        assert!(app_management_blocked(bundled, eperm));
        assert!(!app_management_blocked(
            bundled,
            "Permission denied (os error 13)"
        ));
        assert!(!app_management_blocked(
            bundled,
            "Version not supported (os error 10)"
        ));
        assert!(!app_management_blocked(
            Path::new("/usr/local/bin/agy"),
            eperm
        ));
    }
}
fn patch_root(root: &Path) -> bool {
    if let Err(error) = recover_targets_in_path(root) {
        operation_error("Не удалось восстановить прерванную запись", &error);
        return false;
    }
    let targets = find_targets_in_path(root);
    if targets.is_empty() {
        eprintln!("[✗] Нет поддерживаемых целей: {}", mask_path(root));
        return false;
    }
    patch_targets(targets).succeeded()
}
fn patch_targets(targets: Vec<FoundTarget>) -> FileSetupOutcome {
    let paths: Vec<_> = targets.iter().map(|target| target.path.clone()).collect();
    if !ensure_application_closed(&paths, "включение обхода") {
        return FileSetupOutcome::Stopped;
    }
    let mut ok = true;
    for t in targets {
        ok &= print_patch_result(&t, patch_target(&t));
    }
    // Successful JS patches need cache invalidation even when another file failed.
    if let Err(error) = clear_ide_v8_caches() {
        operation_error("Не удалось очистить кэш приложения", &error);
        ok = false;
    }
    FileSetupOutcome::Completed(ok)
}
fn apply_files_side() -> bool {
    let mut ok = true;
    for note in crate::core::endpoint::apply_all() {
        match note {
            Ok(msg) => crate::net::relay::log_event(&msg),
            Err(e) => {
                ok = false;
                operation_error("Не удалось завершить настройку", &e);
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
        eprintln!("[✗] Установки не найдены; укажите путь в пункте 4.");
        return FileSetupOutcome::Stopped;
    }
    let targets: Vec<_> = installs
        .iter()
        .flat_map(|root| find_targets_in_path(root))
        .collect();
    if targets.is_empty() {
        eprintln!("[✗] Файлы приложения не найдены; укажите путь в пункте 4.");
        return FileSetupOutcome::Stopped;
    }
    continue_setup(patch_targets(targets), apply_files_side)
}
fn show_result(ok: bool) {
    if ok {
        println!("\n  \x1b[92mГотово. Изменения применены.\x1b[0m\n  Теперь откройте Antigravity и проверьте работу.");
    } else {
        eprintln!("\n  Операция не завершена. Причина указана выше.");
        print_error_details();
    }
}

fn show_network_result(setup: &crate::net::NetworkSetup) -> bool {
    crate::net::relay::log_event(&setup.message);
    if setup.local_relay_running {
        println!("  \x1b[92m✓\x1b[0m DNS настроен. Прямое подключение, без фонового подбора");
    } else {
        eprintln!("  \x1b[93m!\x1b[0m Используются прямые DNS и сохранённые адреса");
        eprintln!("  {}", setup.message);
        print_error_details();
    }
    true
}
pub fn handle_unlock_all() -> bool {
    clear_screen();
    banner();
    println!("  ВКЛЮЧЕНИЕ ОБХОДА\n");
    if !check_vpn_before_setup() {
        return false;
    }
    let outcome = continue_setup(patch_installations(), || {
        let mut ok;
        match apply_dns_rules() {
            Ok(setup) => {
                ok = show_network_result(&setup);
                for note in crate::core::endpoint::apply_all() {
                    match note {
                        Ok(msg) => crate::net::relay::log_event(&msg),
                        Err(e) => {
                            operation_error("Не удалось завершить настройку", &e);
                            ok = false;
                        }
                    }
                }
            }
            Err(e) => {
                operation_error("Не удалось настроить подключение", &e);
                ok = false;
            }
        }
        ok
    });
    let ok = outcome.succeeded();
    show_result(ok);
    pause();
    ok
}
/// Enable the private CONNECT route without forcing the legacy VPN preflight.
/// Patching and local gateway startup work even before an upstream proxy is entered.
pub fn handle_proxy_enable() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        return handle_unlock_all();
    }
    #[cfg(target_os = "macos")]
    {
        let config = match crate::net::proxy_config::load() {
            Ok(config) => config,
            Err(error) => {
                operation_error("Не удалось прочитать настройки прокси", &error);
                pause();
                return false;
            }
        };
        if config.mode == crate::net::proxy_config::Mode::SniDirect {
            if let Err(error) = crate::net::local_proxy::disable() {
                operation_error("Не удалось отключить локальный прокси", &error);
                pause();
                return false;
            }
            return handle_unlock_all();
        }
        clear_screen();
        banner();
        println!("  НАКАТ ПАТЧА И ЗАПУСК ЛОКАЛЬНОГО ШЛЮЗА\n");
        println!("  Режим: {}; VPN: {}\n", config.mode, config.vpn_policy);
        let mut ok = patch_installations().succeeded();
        if ok {
            let unready: Vec<_> = find_installations()
                .iter()
                .flat_map(|root| find_targets_in_path(root))
                .filter(|target| {
                    matches!(
                        target.kind,
                        crate::core::detector::TargetKind::LanguageServer
                            | crate::core::detector::TargetKind::AgyCli
                    ) && !crate::core::patcher::proxy_env_ready(target)
                })
                .collect();
            if !unready.is_empty() {
                for target in unready {
                    operation_error(
                        "В бинарнике нет подтверждённой переменной AG_LS_PROXY",
                        &target.path.display().to_string(),
                    );
                }
                ok = false;
            }
        }
        if ok {
            match crate::net::local_proxy::enable() {
                Ok(port) => {
                    println!(
                        "  \x1b[92m✓\x1b[0m Локальный шлюз запущен: {}",
                        crate::net::local_proxy::url_at(port)
                    );
                    if crate::net::gemini_apps::pac_active() {
                        println!(
                            "  \x1b[92m✓\x1b[0m Системный PAC включён: Gemini Web, AI Studio, Chrome и Gemini.app"
                        );
                    } else {
                        println!(
                            "  \x1b[93m!\x1b[0m Системный PAC пропущен: сохранён ваш сторонний PAC-адрес"
                        );
                    }
                    if crate::net::gemini_apps::stop_gemini_desktop() {
                        println!(
                            "  \x1b[92m✓\x1b[0m Фоновые процессы Gemini.app остановлены для чистого перезапуска"
                        );
                    }
                }
                Err(error) => {
                    operation_error("Не удалось запустить шлюз или системный PAC", &error);
                    ok = false;
                }
            }
        }
        if ok {
            // Remove only this project's owned legacy DNS/hosts/routes after the new
            // route is live. Third-party VPN and resolver settings are not deleted.
            if let Err(error) = remove_dns_rules() {
                operation_error(
                    "Локальный шлюз работает, но старые DNS-правила не полностью сняты",
                    &error,
                );
                ok = false;
            }
        }
        if ok && crate::net::gemini_apps::chrome_installed() && crate::net::gemini_apps::chrome_glic_needs_unlock() {
            let can_unlock = if !crate::net::gemini_apps::chrome_running() {
                true
            } else if unsafe { libc::isatty(0) == 1 } {
                println!("\n  \x1b[96mВстроенный «Спросить Gemini» в Google Chrome\x1b[0m");
                println!("  Для снятия региональной блокировки в профиле Chrome нужно мягко перезапустить браузер.");
                if prompt("  Закрыть Chrome сейчас и разблокировать «Спросить Gemini»? [1 = да / 0 = позже]: ") == "1" {
                    match crate::net::gemini_apps::quit_chrome() {
                        Ok(()) => true,
                        Err(error) => {
                            println!("  \x1b[93m!\x1b[0m {error}");
                            false
                        }
                    }
                } else {
                    false
                }
            } else {
                false
            };
            if can_unlock {
                match crate::net::gemini_apps::unlock_chrome_glic() {
                    Ok(count) => println!(
                        "  \x1b[92m✓\x1b[0m Встроенный «Спросить Gemini» в Chrome разблокирован (профилей: {count})"
                    ),
                    Err(error) => println!("  \x1b[93m!\x1b[0m Chrome GLIC: {error}"),
                }
            } else {
                println!("  \x1b[93m!\x1b[0m Для кнопки «Спросить Gemini» в Chrome позже выберите пункт [4] → [1].");
            }
        }
        if ok {
            if crate::net::local_proxy::cli_shortcut_ready() {
                println!("  \x1b[92m✓\x1b[0m Короткая команда в терминале: ag-bypass");
            }
            match &config.upstream {
                Some(upstream) => {
                    println!(
                        "\n  \x1b[92mГотово! Патч, шлюз и PAC активны.\x1b[0m Прокси: {}",
                        upstream.safe_display()
                    );
                    println!("  Перезапустите Antigravity, Gemini.app и обновите вкладку Chrome (⌘Q → открыть снова).");
                }
                None if config.mode == crate::net::proxy_config::Mode::Vpn => {
                    println!("\n  \x1b[92mГотово! Патч и шлюз активны в режиме системного VPN.\x1b[0m");
                    println!("  Перезапустите Antigravity и Gemini.app (⌘Q → открыть снова).");
                }
                None => {
                    println!("\n  \x1b[92mПатч накачен, локальный шлюз и PAC запущены!\x1b[0m");
                    println!("  \x1b[93mСледующий шаг:\x1b[0m выберите пункт \x1b[1m[2]\x1b[0m в меню, чтобы вставить свой HTTP-прокси.");
                    println!("  (После вставки прокси перепатчивать ничего не нужно — просто перезапустите приложения).");
                }
            }
        } else {
            show_result(false);
        }
        pause();
        ok
    }
}

pub fn handle_patch_files_only() -> bool {
    let ok = if let Some(path) = std::env::args().nth(2) {
        patch_root(&expand_env_vars(&path))
    } else {
        patch_installations().succeeded()
    };
    show_result(ok);
    pause();
    ok
}
pub fn handle_dns_only() -> bool {
    if !check_vpn_before_setup() {
        return false;
    }
    if !apply_files_side() {
        return false;
    }
    let ok = match apply_dns_rules() {
        Ok(setup) => show_network_result(&setup),
        Err(e) => {
            operation_error("Не удалось завершить настройку", &e);
            false
        }
    };
    pause();
    ok
}

fn check_vpn_before_setup() -> bool {
    match crate::net::preflight() {
        Ok(()) => true,
        Err(message) => {
            println!("  \x1b[93mВключение обхода приостановлено\x1b[0m\n");
            println!("  {message}\n");
            println!("  Устраните причину и выберите этот пункт ещё раз.");
            pause();
            false
        }
    }
}
pub fn handle_manual_path() {
    let input = prompt("Путь к папке или файлу Antigravity: ");
    if input.is_empty() {
        return;
    }
    let root = expand_env_vars(input.trim().trim_matches('"'));
    let ok = patch_root(&root);
    show_result(ok);
    pause();
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
            println!("  \x1b[93mНужно закрыть Antigravity\x1b[0m");
            println!("  Перед изменением файлов завершите IDE, CLI и языковой сервер.");
            println!("  Сохраните работу: несохранённые изменения будут потеряны.\n");
            if std::env::args().len() > 1 {
                operation_error(
                    "Закройте Antigravity и повторите команду",
                    &holders.join(", "),
                );
                return false;
            }
            println!("  \x1b[96mВыберите действие\x1b[0m");
            #[cfg(any(windows, target_os = "macos"))]
            println!("  \x1b[1m[1]\x1b[0m  Закрыть Antigravity и продолжить: {action}");
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                let _ = action;
                println!("  \x1b[1m[1]\x1b[0m  Я закрыл Antigravity — проверить и продолжить");
            }
            println!("  \x1b[1m[0]\x1b[0m  Отмена — вернуться в меню\n");
            loop {
                match prompt("  Введите 1 или 0 и нажмите Enter: ").as_str() {
                    "1" => break,
                    "0" => {
                        println!("  Операция отменена.");
                        return false;
                    }
                    _ => println!("  Введите номер действия: 1 — продолжить, 0 — отмена."),
                }
            }
            #[cfg(any(windows, target_os = "macos"))]
            println!("\n  Закрываем Antigravity…");
            #[cfg(not(any(windows, target_os = "macos")))]
            println!("\n  Проверяем открытые файлы…");
            if let Err(error) = crate::system::file_lock::close_application(paths) {
                operation_error(
                    "Не удалось закрыть приложение. Закройте его вручную",
                    &error,
                );
                print_error_details();
                pause();
                return false;
            }
            println!("  \x1b[92m✓\x1b[0m Процессы Antigravity закрыты.\n");
        }
        Err(error) => {
            operation_error("Не удалось проверить, закрыто ли приложение", &error);
            print_error_details();
            pause();
            return false;
        }
        _ => {}
    }
    true
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
    println!("  ОТКЛЮЧЕНИЕ ОБХОДА\n");
    if !ensure_application_closed(&paths, "отключение обхода") {
        return false;
    }
    println!("  Восстанавливаем настройки…\n");
    let mut ok = true;
    for root in installs {
        let targets = find_targets_in_path(&root);
        if targets.is_empty() {
            if std::env::args().nth(2).is_some() {
                eprintln!("[✗] Цели для отката не найдены: {}", root.display());
                ok = false;
            }
        }
        for target in targets {
            ok &= print_patch_result(&target, restore_target(&target));
        }
    }
    if !paths.is_empty() {
        if let Err(error) = clear_ide_v8_caches() {
            operation_error("Не удалось очистить кэш приложения", &error);
            ok = false;
        }
    }
    let endpoint_errors = crate::core::endpoint::remove_all();
    let endpoints_restored = endpoint_errors.is_empty();
    for e in endpoint_errors {
        operation_error("Не удалось восстановить настройки приложения", &e);
        ok = false;
    }
    if !endpoints_restored {
        operation_error("Шлюз сохранён работающим", "Сначала необходимо восстановить endpoint приложения; остановка сейчас оборвала бы подключение.");
        pause();
        return false;
    }
    if !ok {
        operation_error(
            "Сетевые службы сохранены работающими",
            "Сначала устраните ошибку восстановления файлов: удалять маршрут до исправления бинарника небезопасно.",
        );
        pause();
        return false;
    }
    if let Err(error) = crate::net::local_proxy::disable() {
        operation_error("Не удалось отключить локальный прокси", &error);
        ok = false;
    }
    if let Err(e) = remove_dns_rules() {
        operation_error("Не удалось восстановить подключение", &e);
        ok = false;
    }
    if ok {
        println!("  \x1b[92m✓\x1b[0m Настройки подключения восстановлены");
        println!("\n  \x1b[92mПолный откат выполнен. Можно открыть Antigravity.\x1b[0m");
        if crate::net::proxy_config::load()
            .ok()
            .and_then(|c| c.upstream)
            .is_some()
        {
            println!("  Сохранённый адрес прокси не удалён (для очистки выберите [2] → clear).");
        }
    } else {
        eprintln!("\n  Не всё удалось восстановить. Резервные копии сохранены.");
        print_error_details();
    }
    pause();
    ok
}

pub fn handle_diagnostics() -> bool {
    clear_screen();
    banner();
    println!("  ПРОВЕРКА ПОДКЛЮЧЕНИЯ И ПРОКСИ\n");
    let mut ok = true;
    let summary = crate::net::local_proxy::summary();
    if summary["listener"] == true {
        println!(
            "  \x1b[92m✓\x1b[0m Локальный шлюз: запущен (127.0.0.1:{})",
            summary["local_port"].as_u64().unwrap_or(0)
        );
        if summary["pac_enabled"] == true {
            println!("  \x1b[92m✓\x1b[0m Системный PAC: активен (Gemini Web / AI Studio / Chrome)");
        } else if cfg!(target_os = "macos") {
            println!("  \x1b[93m!\x1b[0m Системный PAC: выключен — выберите пункт [1] с правами sudo");
        }
    } else {
        println!("  \x1b[90m– Локальный шлюз: не запущен\x1b[0m");
    }
    if crate::net::gemini_apps::chrome_installed() {
        if crate::net::gemini_apps::chrome_glic_needs_unlock() {
            println!("  \x1b[93m!\x1b[0m Gemini в Chrome (Local State): не разблокирован — выберите [4] → [1]");
        } else {
            println!("  \x1b[92m✓\x1b[0m Gemini в Chrome (Local State): регион US и флаг GLIC включены");
        }
    }
    match crate::net::proxy_config::load() {
        Ok(cfg) if cfg.upstream.is_some() => match crate::net::local_proxy::test_upstream() {
            Ok(msg) => println!("  \x1b[92m✓\x1b[0m Свой прокси: {msg}"),
            Err(error) => {
                operation_error("Свой прокси: проверка не прошла", &error);
                ok = false;
            }
        },
        Ok(cfg)
            if cfg.mode == crate::net::proxy_config::Mode::OwnProxy
                && summary["listener"] == true =>
        {
            println!("  \x1b[93m!\x1b[0m Свой прокси: не задан — выберите пункт [2] в меню");
            ok = false;
        }
        _ => println!("  \x1b[90m– Свой прокси: не задан\x1b[0m"),
    }
    println!();
    let reports = crate::net::health::probe_all();
    let state = crate::net::route_health::store().snapshot();
    let now = crate::net::route_health::now_ms();
    if let Err(e) = &state {
        operation_error("Не удалось прочитать историю ошибок подключения", e);
        ok = false;
    }
    for report in &reports {
        let label = match report.host.as_str() {
            "cloudcode-pa.googleapis.com" => "Основной сервер",
            "daily-cloudcode-pa.googleapis.com" => "Резервный сервер",
            _ => "Gemini",
        };
        if let Some(error) = &report.error {
            operation_error(&format!("{label}: нет подключения"), error);
            ok = false;
        } else if state
            .as_ref()
            .is_ok_and(|s| s.host_refused(&report.host, now))
        {
            println!(
                "  \x1b[93m!\x1b[0m {label}: сеть доступна, недавно получен региональный отказ"
            );
            ok = false;
        } else {
            println!("  \x1b[92m✓\x1b[0m {label}: TLS/HTTP-соединение доступно");
        }
    }
    println!("\n  Проверена сеть. Доступ к моделям и аккаунту этой проверкой не подтверждается.");
    println!("  Откройте Antigravity и отправьте короткий запрос нужной модели.");
    let observation = crate::model_status::snapshot();
    println!("\n  Модель: {}.", observation.label());
    println!("  Учитываются события за 15 минут. Начало ответа не подтверждает его завершение.");
    if observation.last_failure.is_some()
        && observation.state == crate::model_status::State::StreamStarted
    {
        println!("  Ранее в этом интервале была ошибка; начало нового ответа её не опровергает.");
    }
    if observation.partial {
        println!("  Прочитана только часть журналов; сведения могут быть неполными.");
    }
    for report in &reports {
        crate::net::relay::log_event(&format!("Диагностика: {report:?}"));
    }
    #[cfg(windows)]
    crate::net::relay::log_event(&format!(
        "System DoH disabled: {}",
        crate::net::doh::is_doh_disabled()
    ));
    if let Some(egress) = crate::net::egress::detect() {
        crate::net::relay::log_event(&format!("VPN active: {}", egress.vpn_active));
    }
    if !ok {
        print_error_details();
    }
    pause();
    ok
}

pub fn handle_save_diagnostics(directory: Option<&std::path::Path>) -> bool {
    println!("\n  Собираем диагностику подключения и приложения…");
    println!("  Отчёт сохраняется локально; тексты переписок и токены не включаются.");
    let ok = match crate::diagnostics::save(directory) {
        Ok(path) => {
            println!("\n  Диагностика сохранена:\n  {}", display_path(&path));
            println!("\n  Файл можно приложить к Issue.");
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

fn handle_proxy_setup() {
    clear_screen();
    banner();
    println!("  ВСТАВИТЬ / СМЕНИТЬ HTTP-ПРОКСИ\n");
    let current = crate::net::proxy_config::load().ok();
    match current.as_ref().and_then(|c| c.upstream.as_ref()) {
        Some(upstream) => println!("  Текущий прокси: \x1b[92m{}\x1b[0m\n", upstream.safe_display()),
        None => println!("  Текущий прокси: \x1b[90mне задан\x1b[0m\n"),
    }
    println!("  Поддерживаемые форматы:");
    println!("    • login:password@ip:port");
    println!("    • ip:port:login:password");
    println!("    • ip:port (без авторизации)\n");
    println!("  Введите \x1b[1mclear\x1b[0m для удаления прокси или просто нажмите Enter для отмены.\n");
    let input = match crate::net::proxy_config::read_hidden("  Вставьте прокси (ввод скрыт): ") {
        Ok(value) => value,
        Err(error) => {
            operation_error("Не удалось прочитать строку прокси", &error);
            pause();
            return;
        }
    };
    let trimmed = input.trim();
    if trimmed.is_empty() {
        println!("\n  Изменения отменены.");
        pause();
        return;
    }
    if trimmed.eq_ignore_ascii_case("clear") || trimmed.eq_ignore_ascii_case("delete") {
        match crate::net::proxy_config::clear_upstream() {
            Ok(()) => println!("\n  \x1b[92m✓\x1b[0m Прокси удалён из настроек."),
            Err(error) => operation_error("Не удалось удалить прокси", &error),
        }
        pause();
        return;
    }
    let upstream = match crate::net::proxy_config::Upstream::parse(trimmed) {
        Ok(upstream) => upstream,
        Err(error) => {
            println!();
            operation_error("Некорректный формат прокси", &error);
            pause();
            return;
        }
    };
    if let Err(error) = crate::net::proxy_config::save_upstream(upstream.clone()) {
        println!();
        operation_error("Не удалось сохранить прокси", &error);
        pause();
        return;
    }
    println!(
        "\n  \x1b[92m✓\x1b[0m Сохранено: {} (режим: own-proxy)",
        upstream.safe_display()
    );
    println!("  Проверяем соединение до Google через прокси…");
    match crate::net::local_proxy::test_upstream() {
        Ok(msg) => {
            println!("  \x1b[92m✓\x1b[0m {msg}");
            if crate::net::local_proxy::summary()["listener"] == true {
                println!("\n  \x1b[92mШлюз уже работает — новый прокси применён сразу без переустановки!\x1b[0m");
            } else {
                println!("\n  \x1b[93mТеперь выберите пункт [1] в меню, чтобы накатить патч и запустить шлюз.\x1b[0m");
            }
        }
        Err(error) => {
            operation_error("Прокси сохранён, но проверка сейчас не прошла", &error);
            println!("  Проверьте логин/пароль, порт HTTP CONNECT (не SOCKS) или политику VPN в пункте [3].");
        }
    }
    pause();
}

fn handle_route_settings() {
    use crate::net::proxy_config::{self, Mode, VpnPolicy};
    clear_screen();
    banner();
    println!("  РЕЖИМ МАРШРУТА И ПОЛИТИКА VPN\n");
    if let Ok(cfg) = proxy_config::load() {
        println!("  Текущий режим: \x1b[96m{}\x1b[0m", cfg.mode);
        println!("  Политика VPN:  \x1b[96m{}\x1b[0m\n", cfg.vpn_policy);
    }
    println!("  [1]  Только свой прокси (own-proxy, рекомендуется)");
    println!("  [2]  Авто: свой прокси, при сбое — напрямую (auto)");
    println!("  [3]  Системный VPN без своего прокси (vpn)");
    println!("  [4]  Резервный публичный DNS/SNI без своего прокси (sni-direct)\n");
    println!("  [5]  Идти в обход корпоративного VPN (bypass-vpn: FortiVPN / NetBird / Happ)");
    println!("  [6]  Идти поверх системного маршрута / VPN (use-vpn)");
    println!("\n  [0]  Назад в меню\n");
    let choice = prompt("Выберите настройку [0-6]: ");
    let result = match choice.as_str() {
        "0" | "" => return,
        "1" => proxy_config::set_mode(Mode::OwnProxy)
            .map(|()| "Выбран режим own-proxy. При смене с sni-direct выполните [1]."),
        "2" => proxy_config::set_mode(Mode::Auto)
            .map(|()| "Выбран режим auto (прокси с прямым резервом)."),
        "3" => proxy_config::set_mode(Mode::Vpn)
            .map(|()| "Выбран режим vpn (через маршрут ОС/VPN)."),
        "4" => proxy_config::set_mode(Mode::SniDirect)
            .map(|()| "Выбран режим sni-direct. Нажмите [1] для применения DNS-обхода."),
        "5" => proxy_config::set_vpn_policy(VpnPolicy::Bypass)
            .map(|()| "Включён обход VPN (bypass-vpn). Действует сразу на новые соединения."),
        "6" => proxy_config::set_vpn_policy(VpnPolicy::Use)
            .map(|()| "Включён системный маршрут (use-vpn). Действует сразу на новые соединения."),
        _ => {
            println!("  \x1b[31mНеверный выбор.\x1b[0m");
            pause();
            return;
        }
    };
    match result {
        Ok(msg) => println!("\n  \x1b[92m✓\x1b[0m {msg}"),
        Err(error) => operation_error("Не удалось сохранить настройку", &error),
    }
    pause();
}

fn handle_chrome_glic_unlock() {
    clear_screen();
    banner();
    println!("  РАЗБЛОКИРОВКА «СПРОСИТЬ GEMINI» В GOOGLE CHROME\n");
    if !crate::net::gemini_apps::chrome_installed() {
        operation_error("Google Chrome не найден", "Файл Local State отсутствует");
        pause();
        return;
    }
    if crate::net::gemini_apps::chrome_running() {
        println!("  \x1b[93mGoogle Chrome сейчас открыт.\x1b[0m");
        println!("  Чтобы Chrome не перезаписал Local State при выходе, его нужно мягко закрыть.\n");
        println!("  [1]  Мягко закрыть Chrome и разблокировать «Спросить Gemini»");
        println!("  [0]  Отмена\n");
        if prompt("Выберите [0-1]: ") != "1" {
            return;
        }
        if let Err(error) = crate::net::gemini_apps::quit_chrome() {
            operation_error("Не удалось закрыть Chrome", &error);
            pause();
            return;
        }
    }
    match crate::net::gemini_apps::unlock_chrome_glic() {
        Ok(count) => {
            println!(
                "\n  \x1b[92m✓\x1b[0m Готово! Разблокировано профилей Chrome: {count} (variations_country = us, is_glic_eligible = true)."
            );
            println!("  Примечание: встроенная панель «Спросить Gemini» требует личный аккаунт @gmail.com");
            println!("  и желательно HTTP-прокси с IP США (обычный сайт gemini.google.com работает через любую страну).");
        }
        Err(error) => operation_error("Не удалось обновить Local State", &error),
    }
    pause();
}

fn handle_files_submenu() {
    clear_screen();
    banner();
    println!("  ДОПОЛНИТЕЛЬНЫЕ ОПЕРАЦИИ\n");
    println!("  \x1b[96m[1]\x1b[0m  Разблокировать встроенный «Спросить Gemini» в Chrome (Local State)");
    println!("  [2]  Пропатчить только файлы Antigravity автоматически");
    println!("  [3]  Указать путь к папке или бинарнику Antigravity вручную");
    println!("\n  [0]  Назад в меню\n");
    match prompt("Выберите действие [0-3]: ").as_str() {
        "1" => handle_chrome_glic_unlock(),
        "2" => {
            handle_patch_files_only();
        }
        "3" => handle_manual_path(),
        _ => {}
    }
}

pub fn run_app() {
    loop {
        clear_screen();
        banner();
        print_dashboard();

        println!("  \x1b[92m[1]\x1b[0m  Накатить патч и включить шлюз (Antigravity + Gemini)");
        println!("  \x1b[96m[2]\x1b[0m  Вставить / сменить HTTP-прокси");
        println!("  [3]  Режим маршрута и VPN");
        println!("  [4]  Дополнительно (Gemini в Chrome / ручной патч)");
        println!("  [5]  Проверить подключение и прокси");
        println!("  \x1b[91m[6]\x1b[0m  Полный откат (восстановить всё)");
        println!("  [7]  Сохранить диагностику");
        println!("\n  [0]  Выход\n");

        match prompt("Выберите действие [0-7]: ").as_str() {
            "1" => {
                handle_proxy_enable();
            }
            "2" => {
                handle_proxy_setup();
            }
            "3" => {
                handle_route_settings();
            }
            "4" => {
                handle_files_submenu();
            }
            "5" => {
                handle_diagnostics();
            }
            "6" => {
                handle_rollback();
            }
            "7" => {
                handle_save_diagnostics(None);
            }
            "0" => {
                clear_screen();
                break;
            }
            _ => {
                println!("\x1b[31mНеверный выбор.\x1b[0m");
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }
    }
}
