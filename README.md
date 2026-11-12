# GoogleAI-bypass-russia

Утилита с интерактивным терминальным меню `[0-7]` для работы из РФ через собственный **HTTP CONNECT-прокси** (параллельно с включённым корпоративным VPN `FortiVPN`, `NetBird`, `Happ` и без глобального проксирования всего трафика):

- **Google Antigravity IDE** (чат, агент, голосовой ввод и `agy` CLI)
- **Gemini в вебе** (`gemini.google.com`), **Google AI Studio** (`aistudio.google.com`), **NotebookLM** (`notebooklm.google.com`) и **Gemini API** (`generativelanguage.googleapis.com`)
- **Gemini Desktop для macOS** (`/Applications/Gemini.app`)
- **Встроенный «Спросить Gemini» в Google Chrome** (панель GLIC)

---

## Быстрый старт (macOS — Apple Silicon и Intel)

Ничего собирать вручную и устанавливать Rust не нужно. Откройте **Терминал** и выполните одну команду:

```bash
curl -fsSL https://github.com/Robert6887/GoogleAI-bypass-russia/releases/latest/download/unlock_and_restore.sh | bash
```

Откроется интерактивное меню со статусом компонентов:

```text
  [1]  Накатить патч и включить шлюз (Antigravity + Gemini)
  [2]  Вставить / сменить HTTP-прокси
  [3]  Режим маршрута и VPN
  [4]  Дополнительно (Gemini в Chrome / ручной патч)
  [5]  Проверить подключение и прокси
  [6]  Полный откат (восстановить всё)
  [7]  Сохранить диагностику

  [0]  Выход
```

### Настройка в два шага

1. Нажмите **`1`** — утилита пропатчит Antigravity и CLI, запустит локальный шлюз `127.0.0.1:53129`, включит точечный системный **PAC-файл** (`http://127.0.0.1:53129/proxy.pac` — проксирует **только** домены Google AI, все обычные сайты идут напрямую), настроит `grpc_proxy` для десктопного `Gemini.app`, предложит разблокировать встроенный **«Спросить Gemini» в Chrome** и создаст короткую команду `ag-bypass`.
2. Нажмите **`2`** — вставьте ваш HTTP-прокси (ввод скрыт) и нажмите `Enter`. Утилита сразу проверит `HTTP CONNECT + TLS + HTTP` до серверов Google.
3. Перезапустите Antigravity и `Gemini.app` (`⌘Q` → открыть снова) и обновите вкладку `gemini.google.com` в Chrome.

> **Важно для кнопки «Спросить Gemini» в правом верхнем углу Chrome (GLIC):** в отличие от сайта `gemini.google.com` и `Gemini.app` (которые работают через прокси почти любой страны Европы/США/Азии), встроенная боковая панель Chrome дополнительно требует:
> 1) разблокировку `Local State` (выполняется автоматически в пункте **`1`** или отдельно через **`[4]` → `[1]`** / `ag-bypass chrome-gemini`);
> 2) **личный аккаунт `@gmail.com`** (не корпоративный Workspace с отключённым ИИ) и желательно **HTTP-прокси с IP США**.

> **Удобная смена прокси на лету:** после первой установки меню открывается из любой папки просто по команде **`ag-bypass`**. Менять прокси через пункт **`2`** (или `ag-bypass proxy set`) можно в любой момент **без повторного патча и без `sudo`** — локальный шлюз подхватывает новый адрес автоматически на следующем соединении.

### Полный откат

Запустите `ag-bypass` (или команду с GitHub выше) и выберите **`6`**. Утилита восстановит оригинальные бинарные файлы по журналу контрольных сумм, очистит кэш V8, вернёт исходное окружение `AG_LS_PROXY` и удалит LaunchAgent.

---

## Что нужно от прокси

- Обычный **HTTP-прокси с поддержкой метода `CONNECT` к порту `443`**.
- Поддерживаются все популярные форматы при вставке:
  - `login:password@ip:port` (или `http://login:password@ip:port`)
  - `ip:port:login:password`
  - `ip:port@login:password`
  - `ip:port` (без авторизации)
- `SOCKS4/SOCKS5` и `HTTPS`-подключение к самому прокси не используются.
- Прокси должен находиться в регионе, где доступен Google AI / Antigravity.

---

## Работа вместе с корпоративным VPN (FortiVPN, NetBird, Happ)

По умолчанию включена политика **`bypass-vpn`**: исходящие сокеты локального шлюза привязываются напрямую к физическому сетевому интерфейсу macOS (`IP_BOUND_IF` / `IPV6_BOUND_IF`) мимо виртуального туннеля VPN, не трогая маршруты, DNS или настройки самого VPN-клиента.

Переключить режим маршрута или политику VPN можно в пункте **`3`** меню:

| Режим / политика | Описание |
| --- | --- |
| `own-proxy` *(по умолчанию)* | Трафик моделей идёт строго через ваш HTTP-прокси без скрытого прямого fallback. |
| `auto` | Сначала ваш HTTP-прокси, при сетевой ошибке — прямое подключение. |
| `vpn` | Прямой туннель через системный маршрут / активный VPN (без внешнего прокси). |
| `sni-direct` | Резервный публичный DNS/SNI-режим без собственного прокси. |
| `bypass-vpn` *(по умолчанию)* | Привязка сокетов к физическому Wi-Fi/Ethernet в обход системного VPN. |
| `use-vpn` | Обычная маршрутизация через таблицу маршрутов ОС / активный VPN. |

---

## Команды CLI (без входа в меню)

После установки все операции доступны также напрямую через `ag-bypass`:

```bash
# Открыть интерактивное меню [0-7]
ag-bypass

# Вставить/сменить прокси (с автопроверкой), посмотреть статус или очистить
ag-bypass proxy set
ag-bypass proxy test
ag-bypass proxy status
ag-bypass proxy clear

# Переключить режим или политику VPN
ag-bypass mode own-proxy
ag-bypass vpn bypass

# Накатить патч и шлюз (или обновить после апдейта Antigravity)
sudo ag-bypass install

# Разблокировать встроенный «Спросить Gemini» в Google Chrome (Local State)
ag-bypass chrome-gemini

# Проверить прокси и соединение
ag-bypass doctor
ag-bypass doctor --json

# Полный откат
sudo ag-bypass rollback
```

---

## Windows 10 / 11

Скачайте `antigravity-bypass-russia.exe` со страницы [Releases](https://github.com/Robert6887/GoogleAI-bypass-russia/releases/latest), запустите от имени Администратора и используйте пункты меню **`1`** (включить обход), **`4` → `1`** (разблокировать Gemini в Chrome) и **`6`** (полный откат).

---

## Как устроен маршрут на macOS

```text
Antigravity (AG_LS_PROXY) / Gemini.app (grpc_proxy + PAC) / Chrome (PAC /proxy.pac)
  → HTTP CONNECT 127.0.0.1:53129 (локальный шлюз)
  → ваш HTTP CONNECT-прокси (только домены Google AI / Gemini)
  → Google (сквозной TLS без расшифровки)
```

Через внешний прокси направляются только домены моделей, голосового ввода, Gemini Web, AI Studio, NotebookLM, `Gemini.app` и Chrome GLIC (`daily-cloudcode-pa.googleapis.com`, `cloudcode-pa.googleapis.com`, `aicode.googleapis.com`, `generativelanguage.googleapis.com`, `aistudio.google.com`, `gemini.google.com`, `robinfrontend-pa.googleapis.com`, `optimizationguide-pa.googleapis.com`, `accountcapabilities-pa.googleapis.com` и др.). Для всех остальных сайтов (`*.ru`, Почта, YouTube, корпоративные ресурсы) PAC возвращает `DIRECT`. Учётные данные прокси хранятся локально в `~/Library/Application Support/AntigravityBypass/network/proxy.json` с правами `0600` и никогда не попадают в логи или отчёты диагностики (`[7]`).

После обновления самого приложения Antigravity достаточно запустить `ag-bypass` и нажать **`1`** (сохранённый прокси при этом вводить заново не нужно).

---

## Сборка из исходников (для разработчиков)

```bash
cargo build --release --locked
./target/release/antigravity-bypass-russia
```

## Лицензия

[MIT](LICENSE)
