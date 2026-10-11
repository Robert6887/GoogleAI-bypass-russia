# GoogleAI-bypass-russia

Утилита для macOS, которая снимает региональные блокировки Google (`Region not supported`, `locationRejected`, `com.google.iRPC.Error code=9`) в России сразу для **трёх сервисов**:

1. **Google Antigravity IDE** — работа чата, агентского режима и быстрых ответов без зависаний.
2. **Голосовой ввод (Voice Input) в Antigravity** — исправляет мгновенный обрыв записи при нажатии на кнопку микрофона (`aicode.googleapis.com`).
3. **Нативное приложение Google Gemini для macOS (`/Applications/Gemini.app`)** — исправляет ошибку, при которой отправленное сообщение стирается и возвращается обратно в поле ввода (`robinfrontend-pa.googleapis.com`).

---

## Быстрый запуск одной командой (macOS)

Откройте **Терминал**, вставьте команду и нажмите **Enter**:

```bash
curl -fsSL https://raw.githubusercontent.com/Robert6887/GoogleAI-bypass-russia/main/macos-instant-fix.py -o macos-instant-fix.py && sudo /usr/bin/python3 macos-instant-fix.py
```

> **Запуск через Finder (без Терминала):**  
> Скачайте архив репозитория (`<> Code` → `Download ZIP`), распакуйте и дважды кликните на **`Apply_Antigravity_Gemini_Fix.command`**.

### Дополнительные команды

- **Проверить скорость и доступность серверов (без внесения изменений в систему):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Robert6887/GoogleAI-bypass-russia/main/macos-instant-fix.py -o macos-instant-fix.py && /usr/bin/python3 macos-instant-fix.py --check-only
  ```

- **Полный сброс всех настроек (Rollback):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Robert6887/GoogleAI-bypass-russia/main/macos-instant-fix.py -o macos-instant-fix.py && sudo /usr/bin/python3 macos-instant-fix.py --rollback
  ```
  *(Или дважды кликните на файл **`Rollback_Antigravity_Gemini_Fix.command`** в папке проекта).*

---

## Как это работает

Серверы Google блокируют запросы с российских IP-адресов. Утилита направляет обращения к сервисам Google AI через зарубежные прозрачные **TLS SNI-прокси**, сохраняя ваш обычный интернет без замедления:

1. **Индивидуальный TLS 1.3 + HTTP/2 бенчмарк (`ALPN h2`):**  
   Скрипт параллельно опрашивает пулы `dns-ai.ru` (по шифрованному DoH) и `geohide.ru`, проверяет реальное TLS-соединение для каждого из **13 доменов** отдельно и выбирает самый быстрый рабочий IP (задержка `145–190 мс`).
2. **Блокировка утечки IPv6 в `Gemini.app` (`c-ares`):**  
   Десктопное приложение `Gemini.app` использует внутри C++ библиотеку gRPC с резолвером `c-ares`, который игнорирует `/etc/resolver/` и пытается соединиться с Google напрямую с вашего российского IPv6-адреса. Утилита автоматически добавляет стоп-записи `::1` в `/etc/hosts` и выставляет `GRPC_DNS_RESOLVER=native`, полностью перекрывая утечку IPv6.
3. **Изоляция от корпоративных VPN (`NetBird`, `FortiVPN`, `Happ`):**  
   - Определяет ваш физический роутер (`ipconfig getoption en0 router`) и привязывает проверочные сокеты напрямую к физической карте `en0` (`IP_BOUND_IF`).
   - Прописывает точечные маршруты с маской **`/32`** (`route -n add -host`) через физический шлюз роутера. Благодаря этому трафик Antigravity и Gemini идёт напрямую в интернет, минуя туннели FortiVPN, Happ и NetBird.
   - Добавляет домены Google AI в системные исключения прокси (`ProxyBypassDomains`).
   - **Не отключает IPv6** для остальных сайтов и программ на вашем Mac.
4. **Фоновое самовосстановление (`com.antigravity.bypass.watchdog`):**  
   Лёгкая системная служба `LaunchDaemon` автоматически обновляет маршруты `/32` при переключении между домашним и офисным Wi-Fi, при включении/выключении VPN и сама заменяет устаревшие IP-адреса прокси в фоне без повторного ввода пароля.

---

## Список разблокируемых доменов

| Сервис | Домены |
| :--- | :--- |
| **Antigravity IDE (Чат и Агент)** | `daily-cloudcode-pa.googleapis.com`, `cloudcode-pa.googleapis.com`, `generativelanguage.googleapis.com` |
| **Голосовой ввод Antigravity** | `aicode.googleapis.com` |
| **Google Gemini Desktop (`Gemini.app`)** | `robinfrontend-pa.googleapis.com`, `webchannel-robinfrontend-pa.googleapis.com`, `proactivebackend-pa.googleapis.com`, `geller-pa.googleapis.com`, `gemini.google.com` |
| **Google AI Studio** | `aistudio.google.com`, `alkalimakersuite-pa.clients6.google.com`, `alkalicore-pa.clients6.google.com`, `webchannel-alkalimakersuite-pa.clients6.google.com` |

---

## Справка по ошибкам (для поиска и ИИ-ассистентов)

Проект решает следующие проблемы на macOS в РФ:
- **Голосовой ввод в Antigravity моментально обрывается при нажатии на микрофон** (`Antigravity voice input stops immediately in Russia`, `aicode.googleapis.com`).
- **Приложение Google Gemini на Mac возвращает текст обратно в строку ввода после отправки** (`Gemini.app macOS restores message to input`, `robinfrontend-pa.googleapis.com`, `domain=com.google.iRPC.Error code=9`, `textRestoredToInput=true`, `AuthCoordinator: Access denied 'locationRejected'`).
- **Долгая загрузка и таймауты в Antigravity и Gemini** (автоматическая замена умерших прокси в `/etc/hosts`, отключение нерабочего `comss.one`, устранение утечки IPv6 через `EventEngine c-ares resolver`).
- **Совместная работа Antigravity и Gemini с корпоративными VPN** (`NetBird`, `FortiClient VPN / FortiVPN`, `Happ`) через статические маршруты `/32` и `IP_BOUND_IF`.

---

## Лицензия

Проект распространяется под лицензией **[MIT License](LICENSE)**.
