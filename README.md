# GoogleAI-bypass-russia

Скрипт и фоновая служба для macOS, позволяющие работать с **Google Antigravity IDE** (включая голосовой ввод), десктопным **Gemini.app** и **Google AI Studio** из РФ без VPN или параллельно с включённым корпоративным VPN (`FortiClient`, `NetBird`, `Happ`).

Решает типичные проблемы:
- ошибки `Region not supported`, `User location is not supported`, `locationRejected` (`com.google.iRPC.Error Code=9`);
- таймауты и обрывы генерации в Antigravity (`streamGenerateContent`, `dial tcp ... connect: operation timed out`, `broken pipe`);
- сброс записи микрофона в Antigravity сразу после нажатия (`aicode.googleapis.com`);
- возврат отправленного сообщения обратно в поле ввода в нативном `Gemini.app` (`robinfrontend-pa.googleapis.com`).

---

## Установка и запуск (macOS)

Откройте Терминал и выполните:

```bash
curl -fsSL https://raw.githubusercontent.com/Robert6887/GoogleAI-bypass-russia/main/macos-instant-fix.py -o macos-instant-fix.py && sudo /usr/bin/python3 macos-instant-fix.py
```

Либо скачайте архив репозитория и запустите `Apply_Antigravity_Gemini_Fix.command` двойным кликом из Finder.

### Проверка без изменения системы

Посмотреть доступные прокси-узлы, задержку HTTP/2 и вердикт GeoIP Google без записи в `/etc/hosts` и таблицу маршрутизации:

```bash
/usr/bin/python3 macos-instant-fix.py --check-only
```

### Откат изменений (Rollback)

Удалить фоновую службу, очистить записи в `/etc/hosts`, `/etc/resolver` и убрать статические маршруты:

```bash
sudo /usr/bin/python3 macos-instant-fix.py --rollback
```
*(или запустить `Rollback_Antigravity_Gemini_Fix.command` из Finder).*

---

## Что именно делает скрипт

1. **Подбор и проверка SNI-прокси (TLS 1.3 + HTTP/2 + GeoIP)**
   Скрипт собирает пул адресов из нескольких DNS/DoH источников (`dns-ai.ru`, `geohide.ru`, `xbox-dns.ru`, локальный кэш), отсеивает недоступные по TCP:443 серверы и проверяет на оставшихся:
   - реальное рукопожатие TLS и получение фрейма `HTTP/2 SETTINGS` для каждого из 13 доменов;
   - страну выходного узла глазами самого Google (`WIZ_global_data.vXmutd` на `gemini.google.com/app`). Если Google определяет прокси как `RU`/`BY` и т.д., адрес отправляется в карантин.

2. **Точечная маршрутизация мимо VPN (`/32` и `IP_BOUND_IF`)**
   Если на компьютере включён корпоративный или личный VPN (`FortiVPN`, `NetBird`, `Happ`), который заворачивает весь трафик в туннель или выставляет системный прокси:
   - скрипт находит физический интерфейс (`en0`) и IP домашнего/офисного роутера (`ipconfig getoption en0 router`);
   - привязывает проверочные сокеты напрямую к физическому адаптеру через `setsockopt(IPPROTO_IP, IP_BOUND_IF)`;
   - прописывает статические хост-маршруты `/32` (`route -n add -host <IP> <GATEWAY>`) и `AdditionalRoutes` для Wi-Fi, а также добавляет домены Google AI в `ProxyBypassDomains`. Весь остальной трафик продолжает идти через ваш VPN как обычно.

3. **Защита от утечки IPv6 в `Gemini.app`**
   Нативный клиент `Gemini.app` использует gRPC с резолвером `c-ares`, который игнорирует `/etc/resolver` и при наличии IPv6 пытается идти напрямую в Google в обход IPv4-прокси. Для доменов `Gemini.app` в `/etc/hosts` добавляются стоп-записи `::1`, а в окружение `launchctl` прописывается `GRPC_DNS_RESOLVER=native`. Для Chrome дополнительно отключается QUIC (`QuicAllowed = false`), чтобы браузер не пытался стучаться по UDP:443.

4. **Фоновый демон `com.antigravity.bypass.watchdog`**
   После первого запуска скрипт ставит `LaunchDaemon`, который крутится в фоне с правами `root` и не требует повторного ввода пароля:
   - при переключении между сетями Wi-Fi или переподключении VPN за 2 секунды перестраивает маршруты `/32` под новый шлюз;
   - каждые 25 секунд проверяет доступность текущих прокси;
   - следит за логами Antigravity (`~/Library/Logs/Antigravity/language_server.log`, активные `transcript.jsonl`) и `Gemini.app`. При появлении `operation timed out`, `broken pipe`, `connection reset by peer` или `locationRejected` автоматически отправляет проблемный IP в карантин и переключает `/etc/hosts` на живой резерв;
   - имеет встроенный сторожевой таймер (`_deadman_monitor`): если после сна macOS сетевой поток зависнет дольше чем на 90 секунд, процесс перезапустится через `launchd`.

---

## Обслуживаемые домены

| Назначение | Домены |
| :--- | :--- |
| **Antigravity IDE** | `daily-cloudcode-pa.googleapis.com`, `cloudcode-pa.googleapis.com`, `generativelanguage.googleapis.com` |
| **Голосовой ввод Antigravity** | `aicode.googleapis.com` |
| **Gemini.app (macOS)** | `robinfrontend-pa.googleapis.com`, `webchannel-robinfrontend-pa.googleapis.com`, `proactivebackend-pa.googleapis.com`, `geller-pa.googleapis.com`, `gemini.google.com` |
| **Google AI Studio** | `aistudio.google.com`, `alkalimakersuite-pa.clients6.google.com`, `alkalicore-pa.clients6.google.com`, `webchannel-alkalimakersuite-pa.clients6.google.com` |

---

## Логи и диагностика

Файлы состояния и лог фоновой службы лежат в `/Library/Application Support/AntigravityBypass/`:
- `watchdog.log` — журнал переключений маршрутов, срабатываний карантина и смены сетей;
- `quarantine.json` — список временно отбракованных IP с причиной (`tcp_tls_dead`, `google_geo_RU`, `runtime_log:...`);
- `known_good_ips.json` — кэш проверенных рабочих прокси-серверов;
- `owned_routes_macos.json` — текущие прописанные статические маршруты `/32`.

Посмотреть последние события фоновой службы:
```bash
tail -f "/Library/Application Support/AntigravityBypass/watchdog.log"
```

## Лицензия

[MIT](LICENSE)
