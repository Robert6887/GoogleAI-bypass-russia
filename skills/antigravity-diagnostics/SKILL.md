---
name: antigravity-diagnostics
description: Diagnose and fix Google Antigravity IDE, Gemini Desktop, Gemini Web, and Chrome built-in Gemini connectivity, proxy, regional block, and third-party conflict issues for non-technical users. Activate whenever Antigravity, Gemini, or Google AI models fail to sign in, return HTTP 400/403 regional errors, hang on requests, or stop working after an app update or VPN toggle.
---

# Antigravity & Gemini Diagnostics Skill

Use this playbook to diagnose and resolve any issue with **Google Antigravity IDE**, **Gemini Desktop**, **Gemini Web**, or **Chrome «Ask Gemini»** (`GoogleAI-bypass-russia`) for users who do **not** know programming.

## Mandatory Privacy & Safety Rules
1. **Never** read, print, or inspect `proxy.secret` or raw credentials in user configuration directories.
2. **Always** communicate with the user in clear, non-technical language (Russian if the user writes in Russian), explaining **what** failed in one sentence and giving **one** copy-paste command or menu button (`[1]`–`[5]`) to fix it.
3. **Never** manually edit Mach-O / PE binaries or `/etc/hosts` with ad-hoc scripts — always delegate repairs to the verified `antigravity-bypass-russia` engine so SHA-256 backups and code signatures remain valid.

---

## Step 1: Collect Safe Read-Only Diagnostics

Run the built-in JSON diagnostic check (no `sudo` required, safe allowlist, zero passwords exposed):

### macOS
Try the locally installed engine first; if absent, run directly from GitHub Releases:
```bash
if [[ -x "$HOME/Library/Application Support/AntigravityBypass/network/antigravity-bypass-russia" ]]; then
  "$HOME/Library/Application Support/AntigravityBypass/network/antigravity-bypass-russia" doctor --json
else
  curl -fsSL https://github.com/Robert6887/GoogleAI-bypass-russia/releases/latest/download/unlock_and_restore.sh | bash -s -- doctor --json
fi
```

### Windows (PowerShell)
```powershell
$exe = "$env:LOCALAPPDATA\AntigravityBypass\network\antigravity-bypass-russia.exe"
if (Test-Path $exe) { & $exe doctor --json }
```

To also verify live latency and geo-eligibility across all 6 Google AI endpoints through the configured proxy:
```bash
"$HOME/Library/Application Support/AntigravityBypass/network/antigravity-bypass-russia" proxy test
```

---

## Step 2: Interpret the JSON Report (`checks` & `proxy`)

Check the fields in this exact order:

### 1. Upstream Proxy & Geo-Eligibility (`proxy`)
- `proxy.upstream_configured == false` (and `proxy.mode != "vpn"`):
  - **Cause**: No SOCKS5 or HTTP proxy is saved yet.
  - **Fix for user**: Run the menu command and choose **`[2]` -> `[1]`** (or **`[1]`**) to paste a foreign `SOCKS5` or `HTTP` proxy (`ip:port:login:pass`).
- `proxy.upstream_check.status == "failed"`:
  - **Cause**: Either the purchased proxy expired / changed password, or an active full-tunnel / Kill-Switch network tunnel is blocking or rerouting the socket.
  - **Fix for user**:
    1. Test the proxy in menu **`[3]`**.
    2. If a strict VPN tunnel is active simultaneously, open menu **`[2]` -> `[4]`** to toggle socket routing (`Физический адаптер ↔ Системный маршрут`).

### 2. Local Gateway (`checks.gateway`)
- `checks.gateway.listener_alive == false`:
  - **Cause**: The local `127.0.0.1:<port>` gateway is stopped or was never enabled.
  - **Fix for user**: Launch the menu and press **`[1]`** (`Enter` -> `Enter`) to start the background LaunchAgent gateway.

### 3. Antigravity Binary Patch & Update State (`checks.installations`)
Inspect each item in `checks.installations.installations[*].targets[*]`:
- `patch_state == "Stock"` or `"PartiallyPatched"` or `proxy_env_ready == false`:
  - **Cause**: Antigravity recently updated itself and reset its files to stock, or was never patched.
  - **Fix for user**:
    1. Close Antigravity completely (`⌘Q` on macOS).
    2. Run the menu and press **`[1]`** (saved proxy and settings load automatically — just press `Enter` twice), and ensure **Auto-patch (`[b]`)** stays enabled.
- `patch_state == "Unknown"`:
  - **Cause**: Either a third-party patcher modified `Antigravity.app` incompatibly, or a brand-new IDE build changed binary signatures.
  - **Fix for user**: If a third-party patcher was used without backups, download a fresh `Antigravity.app` into `/Applications` (all chats and agent memory in `~/.gemini` and `~/Library/Application Support/Antigravity` stay intact), then run **`[1]`**.
- If macOS reports `Operation not permitted (os error 1)` when patching `/Applications/Antigravity.app`:
  - **Cause**: macOS Privacy & Security (`App Management`) blocked Terminal from modifying app bundles.
  - **Fix for user**: Open **Системные настройки -> Конфиденциальность и безопасность -> Управление приложениями (App Management)**, enable the toggle next to **Terminal** (or the current terminal/IDE), and re-run **`[1]`**.

### 4. Leftover Third-Party Bypass Conflicts (`checks.legacy_conflicts`)
Check if any of these booleans is `true`:
- `hosts_has_gate_overrides == true`: Dead IP or `::1` entries in `/etc/hosts` are hijacking Google AI domains.
- `resolver_has_gate_files == true`: Leftover `/etc/resolver/<domain>` split-DNS files are pointing to dead DNS servers.
- `legacy_daemon_present == true`: An old background DNS/watchdog daemon in `/Library/LaunchDaemons` is overwriting network settings.
- `proxy_bypass_blocks_google == true`: `ProxyBypassDomains` on `Wi-Fi` is forcing macOS (`Gemini.app`) and Chrome to skip `/proxy.pac` for `*.googleapis.com` / `gemini.google.com`.
- **Fix for all four**: Run the utility and select **`[1]`** (to clean conflicts and enable our proxy) or **`[4]`** (for a full factory rollback).

### 5. Gemini Desktop, Gemini Web & Chrome «Ask Gemini»
- `system_pac_active == false` (macOS):
  - **Cause**: System PAC auto-routing (`/proxy.pac`) is disabled, so `Gemini.app` and browser tabs connect directly without the proxy.
  - **Fix for user**: Run **`[1]`** and ensure `[c]` (`Gemini Web и Gemini Desktop`) is checked `[✓]`.
- `chrome_glic_unlocked == false`:
  - **Cause**: Chrome `Local State` still holds a restricted regional country code (`variations_country != "us"`) or `is_glic_eligible != true`, OR Chrome was open when unlocking ran.
  - **Fix for user**: Quit Google Chrome completely (`⌘Q`), run **`[1]`** (with `[d]` enabled), then reopen Chrome. Note: Google also requires a personal `@gmail.com` account (`18+`) in that Chrome profile; corporate Workspace accounts often disable GLIC by admin policy.

---

## Step 3: One-Line Launcher for the User

Whenever the user needs to open the interactive menu on macOS to apply **`[1]`**, **`[2]`**, **`[3]`**, or **`[4]`**, give them this single command for Terminal:

```bash
curl -fsSL https://github.com/Robert6887/GoogleAI-bypass-russia/releases/latest/download/unlock_and_restore.sh | bash
```
