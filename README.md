# Dux KeePassXC (`duxKeePassXC`)

A pure QML/JavaScript launcher plugin for **Dux Modular Shell (DMS)** that searches and retrieves credentials directly from a running KeePassXC instance using KeePassXC's native Browser Integration Unix socket (`org.keepassxc.KeePassXC.BrowserServer`) over inlined NaCl `crypto_box` encryption.

No external binaries or compilation steps are required—install directly through the DMS Plugin Browser or `dms plugins install`.

## Features

- **100% Pure QML + JS**: Talks directly to KeePassXC over `Quickshell.Io.Socket` using a zero-dependency pure-JS NaCl `crypto_box` implementation inlined inside `DuxKeePassXC.qml`.
- **Zero Repeated Unlock Prompts**: Connects to your running KeePassXC session and reacts live to `database-locked` / `database-unlocked` broadcasts.
- **Works With or Without Full Entry Listing**:
  - With KeePassXC's full entry listing enabled, searches all entry titles, groups, usernames, and URLs.
  - Without it (**Limited Access Mode**), warns you about the restriction and falls back to live `get-logins` URL and `keepassxc://by-path/` queries. Persistent disk caching of discovered non-sensitive entry metadata is **opt-in** in plugin settings (**Persist Entry Metadata Cache**, off by default).
- **Category Filtering & MRU Ranking**: Filter by KeePassXC group/folder in the launcher dropdown and rank recently used entries at the top.
- **Keyboard Shortcuts & Context Menu**:
  - `Enter`: Run your configured default action (defaults to **Copy Password**).
  - `Shift+Enter`: Directly copy and paste the primary credential into the previously focused window via DMS's Wayland paste hook (`getPasteArgs`).
  - `Right-Click` / `F10`: Context menu with Copy/Paste actions for Password, Username, TOTP, custom `KPH:` string fields, URL copy/open (restricted by default to `http` and `https` via the **Allowed URL Schemes** whitelist setting), and Auto-Type.
- **Clipboard Security**: Uses `wl-copy --sensitive` (`x-kde-passwordManagerHint`) so clipboard managers ignore secrets, supports `--paste-once`, and runs a detached salted SHA-256 auto-clear timer without exposing hashes in process arguments.
- **Secret Service Deadlock Avoidance**: Stores database association keys in the system keyring (`secret-tool`), and pre-emptively detects if KeePassXC itself is configured or running as `org.freedesktop.secrets` (`[FdoSecrets] Enabled=true`, D-Bus service file, or active D-Bus owner) to switch cleanly to a `0600` local file (`~/.local/share/dms/duxKeePassXC/associations.json`) and warn you.

## Prerequisites

1. **KeePassXC 2.8.0+** with **Browser Integration** enabled:
   - Open KeePassXC → **Tools** → **Settings** → **Browser Integration** → enable **Enable browser integration**.
   - **Recommended** for full fuzzy search across all entries: in **Advanced**, enable **Allow limited access to all entries in connected databases (ignores site access restrictions)**.
   - **Avoiding per-entry permission prompts**: By default, KeePassXC shows a *Browser Access Request* confirmation dialog the first time an entry's password or username is fetched via `get-logins`. You can either check **Remember access to checked entries** per entry as you use them, or enable **Never ask before accessing credentials** (`AlwaysAllowAccess=true`) in **Tools → Settings → Browser Integration → Advanced** (note: this disables confirmation prompts globally for all Browser Integration clients).
   - **KeePassXC 2.7.x–2.8.0 empty-URL crash (upstream bug #13865)**: KeePassXC 2.8.0 segfaults in `BrowserService::sortEntries` when `get-logins` (`keepassxc://by-uuid/...`) matches an entry with no URL. By default, the plugin detects affected KeePassXC versions and blocks fetching URL-less entries with an explanatory warning; give affected entries any placeholder URL (e.g. `https://local.invalid`) or upgrade to KeePassXC 2.8.1+ when available.
   - Without full entry listing enabled, the plugin still works in **Limited Access Mode** (searching by exact path or domain/URL and caching discovered non-sensitive entry metadata) and shows a warning about the restriction.
2. **Wayland utilities**:
   - `wl-clipboard` (`wl-copy` / `wl-paste`) for `--sensitive` and auto-clear support.
   - `dms` (Dux Modular Shell) for launcher UI and `dms clipboard send-paste`.
   - Optional: `wtype` for full `Username → Tab → Password` auto-type (without `wtype`, auto-type pastes the username via DMS and copies the password to clipboard).

## Installation

Install through the **DMS Plugin Browser** (**Settings → Plugins → Browse**), via CLI (`dms plugins install`), or manually for local development:

```bash
ln -sfn "$(pwd)" ~/.config/dms/plugins/duxKeePassXC
dms ipc call plugins reload duxKeePassXC
```

## Usage

Open the DMS launcher and type `[` (default trigger):

- `[` — List entries (plus `Reload Entries` and `Lock Database` utility actions).
- `[github` — Search for matching entries.
- `Enter` — Execute default action (configurable in plugin settings; default is Copy Password).
- `Shift+Enter` — Paste directly into the focused window.
- `Right-Click` or `F10` — Open per-field context menu (Password, Username, TOTP, custom fields, URL, Auto-Type).

## Testing

Run the NaCl `crypto_box` and protocol helper unit tests:

```bash
node --test tests/nacl.test.cjs
```
