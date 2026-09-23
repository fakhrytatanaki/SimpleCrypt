# SimpleCrypt

```text
   /\_/\       .-----------.
  ( o.o )      | SIMPLECRYPT |
   > ^ <       '-----------'
           Small vault. Quiet secrets.
```

A local-first, Vim-inspired password manager for your terminal. Built with Rust and Ratatui, dressed in all four Catppuccin flavors. Store logins, email accounts, Bitcoin addresses, secure notes, and your own key/value fields in a single authenticated, encrypted file.

> **New, unaudited software.** Read [SECURITY.md](SECURITY.md) before trusting it with important secrets. Keep encrypted backups. There is **no master-password recovery**.

## Install and run

Linux is the supported platform for this initial release. You need an interactive terminal with UTF-8 support; truecolor looks best.

```sh
# If Rust is not already installed:
brew install rust

cargo build --release --locked
./target/release/simplecrypt
```

Homebrew supplies both `rustc` and Cargo; Rustup is not required. Requires Rust 1.88 or newer; tested with Homebrew Rust **1.98.1**. If your environment has missing locale warnings, use an available locale for the command, e.g. `LC_ALL=C brew install rust`.

To install the binary on your Cargo PATH:

```sh
cargo install --path . --locked
simplecrypt
```

Choose a vault, theme, or inactivity timeout:

```sh
simplecrypt --vault ~/private/personal.scv --theme frappe --idle-timeout 180
simplecrypt --help
```

Themes: `mocha` (default), `macchiato`, `frappe`, `latte`. Timeout is in seconds, defaults to 300, and must be between 1 and 86400. Themes changed inside the app last for the session; use `--theme` for your launch preference.

The default vault is `$XDG_DATA_HOME/simplecrypt/vault.scv`, or `~/.local/share/simplecrypt/vault.scv`. A missing vault opens the creation screen. Choose and confirm a unique master passphrase of at least 12 characters. An existing file always opens as an existing vault; corruption never triggers silent replacement.

## Navigation

| Key | Action |
| --- | --- |
| `j` / `k`, Up / Down | Select a record or field in the focused pane |
| `h` / `l`, Left / Right, Tab | Switch between record list and field details |
| `/` | Search **labels**, case-insensitively |
| Enter / Escape in search | Accept filter / restore previous filter |
| Escape while browsing | Clear filter |
| `a` | Add a record from a template |
| `e` | Edit selected record |
| `d`, then `y` / `n` | Confirm / cancel deletion |
| `r` | Reveal selected secret for ten seconds; press again to hide |
| PageUp / PageDown, Home | Scroll long field contents / return to top |
| `t` | Choose a Catppuccin theme |
| `L` | Lock immediately |
| `?` | Help |
| `q` | Lock and quit from the browser |
| Ctrl-Q / Ctrl-C | Lock and quit from any screen |

At narrow widths, `h/l` switches between the full-width list and details. Very small terminals display a resize message rather than overlapping controls.

### Editing

Templates are just starting points: **Login**, **Email**, **Bitcoin Address**, **Secure Note**, and **Blank**. Each record has a label and ordered fields. Labels need not be unique.

- Tab / Shift-Tab moves through the label, field list, name, type, secret toggle, value, and action buttons.
- In the field list, `j/k` selects a field. Enter focuses its name.
- On the type control, Left/Right or Enter changes the field type. Space/Enter toggles secrecy.
- Text inputs accept ordinary typing—including `hjkl`, `/`, and `q`. Arrows move the cursor. Ctrl-A / Ctrl-E jump to the beginning/end; Ctrl-U clears the current input.
- Multiline fields accept Enter for a newline and Up/Down for line navigation.
- Focus **Generate** and press Enter for a 24-character OS-random password. Generation marks the selected field secret; it does not save automatically.
- **Add**, **Remove**, **Move up**, and **Move down** customize the field list.
- **Ctrl-S** saves the record and atomically updates the encrypted vault. **Escape** cancels the draft.

Secret values remain masked in the editor. Reveal a saved secret from the browser with `r`. Password fields are marked secret automatically; any field can be marked secret or public. The flag controls display, not disk encryption: **all fields, labels, and metadata are encrypted**.

**Unsaved drafts are discarded on manual or inactivity locking.** Successful changes are persisted immediately. If a save fails, the app does not pretend it succeeded. A post-publication durability failure requires quitting and reopening before further writes.

## Storage and boundaries

- Argon2id derives the encryption key from your master password (64 MiB, three passes, four lanes).
- XChaCha20-Poly1305 authenticates and encrypts the whole vault with a fresh nonce for every save.
- Plaintext is used only in process memory; no plaintext database, external editor, export, log, or recovery file is created.
- Private file modes, a single-process lock, and ciphertext-only atomic writes protect local persistence.
- Secret-buffer cleanup is best-effort. This cannot protect against a compromised host, swap, hibernation, terminal capture, or every rendering/allocator copy.

No network service, telemetry, clipboard integration, wallet functionality, cloud synchronization, import/export, or master-password rotation is included in this initial release. The same password is needed for every backup made under it.

## Encrypted backups

Quit SimpleCrypt, then copy the `.scv` file to a secure backup location. Keep its mode private (`0600`). You do not need the adjacent `.lock` file in a backup; it is a persistent coordination file, not secret data. Do not delete the lock file while an app is running.

To inspect a backup, copy it to a separate private location and launch with `--vault /path/to/copy.scv`. Keep your original safe. Never replace a live vault under a running process. SimpleCrypt does not detect rollback to an older, correctly authenticated backup.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release --locked
```

Tests use synthetic secrets and disposable vaults. The core is separated from UI code so authenticated parsing, malformed inputs, filesystem failures, and application modes can be tested independently. A real-terminal smoke test is provided in `scripts/smoke.py` (Python 3 and `tmux` required):

```sh
python3 scripts/smoke.py target/release/simplecrypt
```
